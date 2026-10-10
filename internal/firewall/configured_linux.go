package firewall

import (
	"context"
	"errors"
	"math"
	"net"
	"os"
	"syscall"
	"time"

	"github.com/mikenorgate/router-policy-agent/internal/agent"
	"github.com/mikenorgate/router-policy-agent/internal/binding"
	"github.com/mikenorgate/router-policy-agent/internal/ipc"
	"github.com/mikenorgate/router-policy-agent/internal/state"
)

// configuredOptions is executable-side wiring, not reader-controlled input.
// The supervisor supplies both already-created listeners. Bindings must come
// from an independently qualified producer; a fixture/config file is not one.
type configuredOptions struct {
	directory     string
	bindingSource string
	bindings      func(context.Context) (binding.Snapshot, error)
	requests      *net.UnixListener
	status        *net.UnixListener
}

// runConfiguredService owns opened resources for the entire joined service
// lifetime. It never creates/unlinks socket paths, initializes missing history,
// learns expected pins, installs guard schemas or accepts a clock override.
// It remains private pending real source, boot, release and path qualification.
func runConfiguredService(ctx context.Context, options configuredOptions) error {
	return runConfiguredWithClock(ctx, options, kernelUTC)
}

// The configured entry point fixes kernelUTC above. This lower-level assembler
// accepts a trusted clock dependency for isolated tests, never serialized input.
func runConfiguredWithClock(
	ctx context.Context,
	options configuredOptions,
	clock func() time.Time,
) (result error) {
	validListeners := options.requests != nil && options.status != nil && options.requests != options.status
	validDependencies := ctx != nil && options.bindings != nil && clock != nil
	if !validDependencies || !validListeners {
		return errors.New("firewall: incomplete configured helper inputs")
	}
	config, err := loadHelperConfig(ctx, options.directory)
	if err != nil {
		return err
	}
	// RunHelper selects the loader from the first private configuration read.
	// A replacement between reads must not promote shadow evidence into an
	// enforcing engine or silently change the selected binding source.
	if options.bindingSource != config.BindingSource {
		return errors.New("firewall: helper binding source changed during startup")
	}
	validRequests := configuredListenerMatches(options.requests, config.RequestSocket)
	validStatus := configuredListenerMatches(options.status, config.StatusSocket)
	if !validRequests || !validStatus {
		return errors.New("firewall: supervisor listeners differ from helper configuration")
	}
	resources, err := openConfiguredWithClock(
		ctx,
		config,
		options.bindings,
		clock,
	)
	if err != nil {
		return err
	}
	defer func() {
		cleanup, cancel := context.WithTimeout(context.WithoutCancel(ctx), 2*time.Second)
		defer cancel()
		result = errors.Join(result, resources.close(cleanup))
	}()
	return resources.service.serveListeners(ctx, serviceListeners{
		requests: options.requests, status: options.status, operator: resources.operator,
	})
}

func configuredListenerMatches(listener *net.UnixListener, path string) bool {
	if listener == nil {
		return false
	}
	// Addr panics on a zero-value UnixListener. Check the actual live descriptor
	// and stream type first, rather than trusting cached address metadata alone.
	raw, err := listener.SyscallConn()
	if err != nil {
		return false
	}
	hasStream := false
	if err := raw.Control(func(fd uintptr) {
		if fd > math.MaxInt {
			return
		}
		kind, err := syscall.GetsockoptInt(int(fd), syscall.SOL_SOCKET, syscall.SO_TYPE)
		hasStream = err == nil && kind == syscall.SOCK_STREAM
	}); err != nil || !hasStream {
		return false
	}
	address, ok := listener.Addr().(*net.UnixAddr)
	if !ok || address == nil {
		return false
	}
	return address.Net == "unix" && address.Name == path
}

type configuredResources struct {
	service  *guardedService
	operator *ipc.Server
	backend  *guardedBackend
	store    *state.Store
	executor *process
	gate     *generationGate
}

// Opening is inert: the state lock and checked executable/fence descriptors
// are retained, but no state load/write, command execution or binding read takes
// place until engine startup. Every partial opening closes earlier resources.
func openConfiguredResources(
	ctx context.Context,
	config helperConfig,
	bindings func(context.Context) (binding.Snapshot, error),
) (*configuredResources, error) {
	return openConfiguredWithClock(
		ctx,
		config,
		bindings,
		kernelUTC,
	)
}

func openConfiguredWithClock(
	ctx context.Context,
	config helperConfig,
	bindings func(context.Context) (binding.Snapshot, error),
	clock func() time.Time,
) (resources *configuredResources, result error) {
	validDependencies := ctx != nil && bindings != nil && clock != nil
	if !validDependencies {
		return nil, errors.New("firewall: invalid configured resource owner or inputs")
	}
	r, err := openConfiguredOwner(ctx, config)
	if err != nil {
		return nil, err
	}
	defer func() {
		if result != nil {
			cleanup, cancel := context.WithTimeout(context.WithoutCancel(ctx), 2*time.Second)
			defer cancel()
			result = errors.Join(result, r.close(cleanup))
		}
	}()
	// Only this trusted executable-side assembler may choose a test clock.
	// The recovery command never samples time or constructs a reader engine.
	r.backend.options.clock = clock
	timeout := time.Duration(config.RequestTimeoutMS) * time.Millisecond
	r.service, err = r.backend.newService(serviceOptions{
		mode:     config.Mode,
		state:    agent.Persistence{Load: r.store.Load, Save: r.store.Save},
		bindings: bindings, readerUID: config.ReaderUID, requestTimeout: timeout,
	})
	if err != nil {
		return nil, err
	}
	r.operator, err = r.service.newStatusServer(config.OperatorUID, timeout)
	if err != nil {
		return nil, err
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return r, nil
}

// openConfiguredOwner holds the same checked enforcement resources for live
// service wiring and denial-only recovery. It does not need a binding producer,
// sample a clock, execute nftables, initialize state or adopt any listener.
func openConfiguredOwner(
	ctx context.Context,
	config helperConfig,
) (resources *configuredResources, result error) {
	if ctx == nil || os.Geteuid() != 0 {
		return nil, errors.New("firewall: invalid configured resource owner or inputs")
	}
	if err := config.validate(); err != nil {
		return nil, err
	}
	r := &configuredResources{}
	defer func() {
		if result != nil {
			cleanup, cancel := context.WithTimeout(context.WithoutCancel(ctx), 2*time.Second)
			defer cancel()
			result = errors.Join(result, r.close(cleanup))
		}
	}()
	profile, err := loadRouterProfile(ctx, profileOptions{
		Directory: config.Profile.Directory, SHA256: config.Profile.SHA256,
	})
	if err != nil {
		return nil, err
	}
	r.executor, err = openProcess(ctx, config.NFTExecutable)
	if err != nil {
		return nil, profileFailure("helper executable unavailable", err)
	}
	r.gate, err = openGenerationGate(ctx, config.GenerationDir)
	if err != nil {
		return nil, profileFailure("helper writer fence unavailable", err)
	}
	r.store, err = state.Open(ctx, state.Options{Directory: config.StateDir, OwnerUID: 0})
	if err != nil {
		return nil, profileFailure("helper persistent store unavailable", err)
	}
	r.backend, err = newGuardedBackend(backendOptions{
		profile: profile, executor: r.executor, generation: r.gate,
		expected: config.ExpectedGeneration, clock: kernelUTC,
	})
	if err != nil {
		return nil, err
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return r, nil
}

// close is only called after both servers and bounded engine sealing have
// returned, or after failed inert construction. It does not itself stop a
// service and must never race one. Each resource is attempted on partial failure.
func (r *configuredResources) close(ctx context.Context) error {
	if r == nil || ctx == nil {
		return errors.New("firewall: invalid configured resource cleanup")
	}
	errorsFound := []error{}
	if r.store != nil {
		errorsFound = append(errorsFound, r.store.Close())
		r.store = nil
	}
	if r.gate != nil {
		errorsFound = append(errorsFound, r.gate.close(ctx))
		r.gate = nil
	}
	if r.executor != nil {
		errorsFound = append(errorsFound, r.executor.close())
		r.executor = nil
	}
	return errors.Join(errorsFound...)
}
