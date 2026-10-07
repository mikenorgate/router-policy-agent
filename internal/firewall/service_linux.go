package firewall

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"sync"
	"sync/atomic"
	"time"

	"github.com/mikenorgate/router-policy-agent/internal/agent"
	"github.com/mikenorgate/router-policy-agent/internal/binding"
	"github.com/mikenorgate/router-policy-agent/internal/ipc"
	"github.com/mikenorgate/router-policy-agent/internal/policy"
)

// serviceOptions is trusted helper wiring, not a reader request. The owning
// executable must supply an already checked store and qualified binding source.
// Initialization, clock overrides, alternate catalogs and firewall callbacks are
// deliberately absent. The caller keeps these dependencies open until serve
// returns, including its bounded cleanup. Mode is explicit helper authority;
// shadow construction supplies no firewall callbacks.
type serviceOptions struct {
	mode           agent.Mode
	state          agent.Persistence
	bindings       func(context.Context) (binding.Snapshot, error)
	readerUID      uint32
	requestTimeout time.Duration
}

// guardedService pairs the real backend, immutable helper compiler and serial
// authenticated IPC. It is single-use and must not be copied. Construction is
// inert; no current executable installs or enables it. Production qualification
// of bindings, boot ordering, release pins, time and packet paths is still required.
type guardedService struct {
	engine    *agent.Engine
	server    *ipc.Server
	backend   *guardedBackend
	readerUID uint32
	hasServed atomic.Bool
}

func (b *guardedBackend) newService(options serviceOptions) (*guardedService, error) {
	if b == nil {
		return nil, errors.New("firewall: missing service backend")
	}
	if err := validateBackendOptions(b.options); err != nil {
		return nil, err
	}
	if options.readerUID == 0 {
		return nil, errors.New("firewall: service requires a distinct non-root reader")
	}
	if options.mode != agent.Shadow && options.mode != agent.Enforce {
		return nil, errors.New("firewall: service requires an explicit valid mode")
	}
	profile := b.options.profile
	compiler, err := policy.New(profile.baseline)
	if err != nil {
		return nil, profileFailure("helper catalog invalid", err)
	}
	if compiler.BaselineHash() != profile.renderer.compiler.BaselineHash() {
		return nil, errors.New("firewall: helper catalog differs from paired backend")
	}
	// Shadow has no firewall callbacks at all, including startup/failure/exit
	// sealing. Only trusted helper configuration may select enforcement.
	callbacks := agent.Enforcement{}
	if options.mode == agent.Enforce {
		callbacks = agent.Enforcement{Seal: b.seal, Apply: b.apply}
	}
	engine, err := agent.New(profile.baseline, agent.Options{
		Mode: options.mode, State: options.state, Bindings: options.bindings,
		Clock: b.options.clock, Firewall: callbacks,
	})
	if err != nil {
		return nil, profileFailure("helper construction failed", err)
	}
	server, err := ipc.NewServer(ipc.ServerOptions{
		ReaderUID: options.readerUID, Timeout: options.requestTimeout,
	}, engine.Process)
	if err != nil {
		return nil, err
	}
	return &guardedService{engine: engine, server: server, backend: b, readerUID: options.readerUID}, nil
}

// serve adopts a supervisor-created listener only for the first valid root
// call. Enforce startup clears permits and restores durable classification
// before any request is accepted. Every enforcing attempt seals on exit,
// including failed or canceled startup, with an independent two-second deadline.
// Shadow has no write callbacks. It never unlinks
// the supervisor's path, initializes state, creates guards or closes caller-owned
// dependencies. Rejected concurrent/repeated calls retain their own listeners.
func (s *guardedService) serve(ctx context.Context, listener *net.UnixListener) error {
	return s.serveListeners(ctx, serviceListeners{requests: listener})
}

type serviceListeners struct {
	requests *net.UnixListener
	status   *net.UnixListener
	operator *ipc.Server
}

// serveListeners admits the optional status listener only as a complete,
// separate pair. Both servers start after engine startup (including deny-only
// restoration in enforce mode), and are joined before engine stop/dependency
// cleanup. Failure of either stops both.
func (s *guardedService) serveListeners(ctx context.Context, listeners serviceListeners) (result error) {
	validService := s != nil && s.engine != nil && s.server != nil
	validStatus := (listeners.status == nil) == (listeners.operator == nil)
	distinctListeners := listeners.status == nil || listeners.status != listeners.requests
	validInputs := ctx != nil && listeners.requests != nil
	if !validService || !validInputs || !validStatus || !distinctListeners {
		return errors.New("firewall: invalid helper service or listener")
	}
	if os.Geteuid() != 0 {
		return errors.New("firewall: helper service requires root")
	}
	if !s.hasServed.CompareAndSwap(false, true) {
		return errors.New("firewall: helper service already used")
	}
	listeners.requests.SetUnlinkOnClose(false)
	if listeners.status != nil {
		listeners.status.SetUnlinkOnClose(false)
	}
	defer func() {
		cleanup, cancel := context.WithTimeout(context.WithoutCancel(ctx), 2*time.Second)
		defer cancel()
		if err := s.engine.Stop(cleanup); err != nil {
			result = errors.Join(result, fmt.Errorf("firewall: stop helper service: %w", err))
		}
		if err := listeners.requests.Close(); err != nil && !errors.Is(err, net.ErrClosed) {
			result = errors.Join(result, fmt.Errorf("firewall: close helper listener: %w", err))
		}
		if listeners.status != nil {
			if err := listeners.status.Close(); err != nil && !errors.Is(err, net.ErrClosed) {
				result = errors.Join(result, fmt.Errorf("firewall: close status listener: %w", err))
			}
		}
	}()
	if err := s.engine.Start(ctx); err != nil {
		return fmt.Errorf("firewall: start helper service: %w", err)
	}
	if listeners.status == nil {
		return s.server.Serve(ctx, listeners.requests)
	}
	return serveHelperPair(ctx,
		func(ctx context.Context) error { return s.server.Serve(ctx, listeners.requests) },
		func(ctx context.Context) error { return listeners.operator.Serve(ctx, listeners.status) },
	)
}

// Both fixed server functions honor cancellation and join their own I/O
// interruption callbacks. Two result slots match exactly two workers; sends
// cannot block during sibling cancellation and no worker survives this call.
func serveHelperPair(ctx context.Context, requests, status func(context.Context) error) error {
	if ctx == nil || requests == nil || status == nil {
		return errors.New("firewall: invalid helper supervision inputs")
	}
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	results := make(chan error, 2)
	var workers sync.WaitGroup
	workers.Go(func() { results <- requests(ctx) })
	workers.Go(func() { results <- status(ctx) })
	first := <-results
	cancel()
	second := <-results
	workers.Wait()
	return errors.Join(first, second)
}
