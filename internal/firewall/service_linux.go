package firewall

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
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
// returns, including its bounded cleanup.
type serviceOptions struct {
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
	profile := b.options.profile
	compiler, err := policy.New(profile.baseline)
	if err != nil {
		return nil, profileFailure("helper catalog invalid", err)
	}
	if compiler.BaselineHash() != profile.renderer.compiler.BaselineHash() {
		return nil, errors.New("firewall: helper catalog differs from paired backend")
	}
	engine, err := agent.New(profile.baseline, agent.Options{
		Mode: agent.Enforce, State: options.state, Bindings: options.bindings,
		Clock: b.options.clock, Firewall: agent.Enforcement{Seal: b.seal, Apply: b.apply},
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
// call. Startup clears permits and restores durable classification before any
// request is accepted. Every adopted attempt seals on exit, including failed or
// canceled startup, with an independent two-second deadline. It never unlinks
// the supervisor's path, initializes state, creates guards or closes caller-owned
// dependencies. Rejected concurrent/repeated calls retain their own listeners.
func (s *guardedService) serve(ctx context.Context, listener *net.UnixListener) (result error) {
	validService := s != nil && s.engine != nil && s.server != nil
	if !validService || ctx == nil || listener == nil {
		return errors.New("firewall: invalid helper service or listener")
	}
	if os.Geteuid() != 0 {
		return errors.New("firewall: helper service requires root")
	}
	if !s.hasServed.CompareAndSwap(false, true) {
		return errors.New("firewall: helper service already used")
	}
	listener.SetUnlinkOnClose(false)
	defer func() {
		cleanup, cancel := context.WithTimeout(context.WithoutCancel(ctx), 2*time.Second)
		defer cancel()
		if err := s.engine.Stop(cleanup); err != nil {
			result = errors.Join(result, fmt.Errorf("firewall: stop helper service: %w", err))
		}
		if err := listener.Close(); err != nil && !errors.Is(err, net.ErrClosed) {
			result = errors.Join(result, fmt.Errorf("firewall: close helper listener: %w", err))
		}
	}()
	if err := s.engine.Start(ctx); err != nil {
		return fmt.Errorf("firewall: start helper service: %w", err)
	}
	return s.server.Serve(ctx, listener)
}
