package firewall

import (
	"context"
	"errors"
	"net"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/mikenorgate/router-policy-agent/internal/agent"
	"github.com/mikenorgate/router-policy-agent/internal/binding"
	"github.com/mikenorgate/router-policy-agent/internal/state"
)

func serviceOptionsFixture() serviceOptions {
	return serviceOptions{
		state: agent.Persistence{
			Load: func(context.Context) (state.Document, error) { return state.Initial(), nil },
			Save: func(context.Context, state.Document) error { return nil },
		},
		bindings: func(context.Context) (binding.Snapshot, error) {
			return binding.Snapshot{}, errors.New("synthetic unavailable binding source")
		},
		readerUID: 65534, requestTimeout: 10 * time.Second,
	}
}

func TestGuardedServiceRequiresTrustedPairedDependencies(t *testing.T) {
	t.Parallel()
	for _, backend := range []*guardedBackend{nil, {}} {
		if service, err := backend.newService(serviceOptionsFixture()); err == nil || service != nil {
			t.Fatal("missing backend constructed a helper service")
		}
	}
	for _, test := range []struct {
		name   string
		change func(*guardedBackend, *serviceOptions)
	}{
		{name: "root reader", change: func(_ *guardedBackend, o *serviceOptions) { o.readerUID = 0 }},
		{name: "missing load", change: func(_ *guardedBackend, o *serviceOptions) { o.state.Load = nil }},
		{name: "missing save", change: func(_ *guardedBackend, o *serviceOptions) { o.state.Save = nil }},
		{name: "missing bindings", change: func(_ *guardedBackend, o *serviceOptions) { o.bindings = nil }},
		{name: "zero timeout", change: func(_ *guardedBackend, o *serviceOptions) { o.requestTimeout = 0 }},
		{name: "negative timeout", change: func(_ *guardedBackend, o *serviceOptions) { o.requestTimeout = -time.Second }},
		{name: "excess timeout", change: func(_ *guardedBackend, o *serviceOptions) {
			o.requestTimeout = 10*time.Second + time.Nanosecond
		}},
		{name: "invalid catalog", change: func(b *guardedBackend, _ *serviceOptions) {
			b.options.profile.baseline.SchemaVersion = 0
		}},
		{name: "different catalog", change: func(b *guardedBackend, _ *serviceOptions) {
			b.options.profile.baseline.Generation = "synthetic-different-catalog"
		}},
		{name: "broken backend", change: func(b *guardedBackend, _ *serviceOptions) { b.options.profile.renderer = nil }},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			backend, err := newGuardedBackend(backendOptionsFixture(t))
			if err != nil {
				t.Fatal(err)
			}
			options := serviceOptionsFixture()
			test.change(backend, &options)
			if service, err := backend.newService(options); err == nil || service != nil {
				t.Fatal("invalid or unpaired dependencies constructed a helper service")
			}
		})
	}
}

func TestGuardedServiceConstructionIsInert(t *testing.T) {
	t.Parallel()
	var invocations atomic.Int32
	options := serviceOptionsFixture()
	options.state.Load = func(context.Context) (state.Document, error) {
		invocations.Add(1)
		return state.Initial(), nil
	}
	options.state.Save = func(context.Context, state.Document) error { invocations.Add(1); return nil }
	options.bindings = func(context.Context) (binding.Snapshot, error) {
		invocations.Add(1)
		return binding.Snapshot{}, nil
	}
	backendOptions := backendOptionsFixture(t)
	backendOptions.clock = func() time.Time { invocations.Add(1); return time.Now() }
	backend, err := newGuardedBackend(backendOptions)
	if err != nil {
		t.Fatal(err)
	}
	service, err := backend.newService(options)
	if err != nil {
		t.Fatal(err)
	}
	_, _, _, input := renderFixture(t)
	if _, err := service.engine.Process(t.Context(), input.Directory); err == nil {
		t.Fatal("constructor started the helper engine")
	}
	if invocations.Load() != 0 || service.hasServed.Load() {
		t.Fatal("construction accessed runtime evidence or started serving")
	}
}

func TestGuardedServiceRejectsMissingLifecycleInputs(t *testing.T) {
	t.Parallel()
	backend, err := newGuardedBackend(backendOptionsFixture(t))
	if err != nil {
		t.Fatal(err)
	}
	valid, err := backend.newService(serviceOptionsFixture())
	if err != nil {
		t.Fatal(err)
	}
	for _, service := range []*guardedService{nil, {}, {engine: valid.engine}, {server: valid.server}, valid} {
		if err := service.serve(t.Context(), nil); err == nil {
			t.Fatal("invalid service or missing listener accepted")
		}
	}
	listener := serviceUnitListener(t)
	// Deliberate invalid input: production always supplies a real context.
	var missingContext context.Context
	if err := valid.serve(missingContext, listener); err == nil || valid.hasServed.Load() {
		t.Fatal("missing context adopted the listener or started lifecycle")
	}
	if err := listener.SetDeadline(time.Now()); err != nil {
		t.Fatal("invalid call closed the caller's listener")
	}
}

func TestGuardedServiceRejectsNonRootServing(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("this rejection path requires the ordinary unprivileged runner")
	}
	backend, err := newGuardedBackend(backendOptionsFixture(t))
	if err != nil {
		t.Fatal(err)
	}
	service, err := backend.newService(serviceOptionsFixture())
	if err != nil {
		t.Fatal(err)
	}
	listener := serviceUnitListener(t)
	if err := service.serve(t.Context(), listener); err == nil || service.hasServed.Load() {
		t.Fatal("unprivileged helper adopted a listener or began startup")
	}
	if err := listener.SetDeadline(time.Now()); err != nil {
		t.Fatal("rejected unprivileged call closed the caller's listener")
	}
}

func serviceUnitListener(t *testing.T) *net.UnixListener {
	t.Helper()
	path := filepath.Join(t.TempDir(), "helper.sock")
	listener, err := net.ListenUnix("unix", &net.UnixAddr{Name: path, Net: "unix"})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := listener.Close(); err != nil && !errors.Is(err, net.ErrClosed) {
			t.Error(err)
		}
	})
	return listener
}
