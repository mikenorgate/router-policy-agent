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
	"github.com/mikenorgate/router-policy-agent/internal/ipc"
	"github.com/mikenorgate/router-policy-agent/internal/state"
)

func serviceOptionsFixture() serviceOptions {
	return serviceOptions{
		mode: agent.Enforce,
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
		{name: "missing mode", change: func(_ *guardedBackend, o *serviceOptions) { o.mode = "" }},
		{name: "unknown mode", change: func(_ *guardedBackend, o *serviceOptions) { o.mode = "apply" }},
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

func TestGuardedServiceShadowHasNoFirewallCallbacks(t *testing.T) {
	t.Parallel()
	for _, name := range []string{"grants", "inactive account", "binding failure", "startup failure"} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			backend, err := newGuardedBackend(backendOptionsFixture(t))
			if err != nil {
				t.Fatal(err)
			}
			// The fixture has no executable or usable fence. Any backend call
			// would fail, including startup, processing failure or stop sealing.
			document := state.Initial()
			options := serviceOptionsFixture()
			options.mode = agent.Shadow
			options.state.Load = func(context.Context) (state.Document, error) {
				if name == "startup failure" {
					return state.Document{}, errors.New("synthetic unavailable history")
				}
				return state.Clone(document)
			}
			options.state.Save = func(_ context.Context, next state.Document) error {
				document = next
				return nil
			}
			_, _, _, input := renderFixture(t)
			options.bindings = func(context.Context) (binding.Snapshot, error) {
				if name == "binding failure" {
					return binding.Snapshot{}, errors.New("synthetic unavailable bindings")
				}
				return input.Bindings, nil
			}
			service, err := backend.newService(options)
			if err != nil {
				t.Fatal(err)
			}
			startErr := service.engine.Start(t.Context())
			if name == "startup failure" {
				if startErr == nil {
					t.Fatal("shadow mode initialized or ignored missing history")
				}
			} else {
				if startErr != nil {
					t.Fatalf("shadow startup called an unusable firewall backend: %v", startErr)
				}
				now := time.Now().Round(0).UTC()
				input.Directory.ObservedAt, input.Bindings.ObservedAt = now, now
				for i := range input.Bindings.Records {
					record := &input.Bindings.Records[i]
					record.AssociatedAt = now
					for j := range record.Addresses {
						record.Addresses[j].ObservedAt = now
						record.Addresses[j].ValidUntil = now.Add(time.Hour)
					}
				}
				if name == "inactive account" {
					input.Directory.Devices[0].Active = false
				}
				receipt, err := service.engine.Process(t.Context(), input.Directory)
				switch name {
				case "binding failure":
					if err == nil || receipt.Status != "" {
						t.Fatal("shadow mode accepted failed binding evidence")
					}
				case "inactive account":
					if err != nil || receipt.Status != ipc.StatusShadow || receipt.GrantCount != 0 || receipt.DenialCount != 1 {
						t.Fatalf("shadow mode ignored inactive identity: %v", err)
					}
				case "grants":
					if err != nil || receipt.Status != ipc.StatusShadow || receipt.GrantCount != 1 || receipt.DenialCount != 0 {
						t.Fatalf("shadow mode applied or rejected a valid compilation: %v", err)
					}
				}
			}
			if err := service.engine.Stop(t.Context()); err != nil {
				t.Fatalf("shadow shutdown called an unusable firewall backend: %v", err)
			}
		})
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
