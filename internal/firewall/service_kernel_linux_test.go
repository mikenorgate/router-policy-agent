//go:build integration && kernel && servicekernel && linux

package firewall

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/mikenorgate/router-policy-agent/internal/agent"
	"github.com/mikenorgate/router-policy-agent/internal/binding"
	"github.com/mikenorgate/router-policy-agent/internal/ipc"
	"github.com/mikenorgate/router-policy-agent/internal/policy"
	"github.com/mikenorgate/router-policy-agent/internal/state"
)

func TestKernelGuardedServiceAuthenticatedLifecycle(t *testing.T) {
	requireKernelIsolation(t)
	t.Cleanup(func() { requireKernelIsolation(t) })
	ctx, cancel := context.WithTimeout(t.Context(), 45*time.Second)
	defer cancel()
	backend, _ := setupBackendPacketFixture(ctx, t)
	directory, store := serviceKernelStore(ctx, t)
	if err := store.Initialize(ctx); err != nil {
		t.Fatal(err)
	}
	seed := backendInputFixture(t, 5*time.Second)
	ledger, err := backend.options.profile.renderer.compiler.ObserveDirectory(
		ctx, seed.Directory, seed.Now, state.Initial().Ledger,
	)
	if err != nil {
		t.Fatal(err)
	}
	document, err := state.Advance(state.Initial(), seed.Directory, ledger)
	if err != nil {
		t.Fatal(err)
	}
	document, err = state.RememberAddresses(document, []netip.Addr{
		netip.MustParseAddr("10.240.3.15"), netip.MustParseAddr("fdca:1a2b:3::15"),
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Save(ctx, document); err != nil {
		t.Fatal(err)
	}
	ready := make(chan struct{})
	var announced atomic.Bool
	options := backend.options
	options.clock = func() time.Time {
		now := time.Now()
		// Engine startup samples this clock only after restoring classification.
		if announced.CompareAndSwap(false, true) {
			close(ready)
		}
		return now
	}
	backend, err = newGuardedBackend(options)
	if err != nil {
		t.Fatal(err)
	}
	// This queue is a synthetic qualified binding source, not a NAS collector.
	// Each transaction receives separately constructed post-startup evidence.
	bindings := make(chan binding.Snapshot, 1)
	var bindingReads atomic.Int32
	service, err := backend.newService(serviceOptions{
		mode:  agent.Enforce,
		state: agent.Persistence{Load: store.Load, Save: store.Save},
		bindings: func(ctx context.Context) (binding.Snapshot, error) {
			bindingReads.Add(1)
			select {
			case snapshot := <-bindings:
				return snapshot, nil
			case <-ctx.Done():
				return binding.Snapshot{}, ctx.Err()
			}
		},
		readerUID: 65534, requestTimeout: 10 * time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}
	listener := serviceKernelListener(t, directory, "helper.sock")
	stop := startServiceKernelFixture(ctx, t, service, listener)
	select {
	case <-ready:
	case <-ctx.Done():
		t.Fatal("helper did not complete closed startup")
	}
	history, err := state.Classifiers(document)
	if err != nil {
		t.Fatal(err)
	}
	assertClassifiedGuardInventory(ctx, t, backend.options.executor, backend.options.profile.layout, history, false)
	peer, device := packetSocket(t, "peer0"), packetSocket(t, "device0")
	traffic := func(allowed bool, stage string) {
		for _, datagram := range backendNativeFrames(t) {
			datagram.payload = "synthetic-service-" + stage
			input, output := device, peer
			if datagram.sourceMAC == "02:00:00:00:00:10" {
				input, output = peer, device
			}
			frame := packetFrame(t, datagram)
			sendPacket(ctx, t, input, frame)
			receivePacket(ctx, t, output, frame, allowed)
		}
	}
	traffic(false, "startup")
	path := listener.Addr().String()
	rootInput := backendInputFixture(t, 0)
	if _, err := ipc.Submit(ctx, ipc.ClientOptions{
		Socket: path, ServerUID: 0, Timeout: time.Second,
	}, rootInput.Directory); err == nil {
		t.Fatal("root impersonated the pinned unprivileged reader")
	}
	afterRoot, err := store.Load(ctx)
	if err != nil || afterRoot.DirectoryHash != document.DirectoryHash || bindingReads.Load() != 0 {
		t.Fatal("unauthorized reader reached durable state or binding collection")
	}
	executable := serviceReaderExecutable(t, directory)
	baselineHash := backend.options.profile.renderer.compiler.BaselineHash()
	for _, test := range []struct {
		name, expected string
		active         bool
	}{
		{name: "allow", expected: "applied", active: true},
		{name: "disable", expected: "denied"},
		{name: "restore", expected: "applied", active: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			input := backendInputFixture(t, 0)
			input.Directory.Devices[0].Active = test.active
			bindings <- input.Bindings
			serviceReaderSubmit(ctx, t, executable, path, baselineHash, input.Directory, test.expected)
			document, err = store.Load(ctx)
			if err != nil {
				t.Fatal(err)
			}
			history, err = state.Classifiers(document)
			if err != nil {
				t.Fatal(err)
			}
			assertClassifiedGuardInventory(ctx, t, backend.options.executor, backend.options.profile.layout, history, test.active)
			before := guardFixtureCounter(ctx, t, "reviewed_floor", "flow_hits")
			traffic(test.active, test.name)
			if !test.active && guardFixtureCounter(ctx, t, "reviewed_floor", "flow_hits") != before {
				t.Fatal("revoked existing flows reached the stateful shortcut")
			}
		})
	}
	if bindingReads.Load() != 3 {
		t.Fatal("accepted transactions did not independently reread qualified evidence")
	}
	again := serviceKernelListener(t, directory, "again.sock")
	if err := service.serve(ctx, again); err == nil {
		t.Fatal("concurrent serving reused a live helper")
	}
	if err := again.SetDeadline(time.Now()); err != nil {
		t.Fatal("rejected concurrent call adopted the other listener")
	}
	traffic(true, "concurrent-rejection")
	if err := stop(); !errors.Is(err, context.Canceled) {
		t.Fatalf("helper shutdown: %v", err)
	}
	assertClassifiedGuardInventory(ctx, t, backend.options.executor, backend.options.profile.layout, history, false)
	traffic(false, "shutdown")
	afterStop, err := store.Load(ctx)
	if err != nil || afterStop.DirectoryHash != document.DirectoryHash {
		t.Fatal("shutdown changed durable authorization anchors")
	}
	if _, err := os.Lstat(path); err != nil {
		t.Fatal("shutdown removed the supervisor-owned socket path")
	}
	if err := service.serve(ctx, again); err == nil {
		t.Fatal("stopped helper silently restarted its single-use lifecycle")
	}
}

func TestKernelGuardedServiceStatusReadOnly(t *testing.T) {
	requireKernelIsolation(t)
	t.Cleanup(func() { requireKernelIsolation(t) })
	ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
	defer cancel()
	backend, writerRoot := setupBackendPacketFixture(ctx, t)
	directory, store := serviceKernelStore(ctx, t)
	if err := store.Initialize(ctx); err != nil {
		t.Fatal(err)
	}
	var bindings binding.Snapshot
	var reads atomic.Int32
	service, err := backend.newService(serviceOptions{
		mode:      agent.Enforce,
		state:     agent.Persistence{Load: store.Load, Save: store.Save},
		bindings:  func(context.Context) (binding.Snapshot, error) { reads.Add(1); return bindings, nil },
		readerUID: 65534, requestTimeout: 10 * time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := service.engine.Start(ctx); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		cleanup, stop := context.WithTimeout(context.WithoutCancel(t.Context()), 2*time.Second)
		defer stop()
		if err := service.engine.Stop(cleanup); err != nil {
			t.Error(err)
		}
	})
	input := backendInputFixture(t, 0)
	bindings = input.Bindings
	if _, err := service.engine.Process(ctx, input.Directory); err != nil {
		t.Fatal(err)
	}
	before, err := store.Load(ctx)
	if err != nil {
		t.Fatal(err)
	}
	history, err := state.Classifiers(before)
	if err != nil {
		t.Fatal(err)
	}
	listener := serviceKernelListener(t, directory, "status.sock")
	server, err := service.newStatusServer(65533, 10*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	serveCtx, stop := context.WithCancel(ctx)
	defer stop()
	var worker sync.WaitGroup
	result := make(chan error, 1)
	worker.Go(func() { result <- server.Serve(serveCtx, listener) })
	t.Cleanup(func() {
		stop()
		worker.Wait()
		if err := <-result; !errors.Is(err, context.Canceled) {
			t.Error(err)
		}
	})
	executable := serviceReaderExecutable(t, directory)
	query := func(expected string) {
		t.Helper()
		// #nosec G204 -- The fixed child entry point belongs to this test executable.
		command := exec.CommandContext(ctx, executable, "-test.run=^TestGuardedServiceStatusProcess$")
		command.Env = []string{"RPA_SERVICE_STATUS_CHILD=1", "RPA_SERVICE_STATUS_SOCKET=" + listener.Addr().String(),
			"RPA_SERVICE_STATUS_EXPECTED=" + expected}
		command.SysProcAttr = &syscall.SysProcAttr{Credential: &syscall.Credential{Uid: 65533, Gid: 0, NoSetGroups: true}}
		if output, err := command.CombinedOutput(); err != nil {
			t.Fatalf("actual read-only status client: %v: %s", err, output)
		}
	}
	query("matches_pinned_contract")
	closed := backend.options.expected
	closed.Ready = false
	writeGenerationFixture(t, writerRoot, closed)
	query("unverified")
	writeGenerationFixture(t, writerRoot, backend.options.expected)
	packetNft(ctx, t, "insert rule inet reviewed_floor forward accept")
	changedFloor := kernelFixtureCommand(ctx, t, "list", "table", "inet", "reviewed_floor")
	query("unverified")
	if !bytes.Equal(changedFloor, kernelFixtureCommand(ctx, t, "list", "table", "inet", "reviewed_floor")) {
		t.Fatal("status inspection repaired an external floor")
	}
	assertClassifiedGuardInventory(ctx, t, backend.options.executor, backend.options.profile.layout, history, true)
	after, err := store.Load(ctx)
	if err != nil || after.DirectoryHash != before.DirectoryHash || reads.Load() != 1 {
		t.Fatal("status query changed durable authorization or collected ownership evidence")
	}
}

func TestGuardedServiceStatusProcess(t *testing.T) {
	if os.Getenv("RPA_SERVICE_STATUS_CHILD") != "1" {
		t.Skip("subprocess entry point")
	}
	if os.Geteuid() != 65533 {
		t.Fatal("status reader did not drop to the separate operator uid")
	}
	report, err := ipc.ReadStatus(t.Context(), ipc.ClientOptions{
		Socket: os.Getenv("RPA_SERVICE_STATUS_SOCKET"), ServerUID: 0, Timeout: 10 * time.Second,
	})
	if err != nil || report.FloorState != os.Getenv("RPA_SERVICE_STATUS_EXPECTED") || report.LastGrantCount == 0 {
		t.Fatalf("status evidence mismatch: %v", err)
	}
	if report.FloorState == "unverified" && (report.KernelTupleCount != nil || report.WriterSequence != nil) {
		t.Fatal("failed inspection claimed verified kernel evidence")
	}
	if report.FloorState == "matches_pinned_contract" &&
		(report.KernelTupleCount == nil || *report.KernelTupleCount == 0 || report.WriterSequence == nil) {
		t.Fatal("matching contract lacked actual kernel evidence")
	}
}

func TestKernelGuardedServiceFailedStartupRetainsClosure(t *testing.T) {
	for _, name := range []string{"missing state", "corrupt state", "canceled with cleanup failure"} {
		t.Run(name, func(t *testing.T) {
			requireKernelIsolation(t)
			t.Cleanup(func() { requireKernelIsolation(t) })
			ctx, cancel := context.WithTimeout(t.Context(), 15*time.Second)
			defer cancel()
			backend, _ := setupBackendPacketFixture(ctx, t)
			authorization, history := backendAuthorizationFixture(t, backend.options.profile, 0)
			if err := backend.apply(ctx, authorization, history); err != nil {
				t.Fatal(err)
			}
			directory, store := serviceKernelStore(ctx, t)
			if name == "corrupt state" {
				if err := os.WriteFile(filepath.Join(directory, "state", "state.json"), []byte(`{"invalid":true}`), 0o600); err != nil {
					t.Fatal(err)
				}
			}
			service, err := backend.newService(serviceOptions{
				mode:  agent.Enforce,
				state: agent.Persistence{Load: store.Load, Save: store.Save},
				bindings: func(context.Context) (binding.Snapshot, error) {
					return binding.Snapshot{}, errors.New("synthetic binding source must not run during startup")
				},
				readerUID: 65534, requestTimeout: time.Second,
			})
			if err != nil {
				t.Fatal(err)
			}
			listener := serviceKernelListener(t, directory, "startup.sock")
			serveCtx := ctx
			if name == "canceled with cleanup failure" {
				if err := backend.options.generation.close(ctx); err != nil {
					t.Fatal(err)
				}
				canceled, cancel := context.WithCancel(ctx)
				cancel()
				serveCtx = canceled
			}
			err = service.serve(serveCtx, listener)
			if err == nil {
				t.Fatal("unsafe startup began accepting requests")
			}
			if name == "missing state" && !errors.Is(err, state.ErrUninitialized) {
				t.Fatal("missing state did not preserve its explicit initialization error")
			}
			if name == "canceled with cleanup failure" {
				if !errors.Is(err, context.Canceled) || !errors.Is(err, os.ErrClosed) {
					t.Fatal("failed startup discarded cancellation or independent cleanup failure")
				}
				// A broken writer fence cannot be bypassed even to seal. Native
				// expiry remains bounded; this is not a successful closure claim.
				return
			}
			assertClassifiedGuardInventory(ctx, t, backend.options.executor, backend.options.profile.layout, history, false)
			if _, err := os.Lstat(listener.Addr().String()); err != nil {
				t.Fatal("failed startup unlinked the supervisor's socket")
			}
			if _, err := store.Load(ctx); err == nil {
				t.Fatal("runtime initialized or repaired invalid state")
			}
			again := serviceKernelListener(t, directory, "retry.sock")
			if err := service.serve(ctx, again); err == nil {
				t.Fatal("failed startup was silently retried on the same service")
			}
		})
	}
}

func serviceKernelStore(ctx context.Context, t *testing.T) (string, *state.Store) {
	t.Helper()
	directory, err := os.MkdirTemp("", "rpa-service-")
	if err != nil {
		t.Fatal(err)
	}
	// #nosec G302 -- A root-owned, non-writable synthetic directory must be traversable by the reader.
	if err := os.Chmod(directory, 0o755); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := os.RemoveAll(directory); err != nil {
			t.Error(err)
		}
	})
	path := filepath.Join(directory, "state")
	if err := os.Mkdir(path, 0o700); err != nil {
		t.Fatal(err)
	}
	store, err := state.Open(ctx, state.Options{Directory: path, OwnerUID: 0})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := store.Close(); err != nil {
			t.Error(err)
		}
	})
	return directory, store
}

func serviceKernelListener(t *testing.T, directory, name string) *net.UnixListener {
	t.Helper()
	path := filepath.Join(directory, name)
	listener, err := net.ListenUnix("unix", &net.UnixAddr{Name: path, Net: "unix"})
	if err != nil {
		t.Fatal(err)
	}
	// #nosec G302 -- Synthetic shared root group; SO_PEERCRED still admits only the non-root UID.
	if err := os.Chmod(path, 0o660); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := listener.Close(); err != nil && !errors.Is(err, net.ErrClosed) {
			t.Error(err)
		}
	})
	return listener
}

func startServiceKernelFixture(
	ctx context.Context, t *testing.T, service *guardedService, listener *net.UnixListener,
) func() error {
	t.Helper()
	ctx, cancel := context.WithCancel(ctx)
	result := make(chan error, 1)
	var worker sync.WaitGroup
	worker.Go(func() { result <- service.serve(ctx, listener) })
	stop := sync.OnceValue(func() error {
		cancel()
		worker.Wait()
		return <-result
	})
	t.Cleanup(func() {
		if err := stop(); !errors.Is(err, context.Canceled) {
			t.Errorf("helper cleanup: %v", err)
		}
	})
	return stop
}

func serviceReaderExecutable(t *testing.T, directory string) string {
	t.Helper()
	path, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	// #nosec G304 -- Source is the current test binary, not caller-supplied input.
	source, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := source.Close(); err != nil {
			t.Error(err)
		}
	}()
	path = filepath.Join(directory, "reader.test")
	// #nosec G302 G304 -- Exclusive fixed filename in a newly created root-owned fixture directory.
	destination, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o755)
	if err != nil {
		t.Fatal(err)
	}
	_, copyErr := io.Copy(destination, source)
	if err := errors.Join(copyErr, destination.Close()); err != nil {
		t.Fatal(err)
	}
	return path
}

func serviceReaderSubmit(
	ctx context.Context, t *testing.T, executable, socket, baselineHash string,
	snapshot policy.DirectorySnapshot, expected string,
) {
	t.Helper()
	data, err := json.Marshal(snapshot)
	if err != nil {
		t.Fatal(err)
	}
	// #nosec G204 -- Copied current test binary and fixed test-entry flag only.
	command := exec.CommandContext(ctx, executable, "-test.run=^TestGuardedServiceReaderProcess$")
	command.Stdin = bytes.NewReader(data)
	command.Env = []string{
		"RPA_SERVICE_TEST_CHILD=1", "RPA_SERVICE_TEST_SOCKET=" + socket,
		"RPA_SERVICE_TEST_EXPECT=" + expected, "RPA_SERVICE_TEST_BASELINE=" + baselineHash,
	}
	// Only the fixture switches UID. Its synthetic shared socket group stays
	// zero to avoid requiring SETGID/CHOWN; the helper never authorizes by group.
	command.SysProcAttr = &syscall.SysProcAttr{
		Credential: &syscall.Credential{Uid: 65534, Gid: 0, NoSetGroups: true},
	}
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("synthetic unprivileged service client: %v: %s", err, output)
	}
}

func TestGuardedServiceReaderProcess(t *testing.T) {
	if os.Getenv("RPA_SERVICE_TEST_CHILD") != "1" {
		t.Skip("isolated unprivileged subprocess entry point")
	}
	if os.Geteuid() != 65534 {
		t.Fatal("service fixture reader did not drop UID")
	}
	var snapshot policy.DirectorySnapshot
	if err := json.NewDecoder(io.LimitReader(os.Stdin, 16<<20)).Decode(&snapshot); err != nil {
		t.Fatal("invalid synthetic directory input")
	}
	receipt, err := ipc.Submit(t.Context(), ipc.ClientOptions{
		Socket: os.Getenv("RPA_SERVICE_TEST_SOCKET"), ServerUID: 0, Timeout: 10 * time.Second,
	}, snapshot)
	if os.Getenv("RPA_SERVICE_TEST_EXPECT") == "rejected" {
		if !errors.Is(err, ipc.ErrRejected) || receipt.Status != ipc.StatusRejected || receipt.GrantCount != 0 {
			t.Fatal("synthetic service did not return an explicit zero-grant rejection")
		}
		return
	}
	expected := os.Getenv("RPA_SERVICE_TEST_EXPECT")
	expectedStatus := ipc.StatusApplied
	if expected == "shadow" {
		expectedStatus = ipc.StatusShadow
	}
	if err != nil || receipt.Status != expectedStatus || receipt.BaselineHash != os.Getenv("RPA_SERVICE_TEST_BASELINE") {
		t.Fatalf("synthetic service submission failed: %v", err)
	}
	if (expected == "applied" || expected == "shadow") && (receipt.GrantCount == 0 || receipt.DenialCount != 0) ||
		expected == "denied" && (receipt.GrantCount != 0 || receipt.DenialCount != 1) ||
		expected != "applied" && expected != "denied" && expected != "shadow" {
		t.Fatal("synthetic service receipt did not reflect its policy decision")
	}
}
