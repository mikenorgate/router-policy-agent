//go:build integration && kernel && servicekernel && linux

package firewall

import (
	"bytes"
	"context"
	"errors"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/mikenorgate/router-policy-agent/internal/binding"
	"github.com/mikenorgate/router-policy-agent/internal/ipc"
	"github.com/mikenorgate/router-policy-agent/internal/state"
)

func configuredKernelOptions(
	ctx context.Context,
	t *testing.T,
	backend *guardedBackend,
	writerRoot *os.Root,
) configuredOptions {
	t.Helper()
	root, configDir, config := privateHelperConfigFixture(t)
	profileRoot, profileOptions, _ := privateRouterProfileFixture(t)
	profile, _, data := backendPacketProfileDataFixture(t)
	if profile.digest != backend.options.profile.digest {
		t.Fatal("independently authored fixture profile changed")
	}
	if err := profileRoot.WriteFile(routerProfileFile, data, 0o600); err != nil {
		t.Fatal(err)
	}
	directory, err := os.MkdirTemp("", "rpa-configured-")
	if err != nil {
		t.Fatal(err)
	}
	// #nosec G302 -- The two synthetic non-root clients need directory traversal.
	if err := os.Chmod(directory, 0o755); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := os.RemoveAll(directory); err != nil {
			t.Error(err)
		}
	})
	config.StateDir = filepath.Join(directory, "state")
	if err := os.Mkdir(config.StateDir, 0o700); err != nil {
		t.Fatal(err)
	}
	store, err := state.Open(ctx, state.Options{Directory: config.StateDir, OwnerUID: 0})
	if err != nil {
		t.Fatal(err)
	}
	if err := errors.Join(store.Initialize(ctx), store.Close()); err != nil {
		t.Fatal(err)
	}
	requests := serviceKernelListener(t, directory, "requests.sock")
	status := serviceKernelListener(t, directory, "status.sock")
	config.Profile = helperProfile{Directory: profileOptions.Directory, SHA256: profile.digest}
	config.GenerationDir, config.ExpectedGeneration = writerRoot.Name(), backend.options.expected
	config.NFTExecutable = "/usr/sbin/nft"
	config.RequestSocket, config.StatusSocket = requests.Addr().String(), status.Addr().String()
	config.RequestTimeoutMS = 10000
	if err := root.WriteFile(helperConfigFile, helperConfigBytes(t, config), 0o600); err != nil {
		t.Fatal(err)
	}
	return configuredOptions{directory: configDir, requests: requests, status: status}
}

func TestKernelGuardedServiceConfiguredSupervision(t *testing.T) {
	requireKernelIsolation(t)
	t.Cleanup(func() { requireKernelIsolation(t) })
	ctx, cancel := context.WithTimeout(t.Context(), 45*time.Second)
	defer cancel()
	backend, writerRoot := setupBackendPacketFixture(ctx, t)
	options := configuredKernelOptions(
		ctx,
		t,
		backend,
		writerRoot,
	)
	bindings := make(chan binding.Snapshot, 1)
	options.bindings = func(ctx context.Context) (binding.Snapshot, error) {
		select {
		case snapshot := <-bindings:
			return snapshot, nil
		case <-ctx.Done():
			return binding.Snapshot{}, ctx.Err()
		}
	}
	serveCtx, stop := context.WithCancel(ctx)
	defer stop()
	result := make(chan error, 1)
	exited := make(chan struct{})
	var worker sync.WaitGroup
	worker.Go(func() {
		defer close(exited)
		result <- runConfiguredService(serveCtx, options)
	})
	finish := sync.OnceValue(func() error {
		worker.Wait()
		return <-result
	})
	t.Cleanup(func() {
		stop()
		if err := finish(); !errors.Is(err, context.Canceled) {
			t.Errorf("configured helper cleanup: %v", err)
		}
	})
	executable := serviceReaderExecutable(t, filepath.Dir(options.requests.Addr().String()))
	// Accepting this separate status client proves both listeners started after
	// closed startup. The child cannot submit a directory transaction.
	// #nosec G204 -- Fixed entry point in the current synthetic test executable.
	command := exec.CommandContext(ctx, executable, "-test.run=^TestConfiguredServiceStartupProcess$")
	command.Env = []string{"RPA_CONFIGURED_STATUS_CHILD=1", "RPA_CONFIGURED_STATUS_SOCKET=" + options.status.Addr().String()}
	command.SysProcAttr = &syscall.SysProcAttr{Credential: &syscall.Credential{Uid: 65533, Gid: 0, NoSetGroups: true}}
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("configured closed startup: %v: %s", err, output)
	}
	input := backendInputFixture(t, 0)
	bindings <- input.Bindings
	serviceReaderSubmit(
		ctx,
		t,
		executable,
		options.requests.Addr().String(),
		backend.options.profile.renderer.compiler.BaselineHash(),
		input.Directory,
		"applied",
	)
	peer, device := packetSocket(t, "peer0"), packetSocket(t, "device0")
	traffic := func(allowed bool) {
		t.Helper()
		for _, datagram := range backendNativeFrames(t) {
			from, to := device, peer
			if datagram.sourceMAC == "02:00:00:00:00:10" {
				from, to = peer, device
			}
			frame := packetFrame(t, datagram)
			sendPacket(ctx, t, from, frame)
			receivePacket(
				ctx,
				t,
				to,
				frame,
				allowed,
			)
		}
	}
	traffic(true)
	// Status-listener failure must stop the writer and seal leases before the
	// owning runner releases its state lock or backend descriptors.
	if err := options.status.Close(); err != nil {
		t.Fatal(err)
	}
	select {
	case <-exited:
	case <-time.After(5 * time.Second):
		t.Fatal("status failure did not stop the writer without parent cancellation")
	}
	if err := finish(); !errors.Is(err, context.Canceled) || !errors.Is(err, net.ErrClosed) {
		t.Fatal("status failure did not terminate the joined helper")
	}
	traffic(false)
	for _, listener := range []*net.UnixListener{options.requests, options.status} {
		if _, err := os.Lstat(listener.Addr().String()); err != nil {
			t.Fatal("helper unlinked a supervisor-owned path")
		}
		if err := listener.SetDeadline(time.Now().Add(time.Second)); !errors.Is(err, net.ErrClosed) {
			t.Fatal("helper returned without closing both adopted listeners")
		}
	}
	config, err := loadHelperConfig(ctx, options.directory)
	if err != nil {
		t.Fatal(err)
	}
	store, err := state.Open(ctx, state.Options{Directory: config.StateDir, OwnerUID: 0})
	if err != nil {
		t.Fatal("joined helper retained its state process lock")
	}
	document, loadErr := store.Load(ctx)
	if err := errors.Join(loadErr, store.Close()); err != nil {
		t.Fatal(err)
	}
	if len(document.ClassifiedIPv4) == 0 || len(document.ClassifiedIPv6) == 0 || document.DirectoryHash == "" {
		t.Fatal("joined cleanup discarded durable deny-only history")
	}
}

func TestConfiguredServiceStartupProcess(t *testing.T) {
	if os.Getenv("RPA_CONFIGURED_STATUS_CHILD") != "1" {
		t.Skip("subprocess entry point")
	}
	if os.Geteuid() != 65533 {
		t.Fatal("configured status client retained privileged identity")
	}
	report, err := ipc.ReadStatus(t.Context(), ipc.ClientOptions{
		Socket: os.Getenv("RPA_CONFIGURED_STATUS_SOCKET"), ServerUID: 0, Timeout: 10 * time.Second,
	})
	validStartup := err == nil && report.HelperState == "ready" && report.LastGrantCount == 0
	validKernel := report.FloorState == "matches_pinned_contract" && report.KernelTupleCount != nil
	if !validStartup || !validKernel || *report.KernelTupleCount != 0 {
		t.Fatal("configured helper did not restore a closed inspected state before accepting status")
	}
}

func TestKernelGuardedServiceConfiguredFailedStartup(t *testing.T) {
	for _, name := range []string{"missing", "corrupt"} {
		t.Run(name, func(t *testing.T) {
			requireKernelIsolation(t)
			t.Cleanup(func() { requireKernelIsolation(t) })
			ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
			defer cancel()
			backend, writerRoot := setupBackendPacketFixture(ctx, t)
			options := configuredKernelOptions(
				ctx,
				t,
				backend,
				writerRoot,
			)
			authorization, history := backendAuthorizationFixture(t, backend.options.profile, 0)
			if err := backend.apply(ctx, authorization, history); err != nil {
				t.Fatal(err)
			}
			assertClassifiedGuardInventory(ctx, t, backend.options.executor, backend.options.profile.layout, history, true)
			config, err := loadHelperConfig(ctx, options.directory)
			if err != nil {
				t.Fatal(err)
			}
			root, err := os.OpenRoot(config.StateDir)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() {
				if err := root.Close(); err != nil {
					t.Error(err)
				}
			})
			badState := []byte(`{"schema_version":1}`)
			if name == "missing" {
				if err := root.Remove("state.json"); err != nil {
					t.Fatal(err)
				}
			}
			if name == "corrupt" {
				if err := root.WriteFile("state.json", badState, 0o600); err != nil {
					t.Fatal(err)
				}
			}
			reads := 0
			options.bindings = func(context.Context) (binding.Snapshot, error) {
				reads++
				return binding.Snapshot{}, nil
			}
			if err := runConfiguredService(ctx, options); err == nil || reads != 0 {
				t.Fatal("invalid history started either service or collected bindings")
			}
			assertClassifiedGuardInventory(ctx, t, backend.options.executor, backend.options.profile.layout, history, false)
			after, readErr := root.ReadFile("state.json")
			if name == "missing" && !errors.Is(readErr, os.ErrNotExist) {
				t.Fatal("configured runtime initialized missing history")
			}
			if name == "corrupt" && (readErr != nil || !bytes.Equal(after, badState)) {
				t.Fatal("configured runtime repaired corrupt history")
			}
			for _, listener := range []*net.UnixListener{options.requests, options.status} {
				if err := listener.SetDeadline(time.Now().Add(time.Second)); !errors.Is(err, net.ErrClosed) {
					t.Fatal("failed closed startup retained an adopted listener")
				}
			}
		})
	}
}
