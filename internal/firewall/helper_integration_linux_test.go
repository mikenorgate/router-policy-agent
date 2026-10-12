//go:build integration && linux

package firewall

import (
	"context"
	"errors"
	"net"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/mikenorgate/router-policy-agent/internal/agent"
	"github.com/mikenorgate/router-policy-agent/internal/binding"
	"github.com/mikenorgate/router-policy-agent/internal/state"
)

func TestHelperInitializationNeverResetsHistory(t *testing.T) {
	t.Parallel()
	root, directory, config := privateHelperConfigFixture(t)
	config.StateDir = t.TempDir()
	if err := os.Chmod(config.StateDir, 0o700); err != nil { // #nosec G302 -- Private synthetic state directory.
		t.Fatal(err)
	}
	if err := root.WriteFile(helperConfigFile, helperConfigBytes(t, config), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := InitializeState(t.Context(), directory); err != nil {
		t.Fatal("explicit first installation failed", err)
	}
	path := filepath.Join(config.StateDir, "state.json")
	for _, name := range []string{"existing", "corrupt"} {
		t.Run(name, func(t *testing.T) {
			if name == "corrupt" {
				if err := os.WriteFile(path, []byte(`{"schema_version":1}`), 0o600); err != nil {
					t.Fatal(err)
				}
			}
			before, err := os.ReadFile(path) // #nosec G304 -- Fixed file inside newly created private fixture.
			if err != nil {
				t.Fatal(err)
			}
			if err := InitializeState(t.Context(), directory); err == nil {
				t.Fatal("initialization replaced existing history")
			}
			after, err := os.ReadFile(path) // #nosec G304 -- Same private fixture file.
			if err != nil || string(before) != string(after) {
				t.Fatal("failed initialization changed history")
			}
			store, err := state.Open(t.Context(), state.Options{Directory: config.StateDir, OwnerUID: 0})
			if err != nil {
				t.Fatal("failed initialization retained exclusive ownership")
			}
			if err := store.Close(); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestHelperRejectsBindingSourceChangeBetweenStartupReads(t *testing.T) {
	t.Parallel()
	for _, name := range []string{"shadow to normal", "normal to shadow"} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			root, directory, config := privateHelperConfigFixture(t)
			selected := radiusShadowSource
			if name == "normal to shadow" {
				config.Mode, config.BindingSource = agent.Shadow, radiusShadowSource
				selected = ""
			}
			if err := root.WriteFile(helperConfigFile, helperConfigBytes(t, config), 0o600); err != nil {
				t.Fatal(err)
			}
			reads := 0
			err := runConfiguredService(t.Context(), configuredOptions{
				directory: directory, bindingSource: selected, requests: &net.UnixListener{}, status: &net.UnixListener{},
				bindings: func(context.Context) (binding.Snapshot, error) {
					reads++
					return binding.Snapshot{}, errors.New("unexpected binding read")
				},
			})
			if err == nil || !strings.Contains(err.Error(), "binding source changed") || reads != 0 {
				t.Fatal("source replacement crossed the mode boundary", err)
			}
		})
	}
}

func TestInheritedHelperListenerRetainsSupervisorSocket(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "s")
	listener, err := net.ListenUnix("unix", &net.UnixAddr{Name: path, Net: "unix"})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := listener.Close(); err != nil {
			t.Error(err)
		}
	})
	file, err := listener.File()
	if err != nil {
		t.Fatal(err)
	}
	fd, dupErr := syscall.Dup(int(file.Fd())) // #nosec G115 -- A live OS descriptor fits the platform int.
	if err := errors.Join(dupErr, file.Close()); err != nil {
		t.Fatal(err)
	}
	// The raw inherited descriptor has one owner; the supervisor retains
	// its separate listener, just as with activation across exec.
	adopted, err := inheritedListener(uintptr(fd)) // #nosec G115 -- Dup succeeded with a nonnegative descriptor.
	if err != nil {
		t.Fatal(err)
	}
	if !configuredListenerMatches(adopted, path) || configuredListenerMatches(adopted, path+"-other") {
		t.Fatal("adopted listener did not retain its actual configured identity")
	}
	if err := closeHelperListener(adopted); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(path); err != nil {
		t.Fatal("helper removed supervisor-owned socket path")
	}
	if err := listener.SetDeadline(time.Now()); err != nil {
		t.Fatal("helper closed the supervisor's listener")
	}
}

func TestHelperRequiresActivationBeforeOpeningRuntime(t *testing.T) {
	_, directory, _ := privateHelperConfigFixture(t)
	t.Setenv("LISTEN_PID", "")
	t.Setenv("LISTEN_FDS", "")
	t.Setenv("LISTEN_FDNAMES", "")
	if err := RunHelper(t.Context(), directory, "/nonexistent-bindings"); err == nil {
		t.Fatal("helper started without supervisor-owned sockets")
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if err := InitializeState(ctx, directory); !errors.Is(err, context.Canceled) {
		t.Fatal("canceled initialization opened persistent resources")
	}
}
