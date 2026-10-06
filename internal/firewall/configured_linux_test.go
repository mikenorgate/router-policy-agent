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

	"github.com/mikenorgate/router-policy-agent/internal/binding"
	"github.com/mikenorgate/router-policy-agent/internal/state"
)

func privateHelperConfigFixture(t *testing.T) (*os.Root, string, helperConfig) {
	t.Helper()
	if os.Geteuid() != 0 {
		t.Skip("root-owned configuration fixture runs only in isolated root CI")
	}
	directory := t.TempDir()
	if err := os.Chmod(directory, 0o700); err != nil { // #nosec G302 -- Private fixture needs directory search permission.
		t.Fatal(err)
	}
	root, err := os.OpenRoot(directory)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := root.Close(); err != nil {
			t.Error(err)
		}
	})
	config := helperConfigFixture()
	if err := root.WriteFile(helperConfigFile, helperConfigBytes(t, config), 0o600); err != nil {
		t.Fatal(err)
	}
	return root, directory, config
}

func TestHelperConfigLoadsOnlyPrivateRootOwnedFile(t *testing.T) {
	t.Parallel()
	root, directory, config := privateHelperConfigFixture(t)
	for _, mode := range []os.FileMode{0o400, 0o600} {
		if err := root.Chmod(helperConfigFile, mode); err != nil {
			t.Fatal(err)
		}
		got, err := loadHelperConfig(t.Context(), directory)
		if err != nil || got != config {
			t.Fatalf("safe helper configuration failed: %v", err)
		}
	}
}

func TestHelperConfigRejectsUnsafeRootFiles(t *testing.T) {
	t.Parallel()
	for _, name := range []string{
		"missing", "empty", "oversized", "public", "executable", "write-only", "symlink", "hardlink", "fifo",
		"wrong owner", "public directory", "relative directory", "invalid json",
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			root, directory, _ := privateHelperConfigFixture(t)
			switch name {
			case "missing", "symlink", "fifo":
				if err := root.Remove(helperConfigFile); err != nil {
					t.Fatal(err)
				}
				if name == "symlink" {
					if err := root.WriteFile("other.json", []byte(`{}`), 0o600); err != nil {
						t.Fatal(err)
					}
					if err := root.Symlink("other.json", helperConfigFile); err != nil {
						t.Fatal(err)
					}
				}
				if name == "fifo" {
					if err := syscall.Mkfifo(filepath.Join(directory, helperConfigFile), 0o600); err != nil {
						t.Fatal(err)
					}
				}
			case "hardlink":
				if err := root.Link(helperConfigFile, "other.json"); err != nil {
					t.Fatal(err)
				}
			case "empty", "oversized", "invalid json":
				data := []byte{}
				if name == "oversized" {
					data = []byte(strings.Repeat("x", maximumHelperConfig+1))
				}
				if name == "invalid json" {
					data = []byte(`{}`)
				}
				if err := root.WriteFile(helperConfigFile, data, 0o600); err != nil {
					t.Fatal(err)
				}
			case "public", "executable", "write-only":
				mode := os.FileMode(0o644)
				if name == "executable" {
					mode = 0o700
				}
				if name == "write-only" {
					mode = 0o200
				}
				if err := root.Chmod(helperConfigFile, mode); err != nil { // #nosec G302 -- Intentionally rejected metadata.
					t.Fatal(err)
				}
			case "wrong owner":
				if err := root.Chown(helperConfigFile, 65534, 65534); err != nil {
					if errors.Is(err, syscall.EPERM) {
						t.Skip("ownership substitution needs CAP_CHOWN in the isolated root CI job")
					}
					t.Fatal(err)
				}
			case "public directory":
				if err := root.Chmod(".", 0o755); err != nil { // #nosec G302 -- Intentionally rejected metadata.
					t.Fatal(err)
				}
			case "relative directory":
				directory = "relative"
			}
			got, err := loadHelperConfig(t.Context(), directory)
			if err == nil || got != (helperConfig{}) {
				t.Fatal("unsafe helper configuration returned a usable value")
			}
		})
	}
}

func TestConfiguredResourcesAreInertAndReleasePartialOpening(t *testing.T) {
	t.Parallel()
	_, profileOptions, data := privateRouterProfileFixture(t)
	_, executable := processFixture(t, "nft-error")
	_, _, generationDir := generationGateFixture(t)
	stateDir := t.TempDir()
	if err := os.Chmod(stateDir, 0o700); err != nil { // #nosec G302 -- Private fixture state directory.
		t.Fatal(err)
	}
	profile, err := decodePinnedProfile(t.Context(), data, profileOptions.SHA256)
	if err != nil {
		t.Fatal(err)
	}
	config := helperConfigFixture()
	config.Profile = helperProfile(profileOptions)
	config.NFTExecutable, config.GenerationDir, config.StateDir = executable, generationDir, stateDir
	config.ExpectedGeneration.FloorHash = profile.ruleset.digest
	reads := 0
	bindings := func(context.Context) (binding.Snapshot, error) { reads++; return binding.Snapshot{}, nil }
	resources, err := openConfiguredResources(t.Context(), config, bindings)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := resources.store.Load(t.Context()); !errors.Is(err, state.ErrUninitialized) || reads != 0 {
		t.Fatal("resource opening initialized missing state or collected bindings")
	}
	if err := resources.close(t.Context()); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"profile pin", "executable", "fence", "store", "paired floor"} {
		t.Run(name, func(t *testing.T) {
			changed := config
			switch name {
			case "profile pin":
				changed.Profile.SHA256 = strings.Repeat("b", 64)
			case "executable":
				changed.NFTExecutable += "-missing"
			case "fence":
				changed.GenerationDir += "-missing"
			case "store":
				changed.StateDir += "-missing"
			case "paired floor":
				changed.ExpectedGeneration.FloorHash = strings.Repeat("b", 64)
			}
			if resources, err := openConfiguredResources(t.Context(), changed, bindings); err == nil || resources != nil {
				t.Fatal("failed resource opening returned an activation candidate")
			}
			store, err := state.Open(t.Context(), state.Options{Directory: stateDir, OwnerUID: 0})
			if err != nil {
				t.Fatal("failed opening retained the state process lock")
			}
			if err := store.Close(); err != nil {
				t.Fatal(err)
			}
		})
	}
	if reads != 0 {
		t.Fatal("inert construction called the binding producer")
	}
}

func TestConfiguredHelperRejectsMissingInputsAndCancellation(t *testing.T) {
	t.Parallel()
	// Deliberately invalid input; executable wiring must provide a real context.
	var missingContext context.Context
	if err := runConfiguredService(missingContext, configuredOptions{}); err == nil {
		t.Fatal("missing configured helper inputs accepted")
	}
	if resources, err := openConfiguredResources(missingContext, helperConfigFixture(), nil); err == nil || resources != nil {
		t.Fatal("missing resource inputs accepted")
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if _, err := loadHelperConfig(ctx, "/unavailable"); !errors.Is(err, context.Canceled) {
		t.Fatal("canceled loader did not reject before opening files")
	}
	if _, err := loadHelperConfig(missingContext, "/unavailable"); err == nil {
		t.Fatal("nil configuration context accepted")
	}
	if os.Geteuid() != 0 {
		if _, err := loadHelperConfig(t.Context(), "/unavailable"); err == nil {
			t.Fatal("non-root loader accepted")
		}
	}
	cleanup, stop := context.WithTimeout(t.Context(), time.Second)
	defer stop()
	if err := (*configuredResources)(nil).close(cleanup); err == nil {
		t.Fatal("missing cleanup owner accepted")
	}
	if err := (&configuredResources{}).close(cleanup); err != nil {
		t.Fatal("empty partial construction could not be cleaned up")
	}
}

func TestConfiguredHelperRejectsNonRootWithoutAdoption(t *testing.T) {
	t.Parallel()
	if os.Geteuid() == 0 {
		t.Skip("this boundary requires the ordinary non-root test runner")
	}
	requests, status := serviceUnitListener(t), serviceUnitListener(t)
	options := configuredOptions{
		directory: "/unavailable", requests: requests, status: status,
		bindings: func(context.Context) (binding.Snapshot, error) {
			t.Fatal("non-root activation read bindings")
			return binding.Snapshot{}, nil
		},
	}
	if err := runConfiguredService(t.Context(), options); err == nil {
		t.Fatal("non-root helper activation accepted")
	}
	for _, listener := range []*net.UnixListener{requests, status} {
		if err := listener.SetDeadline(time.Now().Add(time.Second)); err != nil {
			t.Fatal("non-root activation adopted a caller-owned listener")
		}
	}
}

func TestConfiguredHelperDoesNotAdoptRejectedListeners(t *testing.T) {
	t.Parallel()
	root, directory, config := privateHelperConfigFixture(t)
	requests, status := serviceUnitListener(t), serviceUnitListener(t)
	bindings := func(context.Context) (binding.Snapshot, error) {
		t.Fatal("rejected helper collected bindings")
		return binding.Snapshot{}, nil
	}
	options := configuredOptions{directory: directory, bindings: bindings, requests: requests, status: status}
	if err := runConfiguredService(t.Context(), options); err == nil {
		t.Fatal("mismatched supervisor paths accepted")
	}
	config.RequestSocket, config.StatusSocket = requests.Addr().String(), status.Addr().String()
	if err := root.WriteFile(helperConfigFile, helperConfigBytes(t, config), 0o600); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if err := runConfiguredService(ctx, options); !errors.Is(err, context.Canceled) {
		t.Fatal("canceled preflight accepted supervisor resources")
	}
	for _, listener := range []*net.UnixListener{requests, status} {
		if err := listener.SetDeadline(time.Now().Add(time.Second)); err != nil {
			t.Fatal("rejected preflight closed a caller-owned listener")
		}
	}
}
