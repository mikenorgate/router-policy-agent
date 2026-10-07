//go:build integration && linux

package firewall

import (
	"errors"
	"math"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/mikenorgate/router-policy-agent/internal/hostfs"
	"github.com/mikenorgate/router-policy-agent/internal/state"
)

func recoveryOwnerFixture(t *testing.T) (string, helperConfig) {
	t.Helper()
	root, directory, config := privateHelperConfigFixture(t)
	_, options, data := privateRouterProfileFixture(t)
	profile, err := decodePinnedProfile(t.Context(), data, options.SHA256)
	if err != nil {
		t.Fatal(err)
	}
	_, executable := processFixture(t, "nft-error")
	_, _, generationDirectory := generationGateFixture(t)
	config.Profile = helperProfile(options)
	config.NFTExecutable, config.GenerationDir = executable, generationDirectory
	config.StateDir = t.TempDir()
	if err := os.Chmod(config.StateDir, 0o700); err != nil { // #nosec G302 -- Private fixture directory.
		t.Fatal(err)
	}
	config.ExpectedGeneration.FloorHash = profile.ruleset.digest
	if err := root.WriteFile(helperConfigFile, helperConfigBytes(t, config), 0o600); err != nil {
		t.Fatal(err)
	}
	return directory, config
}

func TestConfiguredCleanupAttemptsEveryResourceAfterFailure(t *testing.T) {
	t.Parallel()
	for _, name := range []string{"clean", "store already closed", "fence already closed"} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			uid := os.Geteuid()
			if uid < 0 {
				t.Fatal("invalid isolated test identity")
				return
			}
			wideUID := uint64(uid)
			if wideUID > math.MaxUint32 {
				t.Fatal("isolated test identity exceeds the credential field")
				return
			}
			owner := uint32(wideUID)
			storeDir, fenceDir := t.TempDir(), t.TempDir()
			for _, directory := range []string{storeDir, fenceDir} {
				if err := os.Chmod(directory, 0o700); err != nil { // #nosec G302 -- Private fixture directory.
					t.Fatal(err)
				}
			}
			store, err := state.Open(t.Context(), state.Options{Directory: storeDir, OwnerUID: owner})
			if err != nil {
				t.Fatal(err)
			}
			fence, err := hostfs.OpenFence(t.Context(), hostfs.DirectoryOptions{
				Path: fenceDir, OwnerUID: owner, Private: true,
			})
			if err != nil {
				t.Fatal(errors.Join(err, store.Close()))
			}
			// Opening a checked system ELF is read-only; no command is executed.
			executor, err := openProcess(t.Context(), "/usr/bin/true")
			if err != nil {
				t.Fatal(errors.Join(err, store.Close(), fence.Close(t.Context())))
			}
			resources := &configuredResources{store: store, gate: &generationGate{fence: fence}, executor: executor}
			t.Cleanup(func() {
				hasResources := resources.store != nil || resources.gate != nil || resources.executor != nil
				if hasResources {
					if err := resources.close(t.Context()); err != nil {
						t.Error(err)
					}
				}
			})
			switch name {
			case "store already closed":
				if err := store.Close(); err != nil {
					t.Fatal(err)
				}
			case "fence already closed":
				if err := fence.Close(t.Context()); err != nil {
					t.Fatal(err)
				}
			}
			err = resources.close(t.Context())
			if name == "clean" && err != nil || name != "clean" && !errors.Is(err, os.ErrClosed) {
				t.Fatal("cleanup ignored a resource error or failed a complete close")
			}
			hasResources := resources.store != nil || resources.gate != nil || resources.executor != nil
			if hasResources || executor.executable != nil {
				t.Fatal("cleanup stopped after an earlier resource failure")
			}
			if err := fence.Close(t.Context()); !errors.Is(err, os.ErrClosed) {
				t.Fatal("cleanup retained its writer fence")
			}
			reopened, err := state.Open(t.Context(), state.Options{Directory: storeDir, OwnerUID: owner})
			if err != nil {
				t.Fatal("cleanup retained the process lock")
			}
			if err := reopened.Close(); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestRecoverFailedInspectionRedactsAndReleasesOwner(t *testing.T) {
	t.Parallel()
	directory, config := recoveryOwnerFixture(t)
	err := Recover(t.Context(), directory)
	if err == nil || strings.Contains(err.Error(), "synthetic-confidential") || strings.Contains(err.Error(), directory) {
		t.Fatal("failed recovery succeeded or exposed private diagnostics")
	}
	store, err := state.Open(t.Context(), state.Options{Directory: config.StateDir, OwnerUID: 0})
	if err != nil {
		t.Fatal("failed recovery retained the process lock")
	}
	if _, err := store.Load(t.Context()); !errors.Is(err, state.ErrUninitialized) {
		t.Fatal("recovery initialized missing history after an inspection failure")
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(config.StateDir, "state.json")); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("unsuccessful recovery wrote a durable state file")
	}
}

func TestRecoverRefusesAnAlreadyOwnedPersistentStore(t *testing.T) {
	t.Parallel()
	directory, config := recoveryOwnerFixture(t)
	store, err := state.Open(t.Context(), state.Options{Directory: config.StateDir, OwnerUID: 0})
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := store.Close(); err != nil {
			t.Error(err)
		}
	}()
	if err := Recover(t.Context(), directory); err == nil || strings.Contains(err.Error(), directory) {
		t.Fatal("recovery stole the live owner's lock or disclosed a private path")
	}
	if _, err := store.Load(t.Context()); !errors.Is(err, state.ErrUninitialized) {
		t.Fatal("rejected recovery disturbed the existing store owner")
	}
}
