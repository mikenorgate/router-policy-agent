//go:build integration

package radius

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/mikenorgate/router-policy-agent/internal/binding"
	"github.com/mikenorgate/router-policy-agent/internal/hostfs"
)

func privateExportRoot(t *testing.T) (string, *os.Root) {
	t.Helper()
	if os.Geteuid() != 0 {
		t.Skip("isolated root identity required for root-private export fixture")
	}
	directory := t.TempDir()
	// #nosec G302 -- Private fixture directory needs owner traversal, not file mode 0600.
	if err := os.Chmod(directory, 0o700); err != nil {
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
	return directory, root
}

func readShadowFixture(t *testing.T, directory string) (shadowReport, []byte) {
	t.Helper()
	// #nosec G304 -- Fixed filename inside this test's private t.TempDir, not external input.
	data, err := os.ReadFile(filepath.Join(directory, shadowFilename))
	if err != nil {
		t.Fatal(err)
	}
	var report shadowReport
	if err := json.Unmarshal(data, &report); err != nil {
		t.Fatal(err)
	}
	return report, data
}

func fixtureCollection(t *testing.T) Collection {
	t.Helper()
	candidate, err := MatchIPv4(currentSession(t), fixtureLeaseObservation(), fixtureLeaseScope(), fixtureTime().Add(75*time.Second))
	if err != nil {
		t.Fatal(err)
	}
	return Collection{ObservedAt: fixtureTime().Add(75 * time.Second), Generation: strings.Repeat("a", 64), Candidates: []IPv4Candidate{candidate}}
}

func TestPublishShadowCannotBecomeHelperBindings(t *testing.T) {
	t.Parallel()
	directory, root := privateExportRoot(t)
	want := fixtureCollection(t)
	_, err := publishIPv4(t.Context(), root, func(context.Context) (Collection, error) {
		before, _ := readShadowFixture(t, directory)
		if before.Complete || before.EnforcementReady || len(before.Collection.Candidates) != 0 {
			t.Fatal("previous result remained complete during collection")
		}
		return want, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	report, data := readShadowFixture(t, directory)
	if !report.Complete || report.EnforcementReady || report.Mode != "shadow" || report.Kind != "radius_ipv4_shadow_v1" ||
		len(report.Collection.Candidates) != 1 || report.Collection.Candidates[0] != want.Candidates[0] {
		t.Fatal("shadow fields or original times changed")
	}
	file, err := root.Open(shadowFilename)
	if err != nil {
		t.Fatal(err)
	}
	if err := errors.Join(hostfs.CheckPrivateFile(file, 0, maximumShadow), file.Close()); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(directory, "bindings.json"), data, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := binding.Load(t.Context(), directory); err == nil {
		t.Fatal("shadow export accepted by authoritative helper schema")
	}
	entries, err := os.ReadDir(directory)
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		if strings.HasPrefix(entry.Name(), ".radius-shadow-") {
			t.Fatal("temporary export left behind")
		}
	}
}

func TestPublishShadowInvalidatesBeforeCollectionFailureOrCancellation(t *testing.T) {
	t.Parallel()
	for _, name := range []string{"source failure", "cancel before final publication"} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			directory, root := privateExportRoot(t)
			if err := writeShadow(t.Context(), root, shadowReport{Kind: "radius_ipv4_shadow_v1", Mode: "shadow", Complete: true, Collection: fixtureCollection(t)}); err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			result, err := publishIPv4(ctx, root, func(context.Context) (Collection, error) {
				if name == "source failure" {
					return Collection{}, errors.New("synthetic source unavailable")
				}
				cancel()
				return fixtureCollection(t), nil
			})
			if err == nil || len(result.Candidates) != 0 {
				t.Fatal("failure returned collection")
			}
			report, _ := readShadowFixture(t, directory)
			if report.Complete || report.EnforcementReady || len(report.Collection.Candidates) != 0 {
				t.Fatal("failure retained previous complete collection")
			}
		})
	}
}

func TestPublishShadowRejectsUnsafeExistingFilesAndDirectory(t *testing.T) {
	t.Parallel()
	for _, name := range []string{"symlink", "hardlink", "fifo", "world readable", "public directory"} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			directory, root := privateExportRoot(t)
			path := filepath.Join(directory, shadowFilename)
			var err error
			switch name {
			case "symlink":
				err = os.Symlink("other.json", path)
			case "hardlink":
				other := filepath.Join(directory, "other.json")
				if err := os.WriteFile(other, []byte("{}"), 0o600); err != nil {
					t.Fatal(err)
				}
				err = os.Link(other, path)
			case "fifo":
				err = syscall.Mkfifo(path, 0o600)
			case "world readable":
				// #nosec G306 -- Synthetic negative fixture must be rejected for this unsafe mode.
				err = os.WriteFile(path, []byte("{}"), 0o644)
			case "public directory":
				// #nosec G302 -- Synthetic negative fixture tests rejection of a nonprivate directory.
				err = os.Chmod(directory, 0o755)
			}
			if err != nil {
				t.Fatal(err)
			}
			if name == "public directory" {
				if _, err := PublishIPv4(t.Context(), fixtureCollectorOptions(), directory); err == nil {
					t.Fatal("nonprivate directory admitted")
				}
			} else if err := writeShadow(t.Context(), root, shadowReport{}); err == nil {
				t.Fatal("unsafe export replaced")
			}
		})
	}
}

func TestPublishShadowExclusiveLock(t *testing.T) {
	t.Parallel()
	directory, root := privateExportRoot(t)
	lock, err := hostfs.OpenLock(t.Context(), root, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := lock.Close(); err != nil {
			t.Error(err)
		}
	}()
	fd, err := fileDescriptor(lock)
	if err != nil {
		t.Fatal(err)
	}
	if err := syscall.Flock(fd, syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := syscall.Flock(fd, syscall.LOCK_UN); err != nil {
			t.Error(err)
		}
	}()
	if _, err := PublishIPv4(t.Context(), fixtureCollectorOptions(), directory); err == nil {
		t.Fatal("second publisher acquired same directory")
	}
	if _, err := os.Stat(filepath.Join(directory, shadowFilename)); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("blocked publisher modified export")
	}
}
