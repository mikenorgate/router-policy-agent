//go:build integration && linux

package binding

import (
	"os"
	"path/filepath"
	"syscall"
	"testing"
)

func TestBindingExportCheckedFileAndFreshReopen(t *testing.T) {
	t.Parallel()
	if os.Geteuid() != 0 {
		if _, err := Load(t.Context(), "/synthetic/unavailable"); err == nil {
			t.Fatal("non-root export read accepted")
		}
		t.Skip("root-owned export fixture requires isolated root CI")
	}
	for _, name := range []string{"valid", "missing", "public", "executable", "symlink", "hardlink", "fifo", "public directory", "stale reopen"} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			directory := t.TempDir()
			if err := os.Chmod(directory, 0o700); err != nil { // #nosec G302 -- Private fixture directory.
				t.Fatal(err)
			}
			path := filepath.Join(directory, "bindings.json")
			if err := os.WriteFile(path, snapshotBytes(t), 0o600); err != nil {
				t.Fatal(err)
			}
			switch name {
			case "missing", "symlink", "fifo":
				if err := os.Remove(path); err != nil {
					t.Fatal(err)
				}
				if name == "symlink" {
					if err := os.WriteFile(filepath.Join(directory, "other"), snapshotBytes(t), 0o600); err != nil {
						t.Fatal(err)
					}
					if err := os.Symlink("other", path); err != nil {
						t.Fatal(err)
					}
				}
				if name == "fifo" {
					if err := syscall.Mkfifo(path, 0o600); err != nil {
						t.Fatal(err)
					}
				}
			case "hardlink":
				if err := os.Link(path, filepath.Join(directory, "other")); err != nil {
					t.Fatal(err)
				}
			case "public", "executable":
				mode := os.FileMode(0o644)
				if name == "executable" {
					mode = 0o700
				}
				if err := os.Chmod(path, mode); err != nil { // #nosec G302 -- Deliberately rejected fixture permissions.
					t.Fatal(err)
				}
			case "public directory":
				if err := os.Chmod(directory, 0o755); err != nil { // #nosec G302 -- Deliberately rejected directory permissions.
					t.Fatal(err)
				}
			}
			snapshot, err := Load(t.Context(), directory)
			if name != "valid" && name != "stale reopen" {
				if err == nil {
					t.Fatal("unsafe export file accepted")
				}
				return
			}
			if err != nil || snapshot.Generation != "synthetic-original-generation" {
				t.Fatal("valid export rejected or changed")
			}
			if name == "stale reopen" {
				if err := os.Remove(path); err != nil {
					t.Fatal(err)
				}
				if _, err := Load(t.Context(), directory); err == nil {
					t.Fatal("missing export reused cached evidence")
				}
			}
		})
	}
}
