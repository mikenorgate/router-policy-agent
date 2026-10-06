//go:build integration && linux

package firewall

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

func privateRouterProfileFixture(t *testing.T) (*os.Root, profileOptions, []byte) {
	t.Helper()
	if os.Geteuid() != 0 {
		t.Skip("root-owned profile fixtures run in the isolated root CI job")
	}
	path := t.TempDir()
	if err := os.Chmod(path, 0o700); err != nil { // #nosec G302 -- Owner-only directory needs search permission.
		t.Fatal(err)
	}
	root, err := os.OpenRoot(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := root.Close(); err != nil {
			t.Error(err)
		}
	})
	data := routerProfileFixture(t)
	if err := root.WriteFile(routerProfileFile, data, 0o600); err != nil {
		t.Fatal(err)
	}
	return root, profileOptions{Directory: path, SHA256: routerProfileDigest(data)}, data
}

func TestProfileLoaderReadsOnlyPinnedPrivateBytes(t *testing.T) {
	t.Parallel()
	root, options, data := privateRouterProfileFixture(t)
	for _, mode := range []os.FileMode{0o600, 0o400} {
		if err := root.Chmod(routerProfileFile, mode); err != nil {
			t.Fatal(err)
		}
		profile, err := loadRouterProfile(t.Context(), options)
		if err != nil || profile.digest != options.SHA256 {
			t.Fatalf("safe root-owned profile did not load: %v", err)
		}
		after, err := root.ReadFile(routerProfileFile)
		if err != nil || !bytes.Equal(data, after) {
			t.Fatal("read-only loading changed the stored profile")
		}
	}
}

func TestProfileLoaderRejectsUnsafeFilesWithoutPartialResult(t *testing.T) {
	t.Parallel()
	for _, name := range []string{
		"missing", "empty", "oversized", "readable", "executable", "setuid", "write-only", "no permissions",
		"symlink", "hardlink", "fifo",
		"directory", "wrong owner", "changed bytes", "malformed", "wrong pin", "missing pin", "directory readable",
		"directory symlink", "relative directory", "unclean directory", "root directory",
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			root, options, data := privateRouterProfileFixture(t)
			switch name {
			case "missing":
				if err := root.Remove(routerProfileFile); err != nil {
					t.Fatal(err)
				}
			case "empty", "oversized", "changed bytes", "malformed":
				switch name {
				case "empty":
					data = []byte{}
				case "oversized":
					data = bytes.Repeat([]byte("x"), maximumRouterProfile+1)
				case "changed bytes":
					data = append(data, ' ')
				case "malformed":
					data = []byte(`{"schema_version":1}`)
					options.SHA256 = routerProfileDigest(data)
				}
				if err := root.WriteFile(routerProfileFile, data, 0o600); err != nil {
					t.Fatal(err)
				}
			case "readable", "executable", "setuid", "write-only", "no permissions":
				mode := os.FileMode(0o644)
				if name == "executable" {
					mode = 0o700
				}
				if name == "setuid" {
					mode = os.ModeSetuid | 0o600
				}
				if name == "write-only" {
					mode = 0o200
				}
				if name == "no permissions" {
					mode = 0
				}
				if err := root.Chmod(routerProfileFile, mode); err != nil { // #nosec G302 -- Deliberately unsafe fixture.
					t.Fatal(err)
				}
			case "symlink":
				if err := root.Rename(routerProfileFile, "original.json"); err != nil {
					t.Fatal(err)
				}
				if err := root.Symlink("original.json", routerProfileFile); err != nil {
					t.Fatal(err)
				}
			case "hardlink":
				if err := os.Link(filepath.Join(options.Directory, routerProfileFile),
					filepath.Join(options.Directory, "linked.json")); err != nil {
					t.Fatal(err)
				}
			case "fifo", "directory":
				if err := root.Remove(routerProfileFile); err != nil {
					t.Fatal(err)
				}
				if name == "fifo" {
					if err := syscall.Mkfifo(filepath.Join(options.Directory, routerProfileFile), 0o600); err != nil {
						t.Fatal(err)
					}
				}
				if name == "directory" {
					if err := root.Mkdir(routerProfileFile, 0o700); err != nil {
						t.Fatal(err)
					}
				}
			case "wrong owner":
				if err := root.Chown(routerProfileFile, 65534, 65534); err != nil {
					if errors.Is(err, syscall.EPERM) {
						t.Skip("ownership substitution needs CAP_CHOWN in the isolated root CI job")
					}
					t.Fatal(err)
				}
			case "wrong pin":
				options.SHA256 = strings.Repeat("0", 64)
			case "missing pin":
				options.SHA256 = ""
			case "directory readable":
				if err := os.Chmod(options.Directory, 0o755); err != nil { // #nosec G302 -- Deliberately unsafe fixture.
					t.Fatal(err)
				}
			case "directory symlink":
				link := filepath.Join(t.TempDir(), "link")
				if err := os.Symlink(options.Directory, link); err != nil {
					t.Fatal(err)
				}
				options.Directory = link
			case "relative directory":
				options.Directory = "relative-profile"
			case "unclean directory":
				options.Directory += "/."
			case "root directory":
				options.Directory = "/"
			}
			ctx, cancel := context.WithTimeout(t.Context(), time.Second)
			defer cancel()
			profile, err := loadRouterProfile(ctx, options)
			if err == nil || profile != nil {
				t.Fatal("unsafe, changed or malformed file produced trusted components")
			}
			if strings.Contains(err.Error(), options.Directory) && options.Directory != "" {
				t.Fatal("printable profile error exposed its private path")
			}
		})
	}
}

func TestProfileLoaderCancellationAndNonRootBoundary(t *testing.T) {
	t.Parallel()
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if profile, err := loadRouterProfile(ctx, profileOptions{}); !errors.Is(err, context.Canceled) || profile != nil {
		t.Fatal("canceled loading reached trusted configuration or lost cancellation")
	}
	var missingContext context.Context // Deliberately exercise the fail-closed nil dependency.
	if profile, err := loadRouterProfile(missingContext, profileOptions{}); err == nil || profile != nil {
		t.Fatal("nil context accepted")
	}
	if os.Geteuid() == 0 {
		return // Non-root rejection runs separately in hosted and non-root jobs.
	}
	data := routerProfileFixture(t)
	if profile, err := loadRouterProfile(t.Context(), profileOptions{
		Directory: t.TempDir(), SHA256: routerProfileDigest(data),
	}); err == nil || profile != nil || !strings.Contains(err.Error(), "requires root") {
		t.Fatal("unprivileged loading was not rejected before reading")
	}
}

func TestProfileInspectionRejectsIncompleteDependencies(t *testing.T) {
	t.Parallel()
	data := routerProfileFixture(t)
	profile, err := decodePinnedProfile(t.Context(), data, routerProfileDigest(data))
	if err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		name    string
		profile *routerProfile
		process *process
	}{
		{name: "nil profile", process: &process{}},
		{name: "zero profile", profile: &routerProfile{}, process: &process{}},
		{name: "nil executor", profile: profile},
		{name: "closed executor", profile: profile, process: &process{}},
		{name: "missing layout", profile: &routerProfile{
			digest: profile.digest, renderer: profile.renderer, ruleset: profile.ruleset,
		}, process: &process{}},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			if observation, err := test.profile.inspect(t.Context(), test.process); err == nil || observation != nil {
				t.Fatal("incomplete profile/executor returned successful or partial inspection")
			}
		})
	}
}

func TestProfileLoaderClosesDescriptorsOnSuccessAndFailure(t *testing.T) {
	t.Parallel()
	root, options, data := privateRouterProfileFixture(t)
	countDescriptors := func() int {
		entries, err := os.ReadDir("/proc/self/fd")
		if err != nil {
			t.Fatal(err)
		}
		count := 0
		for _, entry := range entries {
			target, err := os.Readlink(filepath.Join("/proc/self/fd", entry.Name()))
			if errors.Is(err, os.ErrNotExist) {
				continue // Another test may close an unrelated descriptor between calls.
			}
			if err != nil {
				t.Fatal(err)
			}
			if target == options.Directory || strings.HasPrefix(target, options.Directory+"/") {
				count++
			}
		}
		return count
	}
	before := countDescriptors()
	for range 4 {
		if err := root.WriteFile(routerProfileFile, data, 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := loadRouterProfile(t.Context(), options); err != nil {
			t.Fatal(err)
		}
		malformed := []byte(`{"schema_version":1}`)
		if err := root.WriteFile(routerProfileFile, malformed, 0o600); err != nil {
			t.Fatal(err)
		}
		for _, pin := range []string{options.SHA256, routerProfileDigest(malformed)} {
			if profile, err := loadRouterProfile(t.Context(), profileOptions{
				Directory: options.Directory, SHA256: pin,
			}); err == nil || profile != nil {
				t.Fatal("a failed integrity/schema check returned a profile")
			}
		}
		if after := countDescriptors(); after != before {
			t.Fatal("profile loading retained directory or file descriptors")
		}
	}
}
