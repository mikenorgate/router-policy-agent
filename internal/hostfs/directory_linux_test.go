package hostfs

import (
	"context"
	"errors"
	"math"
	"os"
	"path/filepath"
	"testing"
)

func TestOpenDirectory(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name   string
		mutate func(*testing.T, *DirectoryOptions)
	}{
		{name: "relative path", mutate: func(_ *testing.T, o *DirectoryOptions) { o.Path = "relative" }},
		{name: "filesystem root", mutate: func(_ *testing.T, o *DirectoryOptions) { o.Path = "/" }},
		{name: "unclean path", mutate: func(_ *testing.T, o *DirectoryOptions) { o.Path += "/." }},
		{name: "missing directory", mutate: func(_ *testing.T, o *DirectoryOptions) { o.Path += "/missing" }},
		{name: "wrong owner", mutate: func(_ *testing.T, o *DirectoryOptions) { o.OwnerUID++ }},
		{name: "readable private directory", mutate: func(t *testing.T, o *DirectoryOptions) {
			if err := os.Chmod(o.Path, 0o755); err != nil { // #nosec G302 -- Unsafe permissions are the rejection fixture.
				t.Fatal(err)
			}
		}},
		{name: "writable ancestor", mutate: func(t *testing.T, o *DirectoryOptions) {
			parent := filepath.Join(o.Path, "writable")
			child := filepath.Join(parent, "child")
			if err := os.MkdirAll(child, 0o700); err != nil {
				t.Fatal(err)
			}
			if err := os.Chmod(parent, 0o777); err != nil { // #nosec G302 -- An untrusted writable ancestor must reject.
				t.Fatal(err)
			}
			o.Path = child
		}},
		{name: "symlink ancestor", mutate: func(t *testing.T, o *DirectoryOptions) {
			link := filepath.Join(t.TempDir(), "link")
			if err := os.Symlink(o.Path, link); err != nil {
				t.Fatal(err)
			}
			o.Path = link
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			options := DirectoryOptions{Path: privateTempDir(t), OwnerUID: testUID(t), Private: true}
			test.mutate(t, &options)
			root, err := OpenDirectory(t.Context(), options)
			if root != nil {
				if closeErr := root.Close(); closeErr != nil {
					t.Fatal(closeErr)
				}
			}
			if err == nil {
				t.Fatal("unsafe directory accepted")
			}
		})
	}
	t.Run("private root", func(t *testing.T) {
		root := testRoot(t)
		if _, err := root.Stat("."); err != nil {
			t.Fatal(err)
		}
	})
	t.Run("canceled context", func(t *testing.T) {
		ctx, cancel := context.WithCancel(t.Context())
		cancel()
		if _, err := OpenDirectory(ctx, DirectoryOptions{Path: t.TempDir()}); !errors.Is(err, context.Canceled) {
			t.Fatalf("got %v", err)
		}
	})
	t.Run("nil context", func(t *testing.T) {
		//nolint:staticcheck // Deliberately test rejection of an invalid API input.
		if _, err := OpenDirectory(nil, DirectoryOptions{Path: t.TempDir()}); err == nil {
			t.Fatal("nil context accepted")
		}
	})
}

func testRoot(t *testing.T) *os.Root {
	t.Helper()
	root, err := OpenDirectory(t.Context(), DirectoryOptions{
		Path: privateTempDir(t), OwnerUID: testUID(t), Private: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := root.Close(); err != nil {
			t.Error(err)
		}
	})
	return root
}

func privateTempDir(t *testing.T) string {
	t.Helper()
	path := t.TempDir()
	if err := os.Chmod(path, 0o700); err != nil { // #nosec G302 -- Owner-only directories require traversal permission.
		t.Fatal(err)
	}
	return path
}

func testUID(t *testing.T) uint32 {
	t.Helper()
	uid := os.Geteuid()
	if uid < 0 || uint64(uid) > math.MaxUint32 {
		t.Fatal("test uid is outside the kernel credential range")
		return 0
	}
	return uint32(uid)
}
