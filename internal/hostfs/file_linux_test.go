package hostfs

import (
	"context"
	"os"
	"path/filepath"
	"syscall"
	"testing"
)

func TestOpenLock(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name   string
		mutate func(*testing.T, *os.Root)
	}{
		{name: "symlink", mutate: func(t *testing.T, root *os.Root) {
			if err := root.WriteFile("other", []byte{}, 0o600); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink("other", filepath.Join(root.Name(), ".lock")); err != nil {
				t.Fatal(err)
			}
		}},
		{name: "nonempty", mutate: func(t *testing.T, root *os.Root) {
			if err := root.WriteFile(".lock", []byte("x"), 0o600); err != nil {
				t.Fatal(err)
			}
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			root := testRoot(t)
			test.mutate(t, root)
			if file, err := OpenLock(t.Context(), root, testUID(t)); err == nil {
				if err := file.Close(); err != nil {
					t.Fatal(err)
				}
				t.Fatal("unsafe lock file accepted")
			}
		})
	}
	t.Run("empty lock", func(t *testing.T) {
		root := testRoot(t)
		file, err := OpenLock(t.Context(), root, testUID(t))
		if err != nil {
			t.Fatal(err)
		}
		if err := file.Close(); err != nil {
			t.Fatal(err)
		}
	})
	t.Run("canceled lock", func(t *testing.T) {
		ctx, cancel := context.WithCancel(t.Context())
		cancel()
		if _, err := OpenLock(ctx, testRoot(t), testUID(t)); err == nil {
			t.Fatal("canceled lock open accepted")
		}
	})
}

func TestOpenRegular(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name   string
		mutate func(*testing.T, *os.Root, *FileOptions)
	}{
		{name: "traversal", mutate: func(_ *testing.T, _ *os.Root, o *FileOptions) { o.Name = "../state.json" }},
		{name: "dot", mutate: func(_ *testing.T, _ *os.Root, o *FileOptions) { o.Name = "." }},
		{name: "absolute path", mutate: func(_ *testing.T, _ *os.Root, o *FileOptions) { o.Name = "/state.json" }},
		{name: "zero limit", mutate: func(_ *testing.T, _ *os.Root, o *FileOptions) { o.MaximumSize = 0 }},
		{name: "wrong owner", mutate: func(_ *testing.T, _ *os.Root, o *FileOptions) { o.OwnerUID++ }},
		{name: "readable file", mutate: func(t *testing.T, root *os.Root, _ *FileOptions) {
			if err := root.Chmod("state.json", 0o644); err != nil {
				t.Fatal(err)
			}
		}},
		{name: "executable file", mutate: func(t *testing.T, root *os.Root, _ *FileOptions) {
			if err := root.Chmod("state.json", 0o700); err != nil {
				t.Fatal(err)
			}
		}},
		{name: "oversized file", mutate: func(_ *testing.T, _ *os.Root, o *FileOptions) { o.MaximumSize = 1 }},
		{name: "symlink file", mutate: func(t *testing.T, root *os.Root, o *FileOptions) {
			if err := os.Symlink("state.json", filepath.Join(root.Name(), "link")); err != nil {
				t.Fatal(err)
			}
			o.Name = "link"
		}},
		{name: "hard linked file", mutate: func(t *testing.T, root *os.Root, _ *FileOptions) {
			if err := os.Link(filepath.Join(root.Name(), "state.json"), filepath.Join(root.Name(), "copy")); err != nil {
				t.Fatal(err)
			}
		}},
		{name: "fifo", mutate: func(t *testing.T, root *os.Root, o *FileOptions) {
			if err := syscall.Mkfifo(filepath.Join(root.Name(), "fifo"), 0o600); err != nil {
				t.Fatal(err)
			}
			o.Name = "fifo"
		}},
		{name: "directory", mutate: func(t *testing.T, root *os.Root, o *FileOptions) {
			if err := root.Mkdir("directory", 0o700); err != nil {
				t.Fatal(err)
			}
			o.Name = "directory"
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			root := testRoot(t)
			if err := root.WriteFile("state.json", []byte("{}"), 0o600); err != nil {
				t.Fatal(err)
			}
			options := FileOptions{Name: "state.json", OwnerUID: testUID(t), MaximumSize: 100}
			test.mutate(t, root, &options)
			file, err := OpenRegular(t.Context(), root, options)
			if file != nil {
				if closeErr := file.Close(); closeErr != nil {
					t.Fatal(closeErr)
				}
			}
			if err == nil {
				t.Fatal("unsafe file accepted")
			}
		})
	}
	t.Run("private file", func(t *testing.T) {
		root := testRoot(t)
		if err := root.WriteFile("state.json", []byte("{}"), 0o600); err != nil {
			t.Fatal(err)
		}
		file, err := OpenRegular(t.Context(), root, FileOptions{
			Name: "state.json", OwnerUID: testUID(t), MaximumSize: 100,
		})
		if err != nil {
			t.Fatal(err)
		}
		if err := file.Close(); err != nil {
			t.Fatal(err)
		}
	})
}
