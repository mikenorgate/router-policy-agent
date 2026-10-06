package hostfs

import (
	"errors"
	"os"
	"path/filepath"
	"syscall"
	"testing"
)

func TestOpenExecutable(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name   string
		data   []byte
		mode   os.FileMode
		accept bool
	}{
		{name: "ELF", data: []byte("\x7fELFsynthetic"), mode: 0o755, accept: true},
		{name: "script", data: []byte("#!/bin/sh\nexit 0\n"), mode: 0o755},
		{name: "short", data: []byte("ELF"), mode: 0o755},
		{name: "not executable", data: []byte("\x7fELFsynthetic"), mode: 0o600},
		{name: "group writable", data: []byte("\x7fELFsynthetic"), mode: 0o775},
		{name: "world writable", data: []byte("\x7fELFsynthetic"), mode: 0o757},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			path := t.TempDir()
			// Deliberately unsafe permission fixtures test that they are rejected.
			// #nosec G306 -- Synthetic test executable, including negative modes.
			if err := os.WriteFile(filepath.Join(path, "program"), test.data, test.mode); err != nil {
				t.Fatal(err)
			}
			// #nosec G302 -- Force the precise negative fixture despite umask.
			if err := os.Chmod(filepath.Join(path, "program"), test.mode); err != nil {
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
			file, err := OpenExecutable(
				t.Context(),
				root,
				"program",
				testUID(t),
			)
			if (err == nil) != test.accept {
				t.Fatalf("accepted=%v, expected=%v, error=%v", err == nil, test.accept, err)
			}
			if file != nil {
				if err := file.Close(); err != nil {
					t.Fatal(err)
				}
			}
		})
	}
}

func TestExecutableRejectsLinksAndBadArguments(t *testing.T) {
	t.Parallel()
	path := t.TempDir()
	// #nosec G306 -- Synthetic executable fixture requires execute permission.
	if err := os.WriteFile(filepath.Join(path, "program"), []byte("\x7fELFsynthetic"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("program", filepath.Join(path, "symlink")); err != nil {
		t.Fatal(err)
	}
	if err := os.Link(filepath.Join(path, "program"), filepath.Join(path, "hardlink")); err != nil {
		t.Fatal(err)
	}
	if err := syscall.Mkfifo(filepath.Join(path, "pipe"), 0o600); err != nil {
		t.Fatal(err)
	}
	root, err := os.OpenRoot(path)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := root.Close(); err != nil {
			t.Error(err)
		}
	}()
	for _, name := range []string{"symlink", "hardlink", "pipe", "../program", "missing", "."} {
		t.Run(name, func(t *testing.T) {
			file, err := OpenExecutable(
				t.Context(),
				root,
				name,
				testUID(t),
			)
			if file != nil {
				t.Fatal(errors.Join(errors.New("accepted unsafe executable"), file.Close()))
			}
			if err == nil {
				t.Fatal("accepted unsafe executable path")
			}
		})
	}
}
