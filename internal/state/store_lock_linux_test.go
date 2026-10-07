//go:build integration && linux

package state

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"syscall"
	"testing"
)

func TestStoreCloseReleasesLockWithInheritedDescriptor(t *testing.T) {
	t.Parallel()
	for _, name := range []string{"sole descriptor", "inherited descriptor"} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			options := storeOptions(t)
			store := openStore(t, options)
			if err := store.Initialize(t.Context()); err != nil {
				t.Fatal(err)
			}
			if err := store.Save(t.Context(), classified(t)); err != nil {
				t.Fatal(err)
			}
			before, err := store.Load(t.Context())
			if err != nil {
				t.Fatal(err)
			}
			beforeBytes, err := json.Marshal(before)
			if err != nil {
				t.Fatal(err)
			}
			var alias *os.File
			if name == "inherited descriptor" {
				alias = duplicateStoreLock(t, store)
			}
			if other, err := Open(t.Context(), options); err == nil {
				if err := other.Close(); err != nil {
					t.Error(err)
				}
				t.Fatal("live owner lost exclusive state locking")
			}
			if err := store.Close(); err != nil {
				t.Fatal(err)
			}
			// The duplicate remains open until cleanup, modeling a child between
			// fork and exec. Closing the owner must still release its lock now.
			reopened := openStore(t, options)
			if alias != nil {
				fd, err := descriptor(alias)
				if err != nil {
					t.Fatal(err)
				}
				if err := syscall.Flock(fd, syscall.LOCK_UN); err != nil {
					t.Fatal(err)
				}
			}
			if third, err := Open(t.Context(), options); err == nil {
				if err := third.Close(); err != nil {
					t.Error(err)
				}
				t.Fatal("old descriptor weakened the new owner's exclusive lock")
			}
			after, err := reopened.Load(t.Context())
			if err != nil {
				t.Fatal(err)
			}
			afterBytes, err := json.Marshal(after)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(beforeBytes, afterBytes) {
				t.Fatal("lock handoff changed durable deny-only history")
			}
		})
	}
}

func TestStoreCloseFinishesCleanupOfAlreadyClosedResources(t *testing.T) {
	t.Parallel()
	for _, name := range []string{"closed lock", "closed directory"} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			options := storeOptions(t)
			store := openStore(t, options)
			root, lock := store.root, store.lock
			var closeErr error
			switch name {
			case "closed lock":
				closeErr = lock.Close()
			case "closed directory":
				closeErr = root.Close()
			}
			if closeErr != nil {
				t.Fatal(closeErr)
			}
			err := store.Close()
			hasMissingError := name == "closed lock" && !errors.Is(err, os.ErrClosed)
			hasUnexpectedError := name == "closed directory" && err != nil
			if hasMissingError || hasUnexpectedError {
				t.Fatal("cleanup lost a lock error or rejected idempotent directory closure")
			}
			if store.root != nil || store.lock != nil {
				t.Fatal("failed cleanup retained store resources")
			}
			if _, err := root.Stat("."); !errors.Is(err, os.ErrClosed) {
				t.Fatal("cleanup failed to close the private directory")
			}
			if _, err := lock.Stat(); !errors.Is(err, os.ErrClosed) {
				t.Fatal("cleanup failed to close its lock descriptor")
			}
			openStore(t, options)
		})
	}
}

func duplicateStoreLock(t *testing.T, store *Store) *os.File {
	t.Helper()
	raw, err := store.lock.SyscallConn()
	if err != nil {
		t.Fatal(err)
	}
	var duplicate uintptr
	var callErr syscall.Errno
	if err := raw.Control(func(fd uintptr) {
		// Atomic CLOEXEC duplication avoids leaking the fixture descriptor
		// through another test's concurrent exec while preserving flock identity.
		duplicate, _, callErr = syscall.Syscall(
			syscall.SYS_FCNTL,
			fd,
			syscall.F_DUPFD_CLOEXEC,
			0,
		)
	}); err != nil {
		t.Fatal(err)
	}
	if callErr != 0 {
		t.Fatal(callErr)
	}
	alias := os.NewFile(duplicate, "synthetic-inherited-state-lock")
	if alias == nil {
		t.Fatal("valid duplicate descriptor did not produce a file")
	}
	t.Cleanup(func() {
		if err := alias.Close(); err != nil {
			t.Error(err)
		}
	})
	return alias
}
