package state

import (
	"context"
	"errors"
	"math"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

func openStore(t *testing.T, options Options) *Store {
	t.Helper()
	store, err := Open(t.Context(), options)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := store.Close(); err != nil && !errors.Is(err, os.ErrClosed) {
			t.Error(err)
		}
	})
	return store
}

func storeOptions(t *testing.T) Options {
	t.Helper()
	directory := t.TempDir()
	if err := os.Chmod(directory, 0o700); err != nil { // #nosec G302 -- Owner-only directories require traversal permission.
		t.Fatal(err)
	}
	uid := os.Geteuid()
	if uid < 0 || uint64(uid) > math.MaxUint32 {
		t.Fatal("test uid is outside the kernel credential range")
		return Options{}
	}
	return Options{Directory: directory, OwnerUID: uint32(uid)}
}

func TestStoreRestartAndExclusiveLock(t *testing.T) {
	t.Parallel()
	options := storeOptions(t)
	store := openStore(t, options)
	if _, err := store.Load(t.Context()); !errors.Is(err, ErrUninitialized) {
		t.Fatalf("missing state: %v", err)
	}
	if err := store.Save(t.Context(), advanced(t)); !errors.Is(err, ErrUninitialized) {
		t.Fatalf("save must not implicitly initialize: %v", err)
	}
	if err := store.Initialize(t.Context()); err != nil {
		t.Fatal(err)
	}
	if err := store.Initialize(t.Context()); err == nil {
		t.Fatal("state was reinitialized")
	}
	if err := store.Save(t.Context(), advanced(t)); err != nil {
		t.Fatal(err)
	}
	if second, err := Open(t.Context(), options); err == nil {
		if err := second.Close(); err != nil {
			t.Fatal(err)
		}
		t.Fatal("second process lock accepted")
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	restarted := openStore(t, options)
	document, err := restarted.Load(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if len(document.CohortMACs) != 1 || !document.Ledger.FirstSeen["group/rule"].Equal(observed) {
		t.Fatal("restart erased guarded identity or expiry")
	}
	older := snapshot()
	older.ObservedAt = observed.Add(-1)
	if _, err := CheckDirectory(document, older); err == nil {
		t.Fatal("restart admitted older directory snapshot")
	}
	data, err := os.ReadFile(filepath.Join(options.Directory, filename))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(data), "grants") || strings.Contains(string(data), "password") {
		t.Fatal("unnecessary sensitive state persisted")
	}
	entries, err := os.ReadDir(options.Directory)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 2 {
		t.Fatal("temporary files left after atomic save")
	}
}

func TestStoreFailureDoesNotReset(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name   string
		mutate func(*testing.T, Options)
	}{
		{name: "corrupt state", mutate: func(t *testing.T, options Options) {
			if err := os.WriteFile(filepath.Join(options.Directory, filename), []byte("{"), 0o600); err != nil {
				t.Fatal(err)
			}
		}},
		{name: "state symlink", mutate: func(t *testing.T, options Options) {
			if err := os.Symlink("missing", filepath.Join(options.Directory, filename)); err != nil {
				t.Fatal(err)
			}
		}},
		{name: "readable state", mutate: func(t *testing.T, options Options) {
			// #nosec G306 -- A readable state file is deliberately an invalid fixture.
			if err := os.WriteFile(filepath.Join(options.Directory, filename), []byte("{}"), 0o644); err != nil {
				t.Fatal(err)
			}
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			options := storeOptions(t)
			store := openStore(t, options)
			test.mutate(t, options)
			if _, err := store.Load(t.Context()); err == nil {
				t.Fatal("unsafe state loaded")
			}
			if err := store.Initialize(t.Context()); err == nil {
				t.Fatal("unsafe state silently reset")
			}
		})
	}
}

func TestStoreSerializedUpdatesAndCancellation(t *testing.T) {
	t.Parallel()
	store := openStore(t, storeOptions(t))
	if err := store.Initialize(t.Context()); err != nil {
		t.Fatal(err)
	}
	document := advanced(t)
	errorsOut := make(chan error, 8)
	var workers sync.WaitGroup
	for range 8 {
		workers.Go(func() { errorsOut <- store.Save(t.Context(), document) })
	}
	workers.Wait()
	for range 8 {
		if err := <-errorsOut; err != nil {
			t.Fatal(err)
		}
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if err := store.Save(ctx, document); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled save: %v", err)
	}
	unsafe, err := Clone(document)
	if err != nil {
		t.Fatal(err)
	}
	unsafe.CohortMACs = []string{}
	if err := store.Save(t.Context(), unsafe); err == nil {
		t.Fatal("store erased cohort")
	}
	loaded, err := store.Load(t.Context())
	if err != nil || len(loaded.CohortMACs) != 1 {
		t.Fatalf("failed save changed state: %v", err)
	}
	//nolint:staticcheck // Deliberately test rejection of an invalid API input.
	if _, err := store.Load(nil); err == nil {
		t.Fatal("nil context accepted")
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Load(t.Context()); !errors.Is(err, os.ErrClosed) {
		t.Fatalf("closed store: %v", err)
	}
}
