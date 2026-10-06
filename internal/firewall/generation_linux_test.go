//go:build integration && linux

package firewall

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/mikenorgate/router-policy-agent/internal/hostfs"
)

func generationGateFixture(t *testing.T) (*generationGate, *os.Root, string) {
	t.Helper()
	if os.Geteuid() != 0 {
		t.Skip("root-owned generation fixtures run in the isolated root CI job")
	}
	path := t.TempDir()
	if err := os.Chmod(path, 0o700); err != nil { // #nosec G302 -- Owner-only fixture directory.
		t.Fatal(err)
	}
	root, err := hostfs.OpenDirectory(t.Context(), hostfs.DirectoryOptions{Path: path, OwnerUID: 0, Private: true})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := root.Close(); err != nil {
			t.Error(err)
		}
	})
	gate, err := openGenerationGate(t.Context(), path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.WithoutCancel(t.Context()), 3*time.Second)
		defer cancel()
		if err := gate.close(ctx); err != nil && !errors.Is(err, os.ErrClosed) {
			t.Error(err)
		}
	})
	writeGenerationFixture(t, root, writerGenerationFixture())
	return gate, root, path
}

func writeGenerationFixture(t *testing.T, root *os.Root, generation writerGeneration) {
	t.Helper()
	data, err := json.Marshal(generation)
	if err != nil {
		t.Fatal(err)
	}
	if err := root.WriteFile(writerGenerationFile, data, 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestGenerationGateReadyMetadataDoesNotRenewOrBypassQueue(t *testing.T) {
	t.Parallel()
	gate, root, path := generationGateFixture(t)
	expected := writerGenerationFixture()
	called := 0
	if err := gate.with(t.Context(), expected, func(ctx context.Context) error {
		called++
		if deadline, exists := ctx.Deadline(); !exists || time.Until(deadline) > 2*time.Second {
			return errors.New("synthetic unbounded callback")
		}
		return nil
	}); err != nil || called != 1 {
		t.Fatalf("matching coordination metadata rejected a bounded callback: %v", err)
	}
	writer, err := hostfs.OpenFence(t.Context(), hostfs.DirectoryOptions{Path: path, OwnerUID: 0, Private: true})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.WithoutCancel(t.Context()), 3*time.Second)
		defer cancel()
		if err := writer.Close(ctx); err != nil {
			t.Error(err)
		}
	})
	if err := writer.With(t.Context(), func(ctx context.Context, _ *os.Root) error {
		short, cancel := context.WithTimeout(ctx, 30*time.Millisecond)
		defer cancel()
		err := gate.with(short, expected, func(context.Context) error { called++; return nil })
		if !errors.Is(err, context.DeadlineExceeded) {
			return errors.New("synthetic generation callback bypassed the writer fence")
		}
		advanced := expected
		advanced.Sequence++
		writeGenerationFixture(t, root, advanced)
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if err := gate.with(t.Context(), expected, func(context.Context) error { called++; return nil }); err == nil || called != 1 {
		t.Fatal("an old generation was accepted after the other writer's update")
	}
}

func TestGenerationGateRejectsUnreadyUnsafeAndMissingMetadata(t *testing.T) {
	t.Parallel()
	for _, name := range []string{
		"missing", "closed", "sequence drift", "floor drift", "mapping drift", "malformed", "oversized", "readable", "symlink",
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			gate, root, _ := generationGateFixture(t)
			value := writerGenerationFixture()
			switch name {
			case "missing":
				if err := root.Remove(writerGenerationFile); err != nil {
					t.Fatal(err)
				}
			case "closed":
				value.Ready = false
				writeGenerationFixture(t, root, value)
			case "sequence drift":
				value.Sequence++
				writeGenerationFixture(t, root, value)
			case "floor drift":
				value.FloorHash = value.MappingHash
				writeGenerationFixture(t, root, value)
			case "mapping drift":
				value.MappingHash = value.FloorHash
				writeGenerationFixture(t, root, value)
			case "malformed":
				if err := root.WriteFile(writerGenerationFile, []byte(`{"ready":true}`), 0o600); err != nil {
					t.Fatal(err)
				}
			case "oversized":
				if err := root.WriteFile(writerGenerationFile, []byte(strings.Repeat("x", maximumGenerationSize+1)), 0o600); err != nil {
					t.Fatal(err)
				}
			case "readable":
				if err := root.Chmod(writerGenerationFile, 0o644); err != nil { // #nosec G302 -- Unsafe fixture must reject.
					t.Fatal(err)
				}
			case "symlink":
				if err := root.Rename(writerGenerationFile, "original.json"); err != nil {
					t.Fatal(err)
				}
				if err := root.Symlink("original.json", writerGenerationFile); err != nil {
					t.Fatal(err)
				}
			}
			called := false
			err := gate.with(t.Context(), writerGenerationFixture(), func(context.Context) error {
				called = true
				return nil
			})
			if err == nil || called {
				t.Fatal("unsafe or mismatched metadata reached the critical callback")
			}
		})
	}
}

func TestGenerationGateReportsPostCallbackDriftAndReleasesFence(t *testing.T) {
	t.Parallel()
	gate, root, _ := generationGateFixture(t)
	expected := writerGenerationFixture()
	marker := errors.New("synthetic callback failure")
	if err := gate.with(t.Context(), expected, func(context.Context) error { return marker }); !errors.Is(err, marker) {
		t.Fatal("callback failure was discarded")
	}
	// This deliberately violates the cooperating-writer protocol to exercise
	// detection, not rollback. A production updater must revoke before its
	// actual map/floor change and publish readiness only after independent audit.
	called := false
	if err := gate.with(t.Context(), expected, func(context.Context) error {
		called = true
		closed := expected
		closed.Ready = false
		writeGenerationFixture(t, root, closed)
		return nil
	}); err == nil || !called {
		t.Fatal("post-callback closure was not reported")
	}
	called = false
	if err := gate.with(t.Context(), expected, func(context.Context) error { called = true; return nil }); err == nil || called {
		t.Fatal("closed generation permitted another callback")
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if err := gate.with(ctx, expected, func(context.Context) error { called = true; return nil }); !errors.Is(err, context.Canceled) || called {
		t.Fatal("generation gate lost cancellation")
	}
}

func TestGenerationGateRejectsMissingDependencies(t *testing.T) {
	t.Parallel()
	expected := writerGenerationFixture()
	operation := func(context.Context) error { return nil }
	if err := (*generationGate)(nil).with(t.Context(), expected, operation); err == nil {
		t.Fatal("nil generation gate accepted")
	}
	if err := (&generationGate{}).close(t.Context()); err == nil {
		t.Fatal("zero generation gate closed successfully")
	}
	gate, _, _ := generationGateFixture(t)
	if err := gate.with(t.Context(), expected, nil); err == nil {
		t.Fatal("nil callback accepted")
	}
	closed := expected
	closed.Ready = false
	if err := gate.with(t.Context(), closed, operation); err == nil {
		t.Fatal("closed expected generation accepted")
	}
	if err := gate.with(t.Context(), writerGeneration{}, operation); err == nil {
		t.Fatal("zero expected generation accepted")
	}
	//nolint:staticcheck // Intentionally invalid context tests the rejection boundary.
	if err := gate.with(nil, expected, operation); err == nil {
		t.Fatal("nil callback context accepted")
	}
	if err := gate.close(t.Context()); err != nil {
		t.Fatal(err)
	}
	if err := gate.with(t.Context(), expected, operation); !errors.Is(err, os.ErrClosed) {
		t.Fatal("closed generation gate accepted another callback")
	}
}

func TestGenerationGateRequiresPrivilegedOwner(t *testing.T) {
	t.Parallel()
	if os.Geteuid() == 0 {
		t.Skip("non-root constructor rejection runs in ordinary CI jobs")
	}
	if gate, err := openGenerationGate(t.Context(), t.TempDir()); err == nil || gate != nil {
		t.Fatal("unprivileged identity opened a writer generation gate")
	}
}
