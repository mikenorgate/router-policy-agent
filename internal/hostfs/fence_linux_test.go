package hostfs

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func testFence(t *testing.T, path string) *Fence {
	t.Helper()
	fence, err := OpenFence(t.Context(), DirectoryOptions{Path: path, OwnerUID: testUID(t), Private: true})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.WithoutCancel(t.Context()), 3*time.Second)
		defer cancel()
		if err := fence.Close(ctx); err != nil && !errors.Is(err, os.ErrClosed) {
			t.Error(err)
		}
	})
	return fence
}

func TestFenceOpenRejectsUnsafeConfiguration(t *testing.T) {
	t.Parallel()
	for _, name := range []string{"not private", "wrong owner", "relative path", "symlink lock", "nonempty lock"} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			options := DirectoryOptions{Path: privateTempDir(t), OwnerUID: testUID(t), Private: true}
			switch name {
			case "not private":
				options.Private = false
			case "wrong owner":
				options.OwnerUID++
			case "relative path":
				options.Path = "relative"
			case "symlink lock":
				if err := os.Symlink("target", filepath.Join(options.Path, ".lock")); err != nil {
					t.Fatal(err)
				}
			case "nonempty lock":
				if err := os.WriteFile(filepath.Join(options.Path, ".lock"), []byte("x"), 0o600); err != nil {
					t.Fatal(err)
				}
			}
			if fence, err := OpenFence(t.Context(), options); err == nil || fence != nil {
				t.Fatal("unsafe configuration produced a shared fence")
			}
		})
	}
}

func TestFenceSeparateDescriptorsExcludeAndRelease(t *testing.T) {
	t.Parallel()
	path := privateTempDir(t)
	first, second := testFence(t, path), testFence(t, path)
	if err := first.With(t.Context(), func(ctx context.Context, _ *os.Root) error {
		deadline, exists := ctx.Deadline()
		if !exists || time.Until(deadline) > maximumFenceDuration {
			t.Fatal("critical section has no bounded inherited deadline")
		}
		short, cancel := context.WithTimeout(ctx, 30*time.Millisecond)
		defer cancel()
		called := false
		err := second.With(short, func(context.Context, *os.Root) error { called = true; return nil })
		if !errors.Is(err, context.DeadlineExceeded) || called {
			t.Fatal("a separate descriptor bypassed the held kernel flock")
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	marker := errors.New("synthetic callback failure")
	if err := second.With(t.Context(), func(context.Context, *os.Root) error { return marker }); !errors.Is(err, marker) {
		t.Fatal("callback failure was lost")
	}
	if err := first.With(t.Context(), func(context.Context, *os.Root) error { return nil }); err != nil {
		t.Fatal("failure left the cross-process lock held")
	}
	ctx, cancel := context.WithCancel(t.Context())
	if err := second.With(ctx, func(context.Context, *os.Root) error { cancel(); return nil }); !errors.Is(err, context.Canceled) {
		t.Fatal("callback cancellation was lost")
	}
	cancel()
	if err := first.With(t.Context(), func(context.Context, *os.Root) error { return nil }); err != nil {
		t.Fatal("cancellation left the cross-process lock held")
	}
}

func TestFenceLocalQueueAndCloseRespectCancellation(t *testing.T) {
	t.Parallel()
	fence := testFence(t, privateTempDir(t))
	entered, release := make(chan struct{}), make(chan struct{})
	result := make(chan error, 1)
	go func() {
		result <- fence.With(t.Context(), func(ctx context.Context, _ *os.Root) error {
			close(entered)
			select {
			case <-release:
				return nil
			case <-ctx.Done():
				return ctx.Err()
			}
		})
	}()
	select {
	case <-entered:
	case <-t.Context().Done():
		t.Fatal(t.Context().Err())
	}
	short, cancel := context.WithTimeout(t.Context(), 30*time.Millisecond)
	defer cancel()
	called := false
	err := fence.With(short, func(context.Context, *os.Root) error { called = true; return nil })
	if !errors.Is(err, context.DeadlineExceeded) || called {
		t.Error("a local queued operation bypassed cancellation")
	}
	closeCtx, closeCancel := context.WithTimeout(t.Context(), 30*time.Millisecond)
	defer closeCancel()
	if err := fence.Close(closeCtx); !errors.Is(err, context.DeadlineExceeded) {
		t.Error("close ignored its deadline or interrupted the holder")
	}
	close(release)
	if err := <-result; err != nil {
		t.Fatal(err)
	}
	if err := fence.With(t.Context(), func(context.Context, *os.Root) error { return nil }); err != nil {
		t.Fatal("canceled close disposed a live fence")
	}
}

func TestFenceRejectsIdentityReplacementBeforeAndAfterOperation(t *testing.T) {
	t.Parallel()
	for _, timing := range []string{"before operation", "during operation"} {
		for _, mutation := range []string{"replace lock", "remove lock", "lock permissions", "lock data", "replace directory"} {
			t.Run(timing+"/"+mutation, func(t *testing.T) {
				t.Parallel()
				parent := privateTempDir(t)
				path := filepath.Join(parent, "shared")
				if err := os.Mkdir(path, 0o700); err != nil {
					t.Fatal(err)
				}
				fence := testFence(t, path)
				mutate := func() error {
					switch mutation {
					case "replace lock":
						if err := fence.root.Remove(".lock"); err != nil {
							return err
						}
						return fence.root.WriteFile(".lock", []byte{}, 0o600)
					case "remove lock":
						return fence.root.Remove(".lock")
					case "lock permissions":
						return fence.root.Chmod(".lock", 0o644) // #nosec G302 -- Deliberately unsafe fixture mode.
					case "lock data":
						return fence.root.WriteFile(".lock", []byte("x"), 0o600)
					case "replace directory":
						if err := os.Rename(path, filepath.Join(parent, "original")); err != nil {
							return err
						}
						return os.Mkdir(path, 0o700)
					}
					return errors.New("unknown synthetic mutation")
				}
				if timing == "before operation" {
					if err := mutate(); err != nil {
						t.Fatal(err)
					}
				}
				called := false
				err := fence.With(t.Context(), func(context.Context, *os.Root) error {
					called = true
					return mutate()
				})
				if err == nil || called != (timing == "during operation") {
					t.Fatal("lock/directory drift was ignored or an unsafe operation started")
				}
				called = false
				if err := fence.With(t.Context(), func(context.Context, *os.Root) error { called = true; return nil }); err == nil || called {
					t.Fatal("invalidated fence was silently recovered")
				}
			})
		}
	}
}

func TestFenceRejectsMissingClosedAndCanceledInputs(t *testing.T) {
	t.Parallel()
	fence := testFence(t, privateTempDir(t))
	operation := func(context.Context, *os.Root) error { return nil }
	if err := (*Fence)(nil).With(t.Context(), operation); err == nil {
		t.Fatal("nil fence accepted")
	}
	if err := (&Fence{}).With(t.Context(), operation); err == nil {
		t.Fatal("zero fence accepted")
	}
	if err := fence.With(t.Context(), nil); err == nil {
		t.Fatal("nil operation accepted")
	}
	//nolint:staticcheck // Intentionally invalid context tests the rejection boundary.
	if err := fence.With(nil, operation); err == nil {
		t.Fatal("nil operation context accepted")
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if err := fence.With(ctx, operation); !errors.Is(err, context.Canceled) {
		t.Fatal("canceled operation accepted")
	}
	if err := fence.Close(ctx); !errors.Is(err, context.Canceled) {
		t.Fatal("canceled close accepted")
	}
	if err := fence.Close(t.Context()); err != nil {
		t.Fatal(err)
	}
	if err := fence.With(t.Context(), operation); !errors.Is(err, os.ErrClosed) {
		t.Fatal("closed fence reused")
	}
}
