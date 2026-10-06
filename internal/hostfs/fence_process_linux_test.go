//go:build integration && linux

package hostfs

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
	"testing"
	"time"
)

// This fixture is available only in the integration test binary. Its environment
// contains only a test-owned temporary directory, never deployment credentials.
const fenceProcessDirectory = "ROUTER_POLICY_TEST_FENCE_DIRECTORY"

func TestFenceHoldingProcess(t *testing.T) {
	path := os.Getenv(fenceProcessDirectory)
	if path == "" {
		t.Skip("subprocess fixture requires its parent's temporary directory")
	}
	fence := testFence(t, path)
	err := fence.With(t.Context(), func(ctx context.Context, _ *os.Root) error {
		if _, err := fmt.Fprintln(os.Stdout, "fence-held"); err != nil {
			return err
		}
		<-ctx.Done()
		return ctx.Err()
	})
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatal("holder did not retain its fence until its bounded deadline")
	}
}

func TestFenceProcessExclusionAndCrashRelease(t *testing.T) {
	t.Parallel()
	path := privateTempDir(t)
	fence := testFence(t, path)
	original, err := os.Stat(filepath.Join(path, ".lock"))
	if err != nil {
		t.Fatal(err)
	}
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	// #nosec G204 -- Executes only this running integration binary with fixed test arguments.
	child := exec.CommandContext(
		ctx,
		executable,
		"-test.run=^TestFenceHoldingProcess$",
		"-test.count=1",
	)
	child.Env = []string{"PATH=/usr/bin:/bin", "LC_ALL=C", fenceProcessDirectory + "=" + path}
	child.WaitDelay = 250 * time.Millisecond
	output, err := child.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := child.Start(); err != nil {
		if closeErr := output.Close(); closeErr != nil {
			t.Error(closeErr)
		}
		t.Fatal(err)
	}
	waited := false
	t.Cleanup(func() {
		cancel()
		if !waited {
			if err := child.Wait(); err == nil {
				t.Error("holder exited without the expected forced shutdown")
			}
		}
	})
	reader := bufio.NewScanner(output)
	reader.Buffer(make([]byte, 32), 32)
	if !reader.Scan() || reader.Text() != "fence-held" {
		t.Fatal("holder did not confirm a checked critical section")
	}
	short, shortCancel := context.WithTimeout(ctx, 30*time.Millisecond)
	defer shortCancel()
	called := false
	err = fence.With(short, func(context.Context, *os.Root) error { called = true; return nil })
	if !errors.Is(err, context.DeadlineExceeded) || called {
		t.Fatal("a second process bypassed the holder's lock")
	}
	// Kill only the exact child created above, not any host or deployment process.
	if err := child.Process.Kill(); err != nil {
		t.Fatal(err)
	}
	err = child.Wait()
	waited = true
	var exitErr *exec.ExitError
	if !errors.As(err, &exitErr) {
		t.Fatal("holder did not exit through the forced crash")
	}
	status, ok := exitErr.Sys().(syscall.WaitStatus)
	if !ok || !status.Signaled() || status.Signal() != syscall.SIGKILL {
		t.Fatal("holder exited without the expected crash signal")
	}
	if err := fence.With(ctx, func(context.Context, *os.Root) error { called = true; return nil }); err != nil {
		t.Fatal("crash left the shared lock held")
	}
	current, err := os.Stat(filepath.Join(path, ".lock"))
	if err != nil || !called || !os.SameFile(original, current) {
		t.Fatal("crash recovery replaced the lock or failed to enter the critical section")
	}
}
