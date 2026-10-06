//go:build integration && linux

package ipc

import (
	"context"
	"errors"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/mikenorgate/router-policy-agent/internal/policy"
)

func startStatusServer(
	t *testing.T,
	listener *net.UnixListener,
	uid uint32,
	report ReportFunc,
) {
	t.Helper()
	server, err := NewStatusServer(ServerOptions{ReaderUID: uid, Timeout: time.Second}, report)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	var worker sync.WaitGroup
	result := make(chan error, 1)
	worker.Go(func() { result <- server.Serve(ctx, listener) })
	t.Cleanup(func() {
		cancel()
		worker.Wait()
		if err := <-result; !errors.Is(err, context.Canceled) {
			t.Errorf("status server shutdown: %v", err)
		}
	})
}

func TestReadStatusHasNoWriteOperation(t *testing.T) {
	t.Parallel()
	for _, test := range []struct {
		name    string
		report  ReportFunc
		wantErr bool
	}{
		{name: "valid report", report: func(context.Context) (Report, error) { return fixtureReport(), nil }},
		{name: "failure redacted", wantErr: true, report: func(context.Context) (Report, error) {
			return Report{}, errors.New("synthetic sensitive backend detail")
		}},
		{name: "invalid callback result", wantErr: true, report: func(context.Context) (Report, error) {
			return Report{}, nil
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			listener, options := testListener(t)
			var calls atomic.Int32
			startStatusServer(
				t,
				listener,
				options.ServerUID,
				func(ctx context.Context) (Report, error) {
					calls.Add(1)
					return test.report(ctx)
				},
			)
			if _, err := Submit(t.Context(), options, fixtureSnapshot()); err == nil || calls.Load() != 0 {
				t.Fatal("status-only socket accepted a directory write or invoked its callback")
			}
			report, err := ReadStatus(t.Context(), options)
			if (err != nil) != test.wantErr || calls.Load() != 1 {
				t.Fatal("status callback outcome mismatch")
			}
			if test.wantErr {
				if !errors.Is(err, ErrRejected) || strings.Contains(err.Error(), "sensitive") {
					t.Fatal("private status error escaped")
				}
				return
			}
			if ValidateReport(report) != nil {
				t.Fatal("invalid report returned")
			}
		})
	}
}

func TestReadStatusCannotUseWriterSocket(t *testing.T) {
	t.Parallel()
	listener, options := testListener(t)
	var calls atomic.Int32
	startServer(t, listener, options.ServerUID, func(context.Context, policy.DirectorySnapshot) (Receipt, error) {
		calls.Add(1)
		return fixtureReceipt(), nil
	})
	if _, err := ReadStatus(t.Context(), options); err == nil || calls.Load() != 0 {
		t.Fatal("status operation invoked the directory processor")
	}
}

func TestStatusTransportRejectsInvalidDependencies(t *testing.T) {
	t.Parallel()
	for _, timeout := range []time.Duration{0, -time.Second, 11 * time.Second} {
		if _, err := NewStatusServer(ServerOptions{Timeout: timeout}, func(context.Context) (Report, error) {
			return fixtureReport(), nil
		}); err == nil {
			t.Fatal("invalid server deadline accepted")
		}
		if _, err := ReadStatus(t.Context(), ClientOptions{Timeout: timeout}); err == nil {
			t.Fatal("invalid client deadline accepted")
		}
	}
	if _, err := NewStatusServer(ServerOptions{Timeout: time.Second}, nil); err == nil {
		t.Fatal("missing read callback accepted")
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if _, err := ReadStatus(ctx, ClientOptions{Socket: "/synthetic/status.sock", Timeout: time.Second}); err == nil {
		t.Fatal("canceled status lookup succeeded")
	}
	var missingContext context.Context
	if _, err := ReadStatus(missingContext, ClientOptions{Timeout: time.Second}); err == nil {
		t.Fatal("missing status context accepted")
	}
}

func TestRealUnprivilegedStatusReader(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("cross-uid qualification requires an isolated root test runner")
	}
	directory, err := os.MkdirTemp("", "rpa-status-")
	if err != nil {
		t.Fatal(err)
	}
	// #nosec G302 -- Isolated synthetic subprocesses need directory traversal.
	if err := os.Chmod(directory, 0o755); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := os.RemoveAll(directory); err != nil {
			t.Error(err)
		}
	})
	path := filepath.Join(directory, "status.sock")
	listener, err := net.ListenUnix("unix", &net.UnixAddr{Name: path, Net: "unix"})
	if err != nil {
		t.Fatal(err)
	}
	listener.SetUnlinkOnClose(false)
	t.Cleanup(func() {
		if err := closeExpected(listener); err != nil {
			t.Error(err)
		}
	})
	if err := os.Chown(path, 0, 65533); err != nil {
		t.Fatal(err)
	}
	// #nosec G302 -- Only the synthetic operator group can connect.
	if err := os.Chmod(path, 0o660); err != nil {
		t.Fatal(err)
	}
	var calls atomic.Int32
	startStatusServer(t, listener, 65533, func(context.Context) (Report, error) {
		calls.Add(1)
		return fixtureReport(), nil
	})
	executable := copyTestExecutable(t, directory)
	for _, test := range []struct {
		name string
		uid  uint32
	}{
		{name: "operator", uid: 65533},
		{name: "writer with same socket group", uid: 65534},
	} {
		t.Run(test.name, func(t *testing.T) {
			// #nosec G204 -- The copied current test executable and entry point are fixed.
			command := exec.CommandContext(t.Context(), executable, "-test.run=^TestStatusReaderProcess$")
			command.Env = []string{"RPA_STATUS_TEST_CHILD=1", "RPA_STATUS_TEST_SOCKET=" + path}
			command.SysProcAttr = &syscall.SysProcAttr{Credential: &syscall.Credential{Uid: test.uid, Gid: 65533}}
			if output, err := command.CombinedOutput(); err != nil {
				t.Fatalf("status reader: %v: %s", err, output)
			}
		})
	}
	if _, err := ReadStatus(t.Context(), ClientOptions{Socket: path, ServerUID: 0, Timeout: time.Second}); err == nil {
		t.Fatal("root impersonated the operator uid")
	}
	if calls.Load() != 1 {
		t.Fatal("unauthorized identities or directory submissions reached the status callback")
	}
}

func TestStatusReaderProcess(t *testing.T) {
	if os.Getenv("RPA_STATUS_TEST_CHILD") != "1" {
		t.Skip("subprocess entry point")
	}
	uid := os.Geteuid()
	if uid != 65533 && uid != 65534 {
		t.Fatal("status subprocess did not drop privilege")
	}
	options := ClientOptions{Socket: os.Getenv("RPA_STATUS_TEST_SOCKET"), ServerUID: 0, Timeout: time.Second}
	_, err := ReadStatus(t.Context(), options)
	if uid == 65534 {
		if err == nil {
			t.Fatal("writer uid inherited operator status access from its group")
		}
		return
	}
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Submit(t.Context(), options, fixtureSnapshot()); err == nil {
		t.Fatal("read-only operator submitted directory authorization")
	}
}
