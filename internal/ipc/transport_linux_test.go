//go:build integration && linux

package ipc

import (
	"context"
	"errors"
	"io"
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

func TestRealUnprivilegedReader(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("cross-uid subprocess qualification requires an isolated root test runner")
	}
	directory, err := os.MkdirTemp("", "rpa-ipc-")
	if err != nil {
		t.Fatal(err)
	}
	// #nosec G302 -- The isolated reader must traverse its synthetic test root.
	if err := os.Chmod(directory, 0o755); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := os.RemoveAll(directory); err != nil {
			t.Error(err)
		}
	})
	path := filepath.Join(directory, "helper.sock")
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
	if err := os.Chown(path, 0, 65534); err != nil {
		t.Fatal(err)
	}
	// #nosec G302 -- Only the pinned reader group can connect to this test socket.
	if err := os.Chmod(path, 0o660); err != nil {
		t.Fatal(err)
	}
	var invocations atomic.Int32
	startServer(t, listener, 65534, func(context.Context, policy.DirectorySnapshot) (Receipt, error) {
		invocations.Add(1)
		return fixtureReceipt(), nil
	})
	executable := copyTestExecutable(t, directory)
	// #nosec G204 -- Execute only the copied current test binary with fixed flags.
	command := exec.CommandContext(t.Context(), executable, "-test.run=^TestIPCReaderProcess$")
	command.Env = append(os.Environ(), "RPA_IPC_TEST_CHILD=1", "RPA_IPC_TEST_SOCKET="+path)
	command.SysProcAttr = &syscall.SysProcAttr{Credential: &syscall.Credential{Uid: 65534, Gid: 65534}}
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("unprivileged reader: %v: %s", err, output)
	}
	if invocations.Load() != 1 {
		t.Fatal("real unprivileged reader did not reach the processor exactly once")
	}
	options := ClientOptions{Socket: path, ServerUID: 0, Timeout: time.Second}
	if _, err := Submit(t.Context(), options, fixtureSnapshot()); err == nil {
		t.Fatal("root client accepted in place of the pinned unprivileged reader")
	}
	if invocations.Load() != 1 {
		t.Fatal("wrong uid reached the processor")
	}
}

func TestIPCReaderProcess(t *testing.T) {
	if os.Getenv("RPA_IPC_TEST_CHILD") != "1" {
		t.Skip("subprocess entry point")
	}
	if os.Geteuid() != 65534 {
		t.Fatal("reader subprocess did not drop privilege")
	}
	options := ClientOptions{Socket: os.Getenv("RPA_IPC_TEST_SOCKET"), ServerUID: 0, Timeout: time.Second}
	receipt, err := Submit(t.Context(), options, fixtureSnapshot())
	if err != nil || receipt.Status != StatusShadow {
		t.Fatalf("reader submission: %v", err)
	}
}

func copyTestExecutable(t *testing.T, directory string) string {
	t.Helper()
	path, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	// #nosec G304 -- The source is supplied by os.Executable, never test input.
	source, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := source.Close(); err != nil {
			t.Error(err)
		}
	}()
	path = filepath.Join(directory, "reader.test")
	// #nosec G302 G304 -- Fixed executable name in a private, freshly created test root; O_EXCL prevents replacement.
	destination, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o755)
	if err != nil {
		t.Fatal(err)
	}
	_, copyErr := io.Copy(destination, source)
	closeErr := destination.Close()
	if err := errors.Join(copyErr, closeErr); err != nil {
		t.Fatal(err)
	}
	return path
}

func testListener(t *testing.T) (*net.UnixListener, ClientOptions) {
	t.Helper()
	uid, err := currentUID()
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "helper.sock")
	listener, err := net.ListenUnix("unix", &net.UnixAddr{Name: path, Net: "unix"})
	if err != nil {
		t.Fatal(err)
	}
	listener.SetUnlinkOnClose(false)
	// #nosec G302 -- The shared local socket needs reader-group write access.
	if err := os.Chmod(path, 0o660); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := closeExpected(listener); err != nil {
			t.Error(err)
		}
	})
	return listener, ClientOptions{Socket: path, ServerUID: uid, Timeout: time.Second}
}

func startServer(t *testing.T, listener *net.UnixListener, uid uint32, process ProcessFunc) {
	t.Helper()
	server, err := NewServer(ServerOptions{ReaderUID: uid, Timeout: time.Second}, process)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	var worker sync.WaitGroup
	errorsOut := make(chan error, 1)
	worker.Go(func() { errorsOut <- server.Serve(ctx, listener) })
	t.Cleanup(func() {
		cancel()
		worker.Wait()
		if err := <-errorsOut; !errors.Is(err, context.Canceled) {
			t.Errorf("server shutdown: %v", err)
		}
	})
}

func TestSubmit(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name    string
		process ProcessFunc
		wantErr bool
	}{
		{name: "shadow receipt", process: func(context.Context, policy.DirectorySnapshot) (Receipt, error) {
			return fixtureReceipt(), nil
		}},
		{name: "backend failure redacted", wantErr: true, process: func(context.Context, policy.DirectorySnapshot) (Receipt, error) {
			return Receipt{}, errors.New("synthetic sensitive backend detail")
		}},
		{name: "invalid processor response", wantErr: true, process: func(context.Context, policy.DirectorySnapshot) (Receipt, error) {
			return Receipt{}, nil
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			listener, options := testListener(t)
			startServer(t, listener, options.ServerUID, test.process)
			receipt, err := Submit(t.Context(), options, fixtureSnapshot())
			if test.wantErr {
				if !errors.Is(err, ErrRejected) || receipt.Code != "processing_failed" ||
					strings.Contains(err.Error(), "sensitive") {
					t.Fatalf("unsafe rejection: %#v, %v", receipt, err)
				}
				return
			}
			if err != nil || receipt.Status != StatusShadow {
				t.Fatalf("submission: %#v, %v", receipt, err)
			}
		})
	}
}

func TestUIDAndSchemaBoundary(t *testing.T) {
	t.Parallel()
	t.Run("wrong reader uid", func(t *testing.T) {
		listener, options := testListener(t)
		var invocations atomic.Int32
		startServer(t, listener, options.ServerUID+1, func(context.Context, policy.DirectorySnapshot) (Receipt, error) {
			invocations.Add(1)
			return fixtureReceipt(), nil
		})
		if _, err := Submit(t.Context(), options, fixtureSnapshot()); err == nil {
			t.Fatal("incorrect peer uid accepted")
		}
		if invocations.Load() != 0 {
			t.Fatal("unauthorized client reached the processor")
		}
	})
	t.Run("wrong helper uid", func(t *testing.T) {
		listener, options := testListener(t)
		startServer(t, listener, options.ServerUID, func(context.Context, policy.DirectorySnapshot) (Receipt, error) {
			return fixtureReceipt(), nil
		})
		options.ServerUID++
		if _, err := Submit(t.Context(), options, fixtureSnapshot()); err == nil {
			t.Fatal("incorrect helper uid accepted")
		}
	})
	t.Run("unknown fields never processed", func(t *testing.T) {
		listener, options := testListener(t)
		var invocations atomic.Int32
		startServer(t, listener, options.ServerUID, func(context.Context, policy.DirectorySnapshot) (Receipt, error) {
			invocations.Add(1)
			return fixtureReceipt(), nil
		})
		dialer := net.Dialer{}
		connection, err := dialer.DialContext(t.Context(), "unix", options.Socket)
		if err != nil {
			t.Fatal(err)
		}
		defer func() {
			if err := connection.Close(); err != nil {
				t.Error(err)
			}
		}()
		if err := connection.SetDeadline(time.Now().Add(time.Second)); err != nil {
			t.Fatal(err)
		}
		if err := writeFrame(connection, []byte(`{"schema_version":1,"directory":{},"command":"anything"}`), maximumRequest); err != nil {
			t.Fatal(err)
		}
		data, err := readFrame(connection, maximumResponse)
		if err != nil {
			t.Fatal(err)
		}
		receipt, err := decodeReceipt(data)
		if err != nil || receipt.Code != "invalid_request" || invocations.Load() != 0 {
			t.Fatalf("unknown field boundary: %#v, %v", receipt, err)
		}
	})
}

func TestCancellationAndSocketPermissions(t *testing.T) {
	t.Parallel()
	t.Run("canceled client", func(t *testing.T) {
		listener, options := testListener(t)
		startServer(t, listener, options.ServerUID, func(context.Context, policy.DirectorySnapshot) (Receipt, error) {
			return fixtureReceipt(), nil
		})
		ctx, cancel := context.WithCancel(t.Context())
		cancel()
		if _, err := Submit(ctx, options, fixtureSnapshot()); !errors.Is(err, context.Canceled) {
			t.Fatalf("canceled submission: %v", err)
		}
	})
	t.Run("world writable socket", func(t *testing.T) {
		listener, options := testListener(t)
		// #nosec G302 -- World-write is deliberately the rejection fixture.
		if err := os.Chmod(options.Socket, 0o666); err != nil {
			t.Fatal(err)
		}
		if err := checkSocket(t.Context(), options.Socket, options.ServerUID); err == nil {
			t.Fatal("world-writable socket accepted")
		}
		server, err := NewServer(ServerOptions{ReaderUID: options.ServerUID, Timeout: time.Second},
			func(context.Context, policy.DirectorySnapshot) (Receipt, error) { return fixtureReceipt(), nil })
		if err != nil {
			t.Fatal(err)
		}
		if err := server.Serve(t.Context(), listener); err == nil {
			t.Fatal("server accepted an unsafe listener")
		}
	})
}
