//go:build integration && linux

package ipc

import (
	"context"
	"errors"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"
)

func TestObservationSocketUIDAndMutationBoundary(t *testing.T) {
	t.Parallel()
	if os.Geteuid() == 0 {
		t.Skip("healthy non-root peer is covered by the cross-UID subprocess test")
	}
	for _, wrong := range []bool{false, true} {
		listener, options := testListener(t)
		uid := options.ServerUID
		if wrong {
			uid++
		}
		var calls atomic.Int32
		server, err := NewObservationsServer(ServerOptions{ReaderUID: uid, Timeout: time.Second}, func(context.Context, ObservationRequest) (ObservationResponse, error) {
			calls.Add(1)
			return ObservationResponse{Code: "unobserved"}, nil
		})
		if err != nil {
			t.Fatal(err)
		}
		ctx, cancel := context.WithCancel(t.Context())
		var workers sync.WaitGroup
		done := make(chan error, 1)
		workers.Go(func() { done <- server.Serve(ctx, listener) })
		t.Cleanup(func() {
			cancel()
			workers.Wait()
			if err := <-done; !errors.Is(err, context.Canceled) {
				t.Error(err)
			}
		})
		for _, operation := range []string{"reset", "observations"} {
			connection, err := net.DialUnix("unix", nil, &net.UnixAddr{Name: options.Socket, Net: "unix"})
			if err != nil {
				t.Fatal(err)
			}
			if err := connection.SetDeadline(time.Now().Add(time.Second)); err != nil {
				t.Fatal(err)
			}
			data := []byte(`{"schema_version":1,"operation":"` + operation + `","generation":"","offset":0}`)
			writeErr := writeFrame(connection, data, maximumStatusRequest)
			response, readErr := readFrame(connection, maximumObservationResponse)
			if err := connection.Close(); err != nil {
				t.Fatal(err)
			}
			if !wrong && (writeErr != nil || readErr != nil || len(response) == 0) {
				t.Fatal("authorized observation transport failed", writeErr, readErr)
			}
			if wrong && writeErr == nil && readErr == nil {
				t.Fatal("wrong UID received an observation")
			}
			expected := int32(0)
			if !wrong && operation == "observations" {
				expected = 1
			}
			if calls.Load() != expected {
				t.Fatal("unauthorized or mutation-shaped request reached observation callback")
			}
		}
	}
}

func TestRealUnprivilegedObservationReader(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("cross-UID test requires isolated root runner")
	}
	directory, err := os.MkdirTemp("", "rpa-observe-")
	if err != nil {
		t.Fatal(err)
	}
	// #nosec G302 -- Synthetic unprivileged peers must traverse their test directory.
	if err := os.Chmod(directory, 0o755); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := os.RemoveAll(directory); err != nil {
			t.Error(err)
		}
	})
	path := filepath.Join(directory, "observe.sock")
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
	// #nosec G302 -- Both synthetic peers share the socket group; UID authorization remains required.
	if err := os.Chmod(path, 0o660); err != nil {
		t.Fatal(err)
	}
	var calls atomic.Int32
	server, err := NewObservationsServer(ServerOptions{ReaderUID: 65533, Timeout: time.Second}, func(context.Context, ObservationRequest) (ObservationResponse, error) {
		calls.Add(1)
		return ObservationResponse{Code: "unobserved"}, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	var worker sync.WaitGroup
	done := make(chan error, 1)
	worker.Go(func() { done <- server.Serve(ctx, listener) })
	t.Cleanup(func() {
		cancel()
		worker.Wait()
		if err := <-done; !errors.Is(err, context.Canceled) {
			t.Error(err)
		}
	})
	executable := copyTestExecutable(t, directory)
	for _, uid := range []uint32{65533, 65534} {
		// #nosec G204 -- Fixed test entry point in the copied current test executable.
		command := exec.CommandContext(t.Context(), executable, "-test.run=^TestObservationReaderProcess$")
		command.Env = []string{"RPA_OBSERVATION_CHILD=1", "RPA_OBSERVATION_SOCKET=" + path}
		command.SysProcAttr = &syscall.SysProcAttr{Credential: &syscall.Credential{Uid: uid, Gid: 65533}}
		if output, err := command.CombinedOutput(); err != nil {
			t.Fatalf("observation peer: %v: %s", err, output)
		}
	}
	if calls.Load() != 1 {
		t.Fatal("observer UID did not exclusively reach callback")
	}
}

func TestObservationReaderProcess(t *testing.T) {
	if os.Getenv("RPA_OBSERVATION_CHILD") != "1" {
		t.Skip("subprocess entry point")
	}
	connection, err := net.DialUnix("unix", nil, &net.UnixAddr{Name: os.Getenv("RPA_OBSERVATION_SOCKET"), Net: "unix"})
	if err != nil {
		t.Fatal(err)
	}
	if err := connection.SetDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	writeErr := writeFrame(connection, []byte(`{"schema_version":1,"operation":"observations","generation":"","offset":0}`), maximumStatusRequest)
	_, readErr := readFrame(connection, maximumObservationResponse)
	if err := connection.Close(); err != nil {
		t.Fatal(err)
	}
	if os.Geteuid() == 65533 && (writeErr != nil || readErr != nil) {
		t.Fatal("observer rejected", writeErr, readErr)
	}
	if os.Geteuid() != 65533 && writeErr == nil && readErr == nil {
		t.Fatal("writer with same socket group accepted")
	}
}
