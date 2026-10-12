//go:build integration && linux

package ipc

import (
	"context"
	"errors"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestObservationSocketUIDAndMutationBoundary(t *testing.T) {
	t.Parallel()
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
