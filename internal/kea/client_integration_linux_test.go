//go:build integration && linux

package kea

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"math"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func queryFixture(t *testing.T, handler func(*net.UnixConn, int), count int) (*net.UnixListener, Options) {
	t.Helper()
	uid := os.Geteuid()
	if uid < 0 || uid > math.MaxUint32 {
		t.Fatal("invalid fixture uid")
		return nil, Options{}
	}
	path := filepath.Join(t.TempDir(), "kea.sock")
	listener, err := net.ListenUnix("unix", &net.UnixAddr{Name: path, Net: "unix"})
	if err != nil {
		t.Fatal(err)
	}
	listener.SetUnlinkOnClose(false)
	// #nosec G302 -- A synthetic local socket, not a secret or an installed API.
	if err := os.Chmod(path, 0o660); err != nil {
		t.Fatal(err)
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		for index := range count {
			connection, err := listener.AcceptUnix()
			if errors.Is(err, net.ErrClosed) {
				return
			}
			if err != nil {
				t.Error(err)
				return
			}
			if err := connection.SetDeadline(time.Now().Add(time.Second)); err != nil {
				t.Error(err)
			}
			handler(connection, index)
			if err := closeConnection(connection); err != nil {
				t.Error(err)
			}
		}
	}()
	t.Cleanup(func() {
		if err := closeConnection(listener); err != nil {
			t.Error(err)
		}
		select {
		case <-done:
		case <-time.After(2 * time.Second):
			t.Error("fixture did not join")
		}
	})
	options := fixtureOptions()
	options.Socket = path
	options.ServerUID = uint32(uid)
	return listener, options
}

func readQuery(t *testing.T, connection *net.UnixConn) bool {
	t.Helper()
	var request struct {
		Command   string            `json:"command"`
		Arguments map[string]string `json:"arguments"`
	}
	decoder := json.NewDecoder(connection)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&request); err != nil {
		t.Error(err)
		return false
	}
	if request.Command != "lease4-get-by-hw-address" || len(request.Arguments) != 1 ||
		request.Arguments["hw-address"] != "02:aa:bb:cc:dd:ee" {
		t.Error("unexpected command, mutation or query identifier")
		return false
	}
	return true
}

func TestLocalQueryIsFreshButCannotRefreshLeaseExpiry(t *testing.T) {
	t.Parallel()
	lease := fixtureLease()
	lease["cltt"] = time.Now().Unix() - 600
	data := fixtureResponse(t, lease)
	var requests atomic.Int32
	_, options := queryFixture(t, func(connection *net.UnixConn, index int) {
		if !readQuery(t, connection) {
			return
		}
		requests.Add(1)
		response := data
		if index == 1 {
			response = []byte(`{"result":3,"arguments":{"leases":[]}}`)
		}
		if _, err := connection.Write(response); err != nil {
			t.Error(err)
		}
	}, 2)
	before := time.Now().UTC()
	observation, err := ReadIPv4(t.Context(), options, fixtureMAC)
	if err != nil || len(observation.Leases) != 1 {
		t.Fatalf("local lease query: %v", err)
	}
	if observation.ObservedAt.Before(before) || observation.ObservedAt.After(time.Now().UTC()) {
		t.Fatal("observation time not sampled during this query")
	}
	if observation.Leases[0].UpdatedAt.Unix() != lease["cltt"] ||
		observation.Leases[0].ValidUntil.Unix() != observation.Leases[0].UpdatedAt.Unix()+3600 {
		t.Fatal("lease renewal or expiry changed")
	}
	absent, err := ReadIPv4(t.Context(), options, fixtureMAC)
	if err != nil || len(absent.Leases) != 0 || absent.ObservedAt.IsZero() || requests.Load() != 2 {
		t.Fatalf("lease disappearance reused cached ownership: %v", err)
	}
}

func TestQueryCancellationJoinsIO(t *testing.T) {
	t.Parallel()
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	_, options := queryFixture(t, func(connection *net.UnixConn, _ int) {
		if !readQuery(t, connection) {
			return
		}
		cancel()
		data := make([]byte, 1)
		if _, err := connection.Read(data); !errors.Is(err, io.EOF) {
			t.Error("cancellation did not close the client connection")
		}
	}, 1)
	observation, err := ReadIPv4(ctx, options, fixtureMAC)
	if !errors.Is(err, context.Canceled) || !observation.ObservedAt.IsZero() || len(observation.Leases) != 0 {
		t.Fatal("canceled query produced ownership or lost cancellation")
	}
}

func TestLocalQueryRejectsIncompleteOrUnboundedResponses(t *testing.T) {
	t.Parallel()
	for _, name := range []string{"truncated", "oversized", "trailing", "stall", "no eof"} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			lease := fixtureLease()
			lease["cltt"] = time.Now().Unix() - 600
			data := fixtureResponse(t, lease)
			_, options := queryFixture(t, func(connection *net.UnixConn, _ int) {
				if !readQuery(t, connection) {
					return
				}
				response := data
				switch name {
				case "truncated":
					response = data[:len(data)-1]
				case "oversized":
					response = []byte(strings.Repeat(" ", maximumResponse+1))
				case "trailing":
					response = append(append([]byte{}, data...), []byte("{}")...)
				case "stall":
					response = []byte{}
				}
				if _, err := connection.Write(response); err != nil && name != "oversized" {
					t.Error(err)
				}
				if name == "stall" || name == "no eof" {
					if _, err := io.Copy(io.Discard, connection); err != nil {
						t.Error(err)
					}
				}
			}, 1)
			options.Timeout = 100 * time.Millisecond
			observation, err := ReadIPv4(t.Context(), options, fixtureMAC)
			if err == nil || !observation.ObservedAt.IsZero() || len(observation.Leases) != 0 {
				t.Fatal("bad or unbounded response produced ownership")
			}
		})
	}
}

func TestUnsafeSocketNeverReceivesAQuery(t *testing.T) {
	t.Parallel()
	for _, name := range []string{"public socket", "public directory", "symlink", "wrong peer", "pre-canceled", "invalid mac"} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			var received atomic.Bool
			_, options := queryFixture(t, func(connection *net.UnixConn, _ int) {
				data := make([]byte, 1)
				if count, _ := connection.Read(data); count > 0 { // Only data arrival matters, not the expected EOF.
					received.Store(true)
				}
			}, 1)
			ctx := t.Context()
			mac := fixtureMAC
			switch name {
			case "public socket":
				// #nosec G302 -- Deliberately rejected fixture permissions.
				if err := os.Chmod(options.Socket, 0o666); err != nil {
					t.Fatal(err)
				}
			case "public directory":
				// #nosec G302 -- Deliberately rejected fixture permissions.
				if err := os.Chmod(filepath.Dir(options.Socket), 0o777); err != nil {
					t.Fatal(err)
				}
			case "symlink":
				alias := filepath.Join(filepath.Dir(options.Socket), "alias.sock")
				if err := os.Symlink(options.Socket, alias); err != nil {
					t.Fatal(err)
				}
				options.Socket = alias
			case "wrong peer":
				if os.Geteuid() != 0 {
					t.Skip("wrong peer fixture requires isolated root with chown capability")
				}
				options.ServerUID = 65534
				if err := os.Chown(filepath.Dir(options.Socket), 65534, 65534); err != nil {
					t.Fatal(err)
				}
				if err := os.Chown(options.Socket, 65534, 65534); err != nil {
					t.Fatal(err)
				}
				// Restore ownership before TempDir cleanup; no DAC override
				// capability is needed for this denied-peer fixture.
				t.Cleanup(func() {
					if err := os.Chown(filepath.Dir(options.Socket), 0, 0); err != nil {
						t.Error(err)
					}
				})
			case "pre-canceled":
				canceled, cancel := context.WithCancel(ctx)
				cancel()
				ctx = canceled
			case "invalid mac":
				mac = `02aabbccddee"}`
			}
			if observation, err := ReadIPv4(ctx, options, mac); err == nil || !observation.ObservedAt.IsZero() {
				t.Fatal("unsafe local boundary accepted")
			}
			if received.Load() {
				t.Fatal("query sent before daemon authentication")
			}
		})
	}
}
