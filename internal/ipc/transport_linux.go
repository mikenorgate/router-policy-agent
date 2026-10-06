package ipc

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"net"
	"os"
	"path/filepath"
	"syscall"
	"time"

	"github.com/mikenorgate/router-policy-agent/internal/hostfs"
	"github.com/mikenorgate/router-policy-agent/internal/policy"
)

// ProcessFunc must independently compile against helper-owned configuration,
// bindings, durable state and time. The transport cannot enforce that contract
// for an arbitrary callback. It never supplies any of those privileged inputs.
type ProcessFunc func(context.Context, policy.DirectorySnapshot) (Receipt, error)

// ServerOptions is local trusted configuration. ReaderUID identifies exactly
// one account through SO_PEERCRED; group membership and message fields do not.
// Production wiring must use a non-root reader distinct from the helper UID.
type ServerOptions struct {
	ReaderUID uint32
	Timeout   time.Duration
}

// Server handles one bounded transaction at a time, without per-client worker
// goroutines or a concurrent mutable policy engine.
type Server struct {
	options ServerOptions
	process ProcessFunc
	report  ReportFunc
}

// NewServer rejects missing processors and timeouts outside the ten-second cap.
func NewServer(options ServerOptions, process ProcessFunc) (*Server, error) {
	if process == nil || options.Timeout <= 0 || options.Timeout > 10*time.Second {
		return nil, errors.New("ipc: invalid server options")
	}
	return &Server{options: options, process: process}, nil
}

// Serve takes ownership of an already created Unix stream listener. A systemd
// socket unit should create its protected path and group before the capability-
// restricted helper starts. Existing paths are never removed or replaced here.
// Cancellation closes and joins the listener interruption; each connection is
// authenticated before reading its frame and has one bounded request lifetime.
func (s *Server) Serve(ctx context.Context, listener *net.UnixListener) (result error) {
	if ctx == nil || s == nil || listener == nil || s.options.Timeout <= 0 {
		return errors.New("ipc: invalid server or listener")
	}
	if (s.process == nil) == (s.report == nil) {
		return errors.New("ipc: server requires exactly one operation")
	}
	defer func() { result = errors.Join(result, closeExpected(listener)) }()
	uid, err := currentUID()
	if err != nil {
		return err
	}
	if err := checkSocket(ctx, listener.Addr().String(), uid); err != nil {
		return err
	}
	stop := interrupt(ctx, listener)
	defer func() { result = errors.Join(result, stop()) }()
	for {
		connection, err := listener.AcceptUnix()
		if err != nil {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			return fmt.Errorf("ipc: accept local connection: %w", err)
		}
		// A denied UID or malformed/disconnected client gets a closed connection,
		// not an engine invocation or a server restart. Kernel leases are never
		// renewed by these failures. Backend errors receive only a fixed code.
		if err := s.serveConnection(ctx, connection); err != nil && ctx.Err() != nil {
			return ctx.Err()
		}
	}
}

func (s *Server) serveConnection(ctx context.Context, connection *net.UnixConn) (result error) {
	defer func() { result = errors.Join(result, closeExpected(connection)) }()
	uid, err := peerUID(connection)
	if err != nil || uid != s.options.ReaderUID {
		return errors.New("ipc: unauthorized local identity")
	}
	ctx, cancel := context.WithTimeout(ctx, s.options.Timeout)
	defer cancel()
	deadline, ok := ctx.Deadline()
	if !ok {
		return errors.New("ipc: missing request deadline")
	}
	if err := connection.SetDeadline(deadline); err != nil {
		return fmt.Errorf("ipc: set transaction deadline: %w", err)
	}
	stop := interrupt(ctx, connection)
	defer func() { result = errors.Join(result, stop()) }()
	if s.report != nil {
		return s.serveStatus(ctx, connection)
	}
	data, err := readFrame(connection, maximumRequest)
	if err != nil {
		return err
	}
	snapshot, err := decodeRequest(data)
	receipt := Receipt{SchemaVersion: 1, Status: StatusRejected, Code: "invalid_request"}
	if err == nil {
		receipt, err = s.process(ctx, snapshot)
		if err != nil || validReceipt(receipt) != nil || receipt.Status == StatusRejected {
			receipt = Receipt{SchemaVersion: 1, Status: StatusRejected, Code: "processing_failed"}
		}
	}
	encoded, err := json.Marshal(receipt)
	if err != nil {
		return errors.New("ipc: encode response")
	}
	return writeFrame(connection, encoded, maximumResponse)
}

// ClientOptions pins the helper UID and a trusted filesystem socket path.
// This protects requests from being delivered to a substituted local server.
type ClientOptions struct {
	Socket    string
	ServerUID uint32
	Timeout   time.Duration
}

// Submit authenticates the helper through kernel peer credentials before
// sending a bounded snapshot. It does not retry, refresh timestamps or turn a
// rejected/shadow receipt into permission. Cancellation closes and joins I/O.
func Submit(ctx context.Context, options ClientOptions, snapshot policy.DirectorySnapshot) (receipt Receipt, result error) {
	if ctx == nil || options.Timeout <= 0 || options.Timeout > 10*time.Second {
		return Receipt{}, errors.New("ipc: invalid client options")
	}
	ctx, cancel := context.WithTimeout(ctx, options.Timeout)
	defer cancel()
	if err := checkSocket(ctx, options.Socket, options.ServerUID); err != nil {
		return Receipt{}, err
	}
	dialer := net.Dialer{}
	raw, err := dialer.DialContext(ctx, "unix", options.Socket)
	if err != nil {
		return Receipt{}, fmt.Errorf("ipc: connect to helper: %w", err)
	}
	defer func() { result = errors.Join(result, closeExpected(raw)) }()
	connection, ok := raw.(*net.UnixConn)
	if !ok {
		return Receipt{}, errors.New("ipc: unix connection required")
	}
	uid, err := peerUID(connection)
	if err != nil || uid != options.ServerUID {
		return Receipt{}, errors.New("ipc: unexpected helper identity")
	}
	deadline, ok := ctx.Deadline()
	if !ok {
		return Receipt{}, errors.New("ipc: missing client deadline")
	}
	if err := connection.SetDeadline(deadline); err != nil {
		return Receipt{}, fmt.Errorf("ipc: set client deadline: %w", err)
	}
	stop := interrupt(ctx, connection)
	defer func() { result = errors.Join(result, stop()) }()
	data, err := encodeRequest(snapshot)
	if err != nil {
		return Receipt{}, err
	}
	if err := writeFrame(connection, data, maximumRequest); err != nil {
		return Receipt{}, err
	}
	response, err := readFrame(connection, maximumResponse)
	if err != nil {
		return Receipt{}, err
	}
	receipt, err = decodeReceipt(response)
	if err != nil {
		return Receipt{}, err
	}
	if receipt.Status == StatusRejected {
		return receipt, ErrRejected
	}
	return receipt, nil
}

func checkSocket(ctx context.Context, path string, owner uint32) error {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return errors.New("ipc: clean absolute socket path required")
	}
	root, err := hostfs.OpenDirectory(ctx, hostfs.DirectoryOptions{Path: filepath.Dir(path), OwnerUID: owner})
	if err != nil {
		return err
	}
	info, statErr := root.Lstat(filepath.Base(path))
	closeErr := root.Close()
	if err := errors.Join(statErr, closeErr); err != nil {
		return fmt.Errorf("ipc: inspect socket: %w", err)
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	isSafeMode := info.Mode()&os.ModeSocket != 0 && info.Mode().Perm()&0o117 == 0
	if !ok || stat.Uid != owner || !isSafeMode {
		return errors.New("ipc: unsafe socket ownership or permissions")
	}
	return nil
}

func peerUID(connection *net.UnixConn) (uint32, error) {
	raw, err := connection.SyscallConn()
	if err != nil {
		return 0, fmt.Errorf("ipc: inspect peer descriptor: %w", err)
	}
	var credential *syscall.Ucred
	var credentialErr error
	err = raw.Control(func(fd uintptr) {
		if fd > math.MaxInt {
			credentialErr = errors.New("ipc: invalid peer descriptor")
			return
		}
		credential, credentialErr = syscall.GetsockoptUcred(int(fd), syscall.SOL_SOCKET, syscall.SO_PEERCRED)
	})
	if err := errors.Join(err, credentialErr); err != nil {
		return 0, fmt.Errorf("ipc: inspect kernel peer credentials: %w", err)
	}
	if credential == nil {
		return 0, errors.New("ipc: missing kernel peer credentials")
	}
	return credential.Uid, nil
}

func currentUID() (uint32, error) {
	uid := os.Geteuid()
	if uid < 0 || uint64(uid) > math.MaxUint32 {
		return 0, errors.New("ipc: invalid helper uid")
	}
	return uint32(uid), nil
}

// interrupt has one callback owner and joins it before resources leave scope.
// Stopping an AfterFunc does not itself wait for an already running callback.
func interrupt(ctx context.Context, closer io.Closer) func() error {
	done := make(chan error, 1)
	stop := context.AfterFunc(ctx, func() { done <- closeExpected(closer) })
	return func() error {
		if stop() {
			return nil
		}
		return <-done
	}
}

func closeExpected(closer io.Closer) error {
	err := closer.Close()
	if errors.Is(err, net.ErrClosed) {
		return nil
	}
	return err
}
