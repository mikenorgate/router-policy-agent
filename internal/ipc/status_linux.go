package ipc

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"time"
)

// ReportFunc must be read-only and must return only bounded status data. The
// transport does not grant access to the directory-processing callback.
type ReportFunc func(context.Context) (Report, error)

// NewStatusServer creates a status-only server for a separate supervisor-owned
// socket. ReaderUID pins the authorized operator account. It has no processor
// and rejects directory submissions, resets and arbitrary operations. Production
// wiring must separate this non-root operator UID from the writer/helper UIDs.
func NewStatusServer(options ServerOptions, report ReportFunc) (*Server, error) {
	if report == nil || options.Timeout <= 0 || options.Timeout > 10*time.Second {
		return nil, errors.New("ipc: invalid status server options")
	}
	return &Server{options: options, report: report}, nil
}

func (s *Server) serveStatus(ctx context.Context, connection *net.UnixConn) error {
	data, err := readFrame(connection, maximumStatusRequest)
	if err != nil {
		return err
	}
	response := reportResponse{SchemaVersion: 1, Code: "invalid_request"}
	if err := decodeStatusRequest(data); err == nil {
		report, err := s.report(ctx)
		response.Code = "status_failed"
		if err == nil && ctx.Err() == nil && validReport(report) == nil {
			response.Code, response.Report = "", &report
		}
	}
	encoded, err := json.Marshal(response)
	if err != nil {
		return errors.New("ipc: encode status response")
	}
	return writeFrame(connection, encoded, maximumResponse)
}

// ReadStatus authenticates the helper and queries its status-only socket. It
// sends a fixed operation without directory, binding, clock or command inputs.
// There is no retry, privilege fallback or interpretation as authorization.
func ReadStatus(ctx context.Context, options ClientOptions) (report Report, result error) {
	if ctx == nil || options.Timeout <= 0 || options.Timeout > 10*time.Second {
		return Report{}, errors.New("ipc: invalid status client options")
	}
	ctx, cancel := context.WithTimeout(ctx, options.Timeout)
	defer cancel()
	if err := checkSocket(ctx, options.Socket, options.ServerUID); err != nil {
		return Report{}, err
	}
	dialer := net.Dialer{}
	raw, err := dialer.DialContext(ctx, "unix", options.Socket)
	if err != nil {
		return Report{}, fmt.Errorf("ipc: connect to status helper: %w", err)
	}
	defer func() { result = errors.Join(result, closeExpected(raw)) }()
	connection, ok := raw.(*net.UnixConn)
	if !ok {
		return Report{}, errors.New("ipc: unix status connection required")
	}
	uid, err := peerUID(connection)
	if err != nil || uid != options.ServerUID {
		return Report{}, errors.New("ipc: unexpected status helper identity")
	}
	deadline, ok := ctx.Deadline()
	if !ok {
		return Report{}, errors.New("ipc: missing status client deadline")
	}
	if err := connection.SetDeadline(deadline); err != nil {
		return Report{}, fmt.Errorf("ipc: set status deadline: %w", err)
	}
	stop := interrupt(ctx, connection)
	defer func() { result = errors.Join(result, stop()) }()
	data := []byte(`{"schema_version":1,"operation":"status"}`)
	if err := writeFrame(connection, data, maximumStatusRequest); err != nil {
		return Report{}, err
	}
	response, err := readFrame(connection, maximumResponse)
	if err != nil {
		return Report{}, err
	}
	return decodeReport(response)
}
