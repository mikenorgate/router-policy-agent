package ipc

import (
	"context"
	"encoding/json"
	"errors"
	"github.com/mikenorgate/router-policy-agent/internal/strictjson"
	"net"
	"time"
)

const maximumObservationResponse = 512 << 10

// NewObservationsServer has no processor or status callback. Its identity must
// be different from the writer/reader and aggregate operator in trusted wiring.
func NewObservationsServer(options ServerOptions, observations ObservationsFunc) (*Server, error) {
	if observations == nil || options.ReaderUID == 0 || options.Timeout <= 0 || options.Timeout > 2*time.Second {
		return nil, errors.New("ipc: invalid observations server")
	}
	return &Server{options: options, observations: observations}, nil
}
func decodeObservationRequest(data []byte) (ObservationRequest, error) {
	var request ObservationRequest
	if err := strictjson.Object(data, []string{"schema_version", "operation", "generation", "offset"}, nil, maximumStatusRequest); err != nil {
		return request, err
	}
	if err := strictjson.Decode(data, &request, maximumStatusRequest); err != nil {
		return request, err
	}
	if request.SchemaVersion != 1 || request.Operation != "observations" || request.Offset < 0 || request.Offset > MaximumObservationGrants || request.Offset > 0 && !statusIdentifier.MatchString(request.Generation) || request.Generation != "" && !statusIdentifier.MatchString(request.Generation) {
		return request, errors.New("ipc: invalid observations request")
	}
	return request, nil
}
func (s *Server) serveObservations(ctx context.Context, connection *net.UnixConn) error {
	data, err := readFrame(connection, maximumStatusRequest)
	if err != nil {
		return err
	}
	response := ObservationResponse{Code: "invalid_request"}
	if request, err := decodeObservationRequest(data); err == nil {
		response, err = s.observations(ctx, request)
		if err != nil || ctx.Err() != nil {
			response = ObservationResponse{Code: "observations_failed"}
		}
	}
	encoded, err := json.Marshal(response)
	if err != nil {
		return errors.New("ipc: encode observations")
	}
	if len(encoded) > maximumObservationResponse {
		encoded = []byte(`{"code":"observations_too_large","snapshot":null,"next_offset":null}`)
	}
	return writeFrame(connection, encoded, maximumObservationResponse)
}
