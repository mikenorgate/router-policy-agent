package ipc

import (
	"context"
	"encoding/json"
	"errors"
	"github.com/mikenorgate/router-policy-agent/internal/strictjson"
	"net"
	"time"
)

// MaximumObservationGrants bounds the retained sanitized policy catalog.
const MaximumObservationGrants = 4096
const maximumObservationResponse = 512 << 10

// ObservationContributor identifies a logical policy contribution and its original deadline.
type ObservationContributor struct {
	GroupID   string    `json:"group_id"`
	RuleID    string    `json:"rule_id"`
	Revision  string    `json:"revision"`
	ExpiresAt time.Time `json:"expires_at"`
}

// ObservationGrant describes a compiled grant and qualified binding evidence.
type ObservationGrant struct {
	DeviceID            string                   `json:"device_id"`
	MAC                 string                   `json:"mac"`
	Interface           string                   `json:"interface"`
	VLAN                uint16                   `json:"vlan"`
	BindingRef          string                   `json:"binding_ref"`
	AssociatedAt        time.Time                `json:"associated_at"`
	OwnershipObservedAt time.Time                `json:"ownership_observed_at"`
	OwnershipValidUntil time.Time                `json:"ownership_valid_until"`
	DeviceAddress       string                   `json:"device_address"`
	DeviceVariants      []string                 `json:"device_variants"`
	PeerAddress         string                   `json:"peer_address"`
	PeerVariants        []string                 `json:"peer_variants"`
	Direction           string                   `json:"direction"`
	Protocol            string                   `json:"protocol"`
	Port                uint16                   `json:"port"`
	Contributors        []ObservationContributor `json:"contributors"`
}

// ObservationSnapshot is immutable compilation evidence, independent of kernel installation.
type ObservationSnapshot struct {
	WriterSequence      uint64             `json:"writer_sequence"`
	FloorHash           string             `json:"floor_hash"`
	SchemaVersion       int                `json:"schema_version"`
	Generation          string             `json:"generation"`
	BaselineHash        string             `json:"baseline_hash"`
	BaselineGeneration  string             `json:"baseline_generation"`
	BindingGeneration   string             `json:"binding_generation"`
	CompiledAt          time.Time          `json:"compiled_at"`
	DirectoryObservedAt time.Time          `json:"directory_observed_at"`
	Mode                string             `json:"mode"`
	Complete            bool               `json:"complete"`
	Total               int                `json:"total"`
	Grants              []ObservationGrant `json:"grants"`
}

// ObservationRequest reads a generation-bound page without enforcement authority.
type ObservationRequest struct {
	SchemaVersion int    `json:"schema_version"`
	Operation     string `json:"operation"`
	Generation    string `json:"generation"`
	Offset        int    `json:"offset"`
}

// ObservationResponse contains a bounded page or a public failure code.
type ObservationResponse struct {
	Code       string               `json:"code"`
	Snapshot   *ObservationSnapshot `json:"snapshot"`
	NextOffset *int                 `json:"next_offset"`
}

// ObservationsFunc reads a sanitized cached snapshot.
type ObservationsFunc func(context.Context, ObservationRequest) (ObservationResponse, error)

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
