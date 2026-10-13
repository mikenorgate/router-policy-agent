package ipc

import (
	"context"
	"time"
)

// MaximumObservationGrants bounds the retained sanitized policy catalog.
const MaximumObservationGrants = 4096

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
	PeerNetwork         string                   `json:"peer_network,omitempty"`
	PeerNetworkVariants []string                 `json:"peer_network_variants,omitempty"`
	Internet            bool                     `json:"internet,omitempty"`
	Direction           string                   `json:"direction"`
	Protocol            string                   `json:"protocol"`
	Port                uint16                   `json:"port"`
	PortEnd             uint16                   `json:"port_end,omitempty"`
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
