// Package ipc carries bounded directory snapshots across a local UID boundary.
// It has no operations for commands, firewall text, bindings or state resets.
package ipc

import (
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"time"

	"github.com/mikenorgate/router-policy-agent/internal/policy"
	"github.com/mikenorgate/router-policy-agent/internal/strictjson"
)

const maximumRequest = 16 << 20
const maximumResponse = 64 << 10

// ErrRejected is deliberately independent of privileged backend error details.
var ErrRejected = errors.New("ipc: snapshot rejected")

// Status distinguishes shadow compilation from an actual kernel transaction.
type Status string

// Supported response states; a shadow receipt is not firewall authorization.
const (
	StatusShadow   Status = "shadow"
	StatusApplied  Status = "applied"
	StatusRejected Status = "rejected"
)

// Receipt is a credential-free summary. Raw policies and backend diagnostics
// cannot cross back through this response envelope.
type Receipt struct {
	SchemaVersion int       `json:"schema_version"`
	Status        Status    `json:"status"`
	Code          string    `json:"code"`
	BaselineHash  string    `json:"baseline_hash"`
	CompiledAt    time.Time `json:"compiled_at"`
	GrantCount    int       `json:"grant_count"`
	DenialCount   int       `json:"denial_count"`
}

type request struct {
	SchemaVersion int             `json:"schema_version"`
	Directory     json.RawMessage `json:"directory"`
}

func decodeRequest(data []byte) (policy.DirectorySnapshot, error) {
	if err := strictjson.Object(data, []string{"schema_version", "directory"}, nil, maximumRequest); err != nil {
		return policy.DirectorySnapshot{}, err
	}
	var envelope request
	if err := strictjson.Decode(data, &envelope, maximumRequest); err != nil {
		return policy.DirectorySnapshot{}, err
	}
	if envelope.SchemaVersion != 1 {
		return policy.DirectorySnapshot{}, errors.New("ipc: unsupported protocol version")
	}
	return decodeDirectory(envelope.Directory)
}

func decodeDirectory(data []byte) (policy.DirectorySnapshot, error) {
	keys := []string{"observed_at", "complete", "groups", "devices"}
	if err := strictjson.Object(data, keys, nil, maximumRequest); err != nil {
		return policy.DirectorySnapshot{}, err
	}
	var shape struct {
		Groups  []json.RawMessage `json:"groups"`
		Devices []json.RawMessage `json:"devices"`
	}
	// Decode the already checked object into RawMessages without permitting
	// unknown fields on the final typed decode below.
	object := map[string]json.RawMessage{}
	if err := strictjson.Decode(data, &object, maximumRequest); err != nil {
		return policy.DirectorySnapshot{}, err
	}
	if err := strictjson.Decode(object["groups"], &shape.Groups, maximumRequest); err != nil {
		return policy.DirectorySnapshot{}, err
	}
	if err := strictjson.Decode(object["devices"], &shape.Devices, maximumRequest); err != nil {
		return policy.DirectorySnapshot{}, err
	}
	if len(shape.Groups) > 8192 || len(shape.Devices) > 4096 {
		return policy.DirectorySnapshot{}, errors.New("ipc: directory collection quota exceeded")
	}
	for _, group := range shape.Groups {
		if err := strictjson.Object(group, []string{"id", "name", "is_network"}, []string{"policy"}, maximumRequest); err != nil {
			return policy.DirectorySnapshot{}, err
		}
	}
	for _, device := range shape.Devices {
		if err := strictjson.Object(device, []string{"id", "mac", "active", "group_ids"}, nil, maximumRequest); err != nil {
			return policy.DirectorySnapshot{}, err
		}
	}
	var snapshot policy.DirectorySnapshot
	if err := strictjson.Decode(data, &snapshot, maximumRequest); err != nil {
		return policy.DirectorySnapshot{}, err
	}
	return snapshot, nil
}

func encodeRequest(snapshot policy.DirectorySnapshot) ([]byte, error) {
	directory, err := json.Marshal(snapshot)
	if err != nil {
		return nil, errors.New("ipc: encode directory snapshot")
	}
	data, err := json.Marshal(request{SchemaVersion: 1, Directory: directory})
	if err != nil || len(data) > maximumRequest {
		return nil, errors.New("ipc: oversized directory request")
	}
	return data, nil
}

func decodeReceipt(data []byte) (Receipt, error) {
	keys := []string{"schema_version", "status", "code", "baseline_hash", "compiled_at", "grant_count", "denial_count"}
	if err := strictjson.Object(data, keys, nil, maximumResponse); err != nil {
		return Receipt{}, err
	}
	var receipt Receipt
	if err := strictjson.Decode(data, &receipt, maximumResponse); err != nil {
		return Receipt{}, err
	}
	if err := validReceipt(receipt); err != nil {
		return Receipt{}, err
	}
	return receipt, nil
}

func validReceipt(receipt Receipt) error {
	isBadEnvelope := receipt.SchemaVersion != 1 || receipt.GrantCount < 0 || receipt.GrantCount > 16384 ||
		receipt.DenialCount < 0 || receipt.DenialCount > 4096
	if isBadEnvelope {
		return errors.New("ipc: invalid response envelope")
	}
	if receipt.Status == StatusRejected {
		isKnownCode := receipt.Code == "invalid_request" || receipt.Code == "processing_failed"
		isEmptySummary := receipt.BaselineHash == "" && receipt.CompiledAt.IsZero() &&
			receipt.GrantCount == 0 && receipt.DenialCount == 0
		if !isKnownCode || !isEmptySummary {
			return errors.New("ipc: invalid rejection response")
		}
		return nil
	}
	isSuccess := receipt.Status == StatusShadow || receipt.Status == StatusApplied
	digest, err := hex.DecodeString(receipt.BaselineHash)
	isValidHash := err == nil && len(digest) == 32 && hex.EncodeToString(digest) == receipt.BaselineHash
	if !isSuccess || receipt.Code != "" || receipt.CompiledAt.IsZero() || !isValidHash {
		return errors.New("ipc: invalid success response")
	}
	return nil
}

func readFrame(reader io.Reader, maximum int) ([]byte, error) {
	if reader == nil || maximum <= 0 || maximum > maximumRequest {
		return nil, errors.New("ipc: invalid frame reader or limit")
	}
	var header [4]byte
	if _, err := io.ReadFull(reader, header[:]); err != nil {
		return nil, fmt.Errorf("ipc: read frame header: %w", err)
	}
	length := binary.BigEndian.Uint32(header[:])
	if length == 0 || uint64(length) > uint64(maximum) {
		return nil, errors.New("ipc: frame size outside limit")
	}
	data := make([]byte, int(length))
	if _, err := io.ReadFull(reader, data); err != nil {
		return nil, fmt.Errorf("ipc: read frame body: %w", err)
	}
	return data, nil
}

func writeFrame(writer io.Writer, data []byte, maximum int) error {
	// Keep the integer narrowing bound explicit at the serialization boundary.
	length := len(data)
	if length <= 0 || length > maximumRequest {
		return errors.New("ipc: invalid frame length")
	}
	isBadLimit := maximum <= 0 || maximum > maximumRequest
	isBadSize := length > maximum
	if writer == nil || isBadLimit || isBadSize {
		return errors.New("ipc: frame size or writer outside limit")
	}
	var header [4]byte
	binary.BigEndian.PutUint32(header[:], uint32(length))
	for _, part := range [][]byte{header[:], data} {
		n, err := writer.Write(part)
		if err != nil {
			return fmt.Errorf("ipc: write frame: %w", err)
		}
		if n != len(part) {
			return io.ErrShortWrite
		}
	}
	return nil
}
