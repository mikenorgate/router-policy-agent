package ipc

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"errors"
	"io"
	"strings"
	"testing"
	"time"

	"github.com/mikenorgate/router-policy-agent/internal/policy"
)

func fixtureSnapshot() policy.DirectorySnapshot {
	return policy.DirectorySnapshot{
		ObservedAt: time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC), Complete: true,
		Groups: []policy.Group{{ID: "synthetic-group", Name: "synthetic", IsNetwork: false}},
		Devices: []policy.Device{{ID: "synthetic-device", MAC: "02:00:00:00:00:01", Active: true,
			GroupIDs: []string{"synthetic-group"}}},
	}
}

func fixtureReceipt() Receipt {
	return Receipt{SchemaVersion: 1, Status: StatusShadow, BaselineHash: strings.Repeat("a", 64),
		CompiledAt: fixtureSnapshot().ObservedAt, GrantCount: 1}
}

func TestRequestSchema(t *testing.T) {
	t.Parallel()
	valid, err := encodeRequest(fixtureSnapshot())
	if err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name string
		raw  string
	}{
		{name: "commands", raw: strings.Replace(string(valid), `"schema_version":`, `"command":"anything","schema_version":`, 1)},
		{name: "firewall program", raw: strings.Replace(string(valid), `"schema_version":`, `"nftables":[],"schema_version":`, 1)},
		{name: "caller bindings", raw: strings.Replace(string(valid), `"schema_version":`, `"bindings":{},"schema_version":`, 1)},
		{name: "caller clock", raw: strings.Replace(string(valid), `"schema_version":`, `"now":"2026-01-01T12:00:00Z","schema_version":`, 1)},
		{name: "state reset", raw: strings.Replace(string(valid), `"schema_version":`, `"reset":true,"schema_version":`, 1)},
		{name: "duplicate key", raw: strings.Replace(string(valid), `"schema_version":1`, `"schema_version":1,"schema_version":1`, 1)},
		{name: "unknown version", raw: strings.Replace(string(valid), `"schema_version":1`, `"schema_version":2`, 1)},
		{name: "wrong key case", raw: strings.Replace(string(valid), `"mac":`, `"MAC":`, 1)},
		{name: "semantic duplicate", raw: strings.Replace(string(valid), `"active":true`, `"active":true,"ACTIVE":false`, 1)},
		{name: "unknown group field", raw: strings.Replace(string(valid), `"is_network":false`, `"is_network":false,"priority":1`, 1)},
		{name: "missing group field", raw: strings.Replace(string(valid), `,"is_network":false`, ``, 1)},
		{name: "null membership", raw: strings.Replace(string(valid), `["synthetic-group"]`, `null`, 1)},
		{name: "null groups", raw: strings.Replace(string(valid), `[{"id":"synthetic-group","name":"synthetic","is_network":false}]`, `null`, 1)},
		{name: "trailing input", raw: string(valid) + `{}`},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			if _, err := decodeRequest([]byte(test.raw)); err == nil {
				t.Fatal("unsupported request accepted")
			}
		})
	}
	snapshot, err := decodeRequest(valid)
	if err != nil || len(snapshot.Devices) != 1 {
		t.Fatalf("valid request: %v", err)
	}
}

func TestReceiptSchema(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name   string
		mutate func(*Receipt)
	}{
		{name: "unknown schema", mutate: func(r *Receipt) { r.SchemaVersion = 2 }},
		{name: "unknown status", mutate: func(r *Receipt) { r.Status = "allow" }},
		{name: "raw error code", mutate: func(r *Receipt) { r.Code = "raw directory text" }},
		{name: "invalid digest", mutate: func(r *Receipt) { r.BaselineHash = "invalid" }},
		{name: "excess grants", mutate: func(r *Receipt) { r.GrantCount = 16385 }},
		{name: "negative denials", mutate: func(r *Receipt) { r.DenialCount = -1 }},
		{name: "missing clock", mutate: func(r *Receipt) { r.CompiledAt = time.Time{} }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			receipt := fixtureReceipt()
			test.mutate(&receipt)
			data, err := json.Marshal(receipt)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := decodeReceipt(data); err == nil {
				t.Fatal("invalid helper receipt accepted")
			}
		})
	}
	for _, status := range []Status{StatusShadow, StatusApplied} {
		t.Run(string(status), func(t *testing.T) {
			receipt := fixtureReceipt()
			receipt.Status = status
			if err := validReceipt(receipt); err != nil {
				t.Fatal(err)
			}
		})
	}
	if err := validReceipt(Receipt{SchemaVersion: 1, Status: StatusRejected, Code: "invalid_request"}); err != nil {
		t.Fatal(err)
	}
	if err := validReceipt(Receipt{SchemaVersion: 1, Status: StatusRejected, Code: "raw error"}); err == nil {
		t.Fatal("arbitrary error text accepted")
	}
}

func TestFrames(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		data []byte
	}{
		{name: "missing header", data: []byte{}},
		{name: "zero length", data: []byte{0, 0, 0, 0}},
		{name: "unbounded length", data: []byte{255, 255, 255, 255}},
		{name: "truncated body", data: []byte{0, 0, 0, 4, 1}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			if _, err := readFrame(bytes.NewReader(test.data), maximumRequest); err == nil {
				t.Fatal("invalid frame accepted")
			}
		})
	}
	var framed bytes.Buffer
	if err := writeFrame(&framed, []byte("{}"), maximumResponse); err != nil {
		t.Fatal(err)
	}
	data, err := readFrame(&framed, maximumResponse)
	if err != nil || string(data) != "{}" {
		t.Fatalf("round trip: %v", err)
	}
	if err := writeFrame(shortWriter{}, []byte("{}"), maximumResponse); !errors.Is(err, io.ErrShortWrite) {
		t.Fatalf("short write: %v", err)
	}
	if err := writeFrame(io.Discard, []byte{}, maximumResponse); err == nil {
		t.Fatal("empty write accepted")
	}
}

type shortWriter struct{}

func (shortWriter) Write([]byte) (int, error) { return 0, nil }

func FuzzRequest(f *testing.F) {
	data, err := encodeRequest(fixtureSnapshot())
	if err != nil {
		f.Fatal(err)
	}
	f.Add(data)
	f.Add([]byte(`{"schema_version":1,"directory":{}}`))
	f.Fuzz(func(t *testing.T, raw []byte) {
		snapshot, err := decodeRequest(raw)
		if err != nil {
			return
		}
		encoded, err := encodeRequest(snapshot)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := decodeRequest(encoded); err != nil {
			t.Fatalf("accepted snapshot cannot round trip: %v", err)
		}
	})
}

func FuzzFrame(f *testing.F) {
	f.Add([]byte{0, 0, 0, 2, '{', '}'})
	f.Add([]byte{255, 255, 255, 255})
	f.Fuzz(func(t *testing.T, data []byte) {
		body, err := readFrame(bytes.NewReader(data), maximumRequest)
		if err == nil && (len(body) > maximumRequest || uint64(len(body)) != uint64(binary.BigEndian.Uint32(data[:4]))) {
			t.Fatal("accepted frame bypassed its allocation bound")
		}
	})
}
