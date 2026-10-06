package state

import (
	"encoding/json"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/mikenorgate/router-policy-agent/internal/policy"
)

var observed = time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)

func snapshot() policy.DirectorySnapshot {
	return policy.DirectorySnapshot{ObservedAt: observed, Complete: true, Groups: []policy.Group{},
		Devices: []policy.Device{{ID: "synthetic-device", MAC: "02:00:00:00:00:01", Active: true, GroupIDs: []string{}}}}
}

func advanced(t *testing.T) Document {
	t.Helper()
	ledger := Initial().Ledger
	ledger.LastValidated = observed
	ledger.FirstSeen["group/rule"] = observed
	ledger.AliasPeers["group/rule/10.250.0.20/32"] = netip.MustParseAddr("fdca:1a2b:2::20")
	ledger.NetworkGroups["group"] = true
	document, err := Advance(Initial(), snapshot(), ledger)
	if err != nil {
		t.Fatal(err)
	}
	return document
}

func TestDirectoryReplayAndRevocation(t *testing.T) {
	t.Parallel()
	first := advanced(t)
	if _, err := CheckDirectory(first, snapshot()); err != nil {
		t.Fatal(err)
	}
	denial := snapshot()
	denial.ObservedAt = observed.Add(time.Second)
	denial.Devices[0].Active = false
	ledger := first.Ledger
	ledger.LastValidated = denial.ObservedAt
	second, err := Advance(first, denial, ledger)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := CheckDirectory(second, snapshot()); err == nil {
		t.Fatal("older allow restored after newer denial")
	}
	conflict := denial
	conflict.Devices = snapshot().Devices
	if _, err := CheckDirectory(second, conflict); err == nil {
		t.Fatal("conflicting same-time allow accepted")
	}
	removed := policy.DirectorySnapshot{ObservedAt: observed.Add(2 * time.Second), Complete: true,
		Groups: []policy.Group{}, Devices: []policy.Device{}}
	ledger.LastValidated = removed.ObservedAt
	third, err := Advance(second, removed, ledger)
	if err != nil {
		t.Fatal(err)
	}
	if len(third.CohortMACs) != 1 || third.CohortMACs[0] != "02:00:00:00:00:01" {
		t.Fatal("cohort disappeared with account")
	}
}

func TestCheckTransition(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name   string
		mutate func(*Document)
	}{
		{name: "cohort loss", mutate: func(d *Document) { d.CohortMACs = []string{} }},
		{name: "first seen lost", mutate: func(d *Document) { delete(d.Ledger.FirstSeen, "group/rule") }},
		{name: "first seen shifted", mutate: func(d *Document) { d.Ledger.FirstSeen["group/rule"] = observed.Add(-time.Hour) }},
		{name: "alias lost", mutate: func(d *Document) { delete(d.Ledger.AliasPeers, "group/rule/10.250.0.20/32") }},
		{name: "alias retargeted", mutate: func(d *Document) {
			d.Ledger.AliasPeers["group/rule/10.250.0.20/32"] = netip.MustParseAddr("fdca:1a2b:2::21")
		}},
		{name: "network group lost", mutate: func(d *Document) { delete(d.Ledger.NetworkGroups, "group") }},
		{name: "clock rollback", mutate: func(d *Document) { d.Ledger.LastValidated = observed.Add(-time.Second) }},
		{name: "watermark rollback", mutate: func(d *Document) { d.LastDirectoryObservedAt = observed.Add(-time.Second) }},
		{name: "same time different digest", mutate: func(d *Document) { d.DirectoryHash = strings.Repeat("a", 64) }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			previous := advanced(t)
			next, err := Clone(previous)
			if err != nil {
				t.Fatal(err)
			}
			test.mutate(&next)
			if err := CheckTransition(previous, next); err == nil {
				t.Fatal("unsafe transition accepted")
			}
		})
	}
}

func TestDecodeAndClone(t *testing.T) {
	t.Parallel()
	valid, err := json.Marshal(advanced(t))
	if err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name string
		raw  []byte
	}{
		{name: "unknown field", raw: append([]byte(`{"grants":[],`), valid[1:]...)},
		{name: "duplicate key", raw: append([]byte(`{"schema_version":1,`), valid[1:]...)},
		{name: "wrong case", raw: []byte(strings.Replace(string(valid), "schema_version", "Schema_Version", 1))},
		{name: "null cohort", raw: []byte(strings.Replace(string(valid), `["02:00:00:00:00:01"]`, "null", 1))},
		{name: "null ledger map", raw: []byte(strings.Replace(string(valid), `"network_groups":{"group":true}`, `"network_groups":null`, 1))},
		{name: "old schema", raw: []byte(strings.Replace(string(valid), `"schema_version":2`, `"schema_version":1`, 1))},
		{name: "invalid cohort mac", raw: []byte(strings.Replace(string(valid), "02:00:00:00:00:01", "invalid", 1))},
		{name: "uppercase digest", raw: []byte(strings.Replace(string(valid), advanced(t).DirectoryHash,
			strings.ToUpper(advanced(t).DirectoryHash), 1))},
		{name: "oversized input", raw: make([]byte, MaximumSize+1)},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			if _, err := Decode(test.raw); err == nil {
				t.Fatal("invalid state accepted")
			}
		})
	}
	decoded, err := Decode(valid)
	if err != nil {
		t.Fatal(err)
	}
	cloned, err := Clone(decoded)
	if err != nil {
		t.Fatal(err)
	}
	cloned.CohortMACs[0] = "02:00:00:00:00:02"
	delete(cloned.Ledger.FirstSeen, "group/rule")
	if decoded.CohortMACs[0] != "02:00:00:00:00:01" || len(decoded.Ledger.FirstSeen) != 1 {
		t.Fatal("cloned state shares mutable storage")
	}
}

func FuzzDecode(f *testing.F) {
	data, err := json.Marshal(Initial())
	if err != nil {
		f.Fatal(err)
	}
	f.Add(data)
	f.Add([]byte(`{"schema_version":1}`))
	f.Fuzz(func(t *testing.T, raw []byte) {
		document, err := Decode(raw)
		if err != nil {
			return
		}
		encoded, err := json.Marshal(document)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := Decode(encoded); err != nil {
			t.Fatalf("accepted state cannot round trip: %v", err)
		}
	})
}
