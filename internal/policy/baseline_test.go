package policy

import (
	"encoding/json"
	"net/netip"
	"strconv"
	"testing"
)

func TestInvalidBaselines(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name   string
		mutate func(*Baseline)
	}{
		{name: "schema", mutate: func(b *Baseline) { b.SchemaVersion = 2 }},
		{name: "generation", mutate: func(b *Baseline) { b.Generation = "bad\nvalue" }},
		{name: "long lease", mutate: func(b *Baseline) { b.LeaseSeconds = 91 }},
		{name: "bad refresh", mutate: func(b *Baseline) { b.RefreshSeconds = 90 }},
		{name: "too many devices", mutate: func(b *Baseline) { b.MaximumDevices = 4097 }},
		{name: "too many tuples", mutate: func(b *Baseline) { b.MaximumTuples = 16385 }},
		{name: "missing role", mutate: func(b *Baseline) { b.Zones = b.Zones[:5] }},
		{name: "duplicate role", mutate: func(b *Baseline) { b.Zones[1].Role = Trusted }},
		{name: "duplicate vlan", mutate: func(b *Baseline) { b.Zones[1].VLAN = 10 }},
		{name: "invalid vlan", mutate: func(b *Baseline) { b.Zones[1].VLAN = 4095 }},
		{name: "no interface", mutate: func(b *Baseline) { b.Zones[1].Interfaces = nil }},
		{name: "duplicate interface", mutate: func(b *Baseline) { b.Zones[1].Interfaces = []string{"lan10"} }},
		{name: "unsafe interface", mutate: func(b *Baseline) { b.Zones[1].Interfaces = []string{"lan;drop"} }},
		{name: "overlapping ownership", mutate: func(b *Baseline) { b.Zones[1].Networks = b.Zones[0].Networks }},
		{name: "host bits in zone", mutate: func(b *Baseline) { b.Zones[1].Networks = prefixes("10.240.1.1/24") }},
		{name: "default zone", mutate: func(b *Baseline) { b.Zones[1].Networks = prefixes("0.0.0.0/0") }},
		{name: "missing protected catalog", mutate: func(b *Baseline) { b.ProtectedNetworks = nil }},
		{name: "missing OOB catalog", mutate: func(b *Baseline) { b.ProtectedNetworks = b.ProtectedNetworks[1:] }},
		{name: "unknown protection", mutate: func(b *Baseline) { b.ProtectedNetworks[0].ProtectionID = "P100" }},
		{name: "conditional protected block", mutate: func(b *Baseline) { b.ProtectedNetworks[0].Roles = []Role{Guest} }},
		{name: "conditional retained entry cannot replace OOB floor", mutate: func(b *Baseline) {
			b.RetainedBlocks = append(b.RetainedBlocks, b.ProtectedNetworks[0])
			b.RetainedBlocks[0].Roles = []Role{Guest}
			b.ProtectedNetworks = b.ProtectedNetworks[1:]
		}},
		{name: "invalid retained MAC", mutate: func(b *Baseline) {
			b.RetainedBlocks = []NetworkBlock{{ProtectionID: "P08", Networks: prefixes("10.241.1.0/24"), SourceMAC: "invalid"}}
		}},
		{name: "unknown retained role", mutate: func(b *Baseline) {
			b.RetainedBlocks = []NetworkBlock{{ProtectionID: "P08", Networks: prefixes("10.241.1.0/24"), Roles: []Role{Unknown}}}
		}},
		{name: "protected protocol", mutate: func(b *Baseline) { b.ProtectedEndpoints[0].Protocol = "all" }},
		{name: "protected port zero", mutate: func(b *Baseline) { b.ProtectedEndpoints[0].Ports = []uint16{0} }},
		{name: "duplicate translator", mutate: func(b *Baseline) { b.NAT64 = append(b.NAT64, b.NAT64[0]) }},
		{name: "wrong prefix length", mutate: func(b *Baseline) { b.NAT64[1].Prefix = netip.MustParsePrefix("fdca:1a2b:64::/64") }},
		{name: "IPv6 alias pool", mutate: func(b *Baseline) { b.NAT46Pools = prefixes("fdca:1a2b:2::/64") }},
		{name: "alias outside pool", mutate: func(b *Baseline) { b.NAT46[0].Alias = netip.MustParseAddr("10.251.0.20") }},
		{name: "duplicate alias", mutate: func(b *Baseline) { b.NAT46[1].Alias = b.NAT46[0].Alias }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			baseline := testBaseline()
			test.mutate(&baseline)
			if _, err := New(baseline); err == nil {
				t.Fatal("invalid baseline accepted")
			}
		})
	}
}

func TestDecodeBaselineRequiresExplicitArrays(t *testing.T) {
	t.Parallel()
	data, err := json.Marshal(testBaseline())
	if err != nil {
		t.Fatal(err)
	}
	object := map[string]json.RawMessage{}
	if err := json.Unmarshal(data, &object); err != nil {
		t.Fatal(err)
	}
	delete(object, "retained_blocks")
	data, err = json.Marshal(object)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := DecodeBaseline(data); err == nil {
		t.Fatal("omitted retained blocks treated as reviewed empty list")
	}
}

func TestLedgerQuota(t *testing.T) {
	t.Parallel()
	ledger := Ledger{NetworkGroups: map[string]bool{}}
	for index := range maximumLedgerEntries + 1 {
		ledger.NetworkGroups[strconv.Itoa(index)] = true
	}
	if _, err := copyLedger(ledger); err == nil {
		t.Fatal("overlarge ledger accepted")
	}
}

func TestProtectedDestinationDevice(t *testing.T) {
	t.Parallel()
	baseline := testBaseline()
	baseline.ProtectedEndpoints = append(baseline.ProtectedEndpoints, EndpointBlock{
		ProtectionID: "P02", Networks: prefixes("fdca:1a2b:3::10/128"),
		Protocol: "tcp", Ports: []uint16{6053}, DestinationOnly: true,
	})
	candidate, err := testCompiler(t, baseline).Compile(testInput(t))
	if err != nil || len(candidate.Grants) != 0 || candidate.Denials[0].Code != "P02_protected_endpoint" {
		t.Fatalf("protected device listener bypassed floor: %+v, %v", candidate, err)
	}
}
