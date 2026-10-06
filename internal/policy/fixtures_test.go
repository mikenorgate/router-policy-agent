package policy

import (
	"encoding/json"
	"net/netip"
	"testing"
	"time"

	"github.com/mikenorgate/router-policy-agent/internal/binding"
)

var testNow = time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)

func testBaseline() Baseline {
	return Baseline{
		SchemaVersion: 1, Generation: "synthetic-v1", LeaseSeconds: 90, RefreshSeconds: 30,
		MaximumDevices: 4096, MaximumTuples: 16384,
		Zones: []Zone{
			{Role: Trusted, VLAN: 10, Interfaces: []string{"lan10"}, Networks: prefixes("10.240.0.0/24", "fdca:1a2b:0::/64")},
			{Role: Guest, VLAN: 11, Interfaces: []string{"lan11"}, Networks: prefixes("10.240.1.0/24", "fdca:1a2b:1::/64")},
			{Role: Infrastructure, VLAN: 12, Interfaces: []string{"lan12"}, Networks: prefixes("10.240.2.0/24", "fdca:1a2b:2::/64")},
			{Role: Untrusted, VLAN: 13, Interfaces: []string{"lan13"}, Networks: prefixes("10.240.3.0/24", "fdca:1a2b:3::/64")},
			{Role: Security, VLAN: 14, Interfaces: []string{"lan14"}, Networks: prefixes("10.240.4.0/24", "fdca:1a2b:4::/64")},
			{Role: Assessment, VLAN: 15, Interfaces: []string{"lan15"}, Networks: prefixes("10.240.5.0/24", "fdca:1a2b:5::/64")},
		},
		ProtectedNetworks: []NetworkBlock{
			{ProtectionID: "P01", Networks: prefixes("10.241.0.0/24"), Roles: []Role{}},
			{ProtectionID: "P03", Networks: prefixes("10.240.2.200/32"), Roles: []Role{}},
		},
		ProtectedEndpoints: []EndpointBlock{
			{ProtectionID: "P02", Networks: prefixes("10.240.2.254/32"), Protocol: "tcp", Ports: []uint16{22, 443}, DestinationOnly: true},
		},
		RetainedBlocks: []NetworkBlock{},
		NAT64: []NAT64{
			{ID: "global64", Prefix: netip.MustParsePrefix("64:ff9b::/96"), Scope: "global"},
			{ID: "private64", Prefix: netip.MustParsePrefix("fdca:1a2b:64::/96"), Scope: "private"},
		},
		NAT46: []NAT46{
			{ID: "app46", Alias: netip.MustParseAddr("10.250.0.20"), Target: netip.MustParseAddr("fdca:1a2b:2::20"), Ready: true},
			{ID: "security46", Alias: netip.MustParseAddr("10.250.0.40"), Target: netip.MustParseAddr("fdca:1a2b:4::40"), Ready: true},
		},
		NAT46Pools: prefixes("10.250.0.0/24"),
	}
}

func prefixes(raw ...string) []netip.Prefix {
	result := make([]netip.Prefix, 0, len(raw))
	for _, value := range raw {
		result = append(result, netip.MustParsePrefix(value))
	}
	return result
}

func testRule() Rule {
	return Rule{ID: "device-api", Direction: ToDevice, Peer: Peer{Addresses: []string{"fdca:1a2b::10/128"}},
		Protocol: "tcp", DestinationPorts: []uint16{6053}, Reason: "synthetic controller"}
}

func accessGroup(t *testing.T, id string, temporary bool, rules ...Rule) Group {
	t.Helper()
	// Explicit false is required on the wire, even though Document omits it.
	data, err := json.Marshal(map[string]any{"schema_version": 1, "kind": "access",
		"vlan_role": "untrusted", "temporary": temporary, "rules": rules})
	if err != nil {
		t.Fatal(err)
	}
	raw := string(data)
	return Group{ID: id, Name: "synthetic " + id, Policy: &raw, IsNetwork: true}
}

func testInput(t *testing.T) Input {
	t.Helper()
	placement := `{"schema_version":1,"kind":"placement","vlan_role":"untrusted"}`
	return Input{
		Now: testNow,
		Directory: DirectorySnapshot{ObservedAt: testNow, Complete: true,
			Groups: []Group{{ID: "placement", Name: "Untrusted", Policy: &placement, IsNetwork: true},
				accessGroup(t, "access", false, testRule())},
			Devices: []Device{{ID: "synthetic-device", MAC: "02:00:00:00:00:01", Active: true,
				GroupIDs: []string{"placement", "access"}}},
		},
		Bindings: binding.Snapshot{SchemaVersion: 1, Generation: "binding-v1", ObservedAt: testNow, Complete: true,
			Records: []binding.Record{{MAC: "02:00:00:00:00:01", NAS: "synthetic-nas", Interface: "lan13",
				VLAN: 13, AssociatedAt: testNow, AssociationID: "association-v1", Addresses: []binding.Address{
					{IP: netip.MustParseAddr("fdca:1a2b:3::10"), Source: "qualified_ipv6", OwnershipID: "lease-v1",
						ObservedAt: testNow, ValidUntil: testNow.Add(time.Hour)},
				}}},
		},
	}
}

func testCompiler(t *testing.T, baseline Baseline) *Compiler {
	t.Helper()
	compiler, err := New(baseline)
	if err != nil {
		t.Fatal(err)
	}
	return compiler
}
