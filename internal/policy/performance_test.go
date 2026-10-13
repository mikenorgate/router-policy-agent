package policy

import (
	"encoding/json"
	"fmt"
	"net/netip"
	"testing"
	"time"

	"github.com/mikenorgate/router-policy-agent/internal/binding"
)

func benchmarkDirectoryInput(b *testing.B, devices int) Input {
	b.Helper()
	placement := `{"schema_version":1,"kind":"placement","vlan_role":"untrusted"}`
	body, err := json.Marshal(map[string]any{"schema_version": 1, "kind": "access",
		"vlan_role": "untrusted", "temporary": false, "rules": []Rule{testRule()}})
	if err != nil {
		b.Fatal(err)
	}
	access := string(body)
	input := Input{
		Now: testNow,
		Directory: DirectorySnapshot{ObservedAt: testNow, Complete: true,
			Groups: []Group{{ID: "placement", Name: "Untrusted", Policy: &placement},
				{ID: "access", Name: "Access", Policy: &access}}, Devices: []Device{}},
		Bindings: binding.Snapshot{SchemaVersion: 1, Generation: "benchmark-bindings", ObservedAt: testNow,
			Complete: true, Records: []binding.Record{}},
	}
	for index := range devices {
		mac := fmt.Sprintf("02:00:00:00:%02x:%02x", index/256, index%256)
		input.Directory.Devices = append(input.Directory.Devices, Device{ID: fmt.Sprintf("device-%d", index),
			MAC: mac, Active: true, GroupIDs: []string{"placement", "access"}})
		input.Bindings.Records = append(input.Bindings.Records, binding.Record{
			MAC: mac, NAS: "benchmark-nas", Interface: "lan13", VLAN: 13, AssociatedAt: testNow,
			AssociationID: fmt.Sprintf("association-%d", index), Addresses: []binding.Address{{
				IP: netip.MustParseAddr(fmt.Sprintf("fdca:1a2b:3::%x", index+1)), Source: "qualified_ipv6",
				OwnershipID: fmt.Sprintf("ownership-%d", index), ObservedAt: testNow, ValidUntil: testNow.Add(time.Hour),
			}},
		})
	}
	return input
}

func benchmarkAliasBaseline(count int) Baseline {
	baseline := testBaseline()
	baseline.NAT46Pools = prefixes("10.250.0.0/16")
	baseline.NAT46 = []NAT46{}
	for index := range count {
		baseline.NAT46 = append(baseline.NAT46, NAT46{ID: fmt.Sprintf("alias-%d", index),
			Alias:  netip.MustParseAddr(fmt.Sprintf("10.250.%d.%d", index/256, index%256)),
			Target: netip.MustParseAddr("fdca:1a2b:2::20"), Ready: true})
	}
	return baseline
}

func benchmarkDisjointGrants(count int) []Grant {
	grants := make([]Grant, 0, count)
	for index := range count {
		network := netip.MustParsePrefix(fmt.Sprintf("fdca:1a2b::%x/128", index+256))
		scope := PeerScope{Real: network, Variants: []netip.Prefix{network}}
		grants = append(grants, Grant{DeviceID: "device", MAC: "02:00:00:00:00:01", Interface: "lan13", VLAN: 13,
			Device: Endpoint{Real: netip.MustParseAddr("fdca:1a2b:3::10"),
				Variants: []netip.Addr{netip.MustParseAddr("fdca:1a2b:3::10")}},
			PeerScope: &scope, Direction: ToDevice, Protocol: "tcp", Port: 80, PortEnd: 80,
			Contributors: []Contributor{{GroupID: "group", RuleID: "rule", ExpiresAt: testNow.Add(time.Minute)}},
		})
	}
	return grants
}

func BenchmarkCompileSharedGroup(b *testing.B) {
	for _, count := range []int{64, 512} {
		b.Run(fmt.Sprintf("devices=%d", count), func(b *testing.B) {
			compiler, err := New(testBaseline())
			if err != nil {
				b.Fatal(err)
			}
			input := benchmarkDirectoryInput(b, count)
			b.ReportAllocs()
			for b.Loop() {
				candidate, err := compiler.CompileContext(b.Context(), input)
				if err != nil || len(candidate.Grants) != count {
					b.Fatalf("unexpected compilation: %v, grants=%d", err, len(candidate.Grants))
				}
			}
		})
	}
}

func BenchmarkResolveScopeSharedNAT46Target(b *testing.B) {
	for _, count := range []int{64, 256} {
		b.Run(fmt.Sprintf("aliases=%d", count), func(b *testing.B) {
			compiler, err := New(benchmarkAliasBaseline(count))
			if err != nil {
				b.Fatal(err)
			}
			network := netip.MustParsePrefix("fdca:1a2b:2::/64")
			b.ReportAllocs()
			for b.Loop() {
				scope := compiler.resolveScope(network)
				if len(scope.Variants) != 1+2*count {
					b.Fatalf("got %d variants, want %d", len(scope.Variants), 1+2*count)
				}
			}
		})
	}
}

func BenchmarkScopeUnionDisjoint(b *testing.B) {
	for _, count := range []int{64, 512} {
		b.Run(fmt.Sprintf("grants=%d", count), func(b *testing.B) {
			compiler, err := New(testBaseline())
			if err != nil {
				b.Fatal(err)
			}
			grants := benchmarkDisjointGrants(count)
			b.ReportAllocs()
			for b.Loop() {
				normalized, err := compiler.normalizeScopeUnion(b.Context(), grants)
				if err != nil || len(normalized) != count {
					b.Fatalf("unexpected union: %v, grants=%d", err, len(normalized))
				}
			}
		})
	}
}
