package policy

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"slices"
	"testing"
	"time"
)

func scopeInput(t *testing.T, rules ...Rule) Input {
	t.Helper()
	input := testInput(t)
	input.Directory.Groups[1] = scopeGroup(t, "access", false, rules...)
	return input
}

func compileScopes(t *testing.T, baseline Baseline, input Input) Candidate {
	t.Helper()
	compiler := testCompiler(t, baseline)
	candidate, err := compiler.CompileContext(t.Context(), input)
	if err != nil || len(candidate.Denials) != 0 || len(candidate.Grants) == 0 {
		t.Fatalf("scope compile failed: %v, denials=%+v, grants=%d", err, candidate.Denials, len(candidate.Grants))
	}
	if err := compiler.CheckCandidate(t.Context(), candidate); err != nil {
		t.Fatalf("compiler produced invalid scope: %v", err)
	}
	return candidate
}

func scopePermits(candidate Candidate, peer string, port uint16) bool {
	address := netip.MustParseAddr(peer)
	for _, grant := range candidate.Grants {
		if grant.PeerScope != nil && grant.PeerScope.Real.Contains(address) && grant.Port <= port && grant.PortEnd >= port {
			return true
		}
	}
	return false
}

func scopeRepresents(candidate Candidate, peer string, port uint16) bool {
	address := netip.MustParseAddr(peer)
	for _, grant := range candidate.Grants {
		if grant.PeerScope == nil || grant.Port > port || grant.PortEnd < port {
			continue
		}
		for _, variant := range grant.PeerScope.Variants {
			if variant.Contains(address) {
				return true
			}
		}
	}
	return false
}

func TestScopeInfrastructureFloorAndCounterparts(t *testing.T) {
	t.Parallel()
	rule := testRule()
	rule.Direction, rule.Peer = FromDevice, Peer{Zones: []Role{Infrastructure}}
	rule.DestinationPorts, rule.AllDestinationPorts = nil, true
	candidate := compileScopes(t, testBaseline(), scopeInput(t, rule))
	cases := []struct {
		peer string
		port uint16
		ok   bool
	}{
		{peer: "10.240.2.10", port: 80, ok: true},
		{peer: "10.240.2.254", port: 80, ok: true},
		{peer: "10.240.2.254", port: 22},
		{peer: "10.240.2.254", port: 443},
		{peer: "10.240.2.200", port: 80},
		{peer: "10.240.2.0", port: 80},
		{peer: "10.240.2.255", port: 80},
		{peer: "10.240.2.10", port: 53},
		{peer: "10.240.2.10", port: 123, ok: true},
		{peer: "10.240.4.10", port: 80},
		{peer: "10.240.3.10", port: 80},
		{peer: "fdca:1a2b:2::20", port: 443, ok: true},
		{peer: "fdca:1a2b:2::21", port: 65535, ok: true},
	}
	for _, test := range cases {
		if got := scopePermits(candidate, test.peer, test.port); got != test.ok {
			t.Errorf("scope %s:%d = %v, want %v", test.peer, test.port, got, test.ok)
		}
	}
	for _, peer := range []string{"10.250.0.20", "fdca:1a2b:64::afa:14", "fdca:1a2b:64::af0:20a"} {
		if !scopeRepresents(candidate, peer, 80) {
			t.Errorf("missing installed counterpart %s", peer)
		}
	}
	for _, peer := range []string{"10.250.0.40", "10.250.0.99", "fdca:1a2b:64::afa:28", "64:ff9b::af0:20a"} {
		if scopeRepresents(candidate, peer, 80) {
			t.Errorf("unauthorized counterpart %s", peer)
		}
	}
	if len(candidate.Grants) > 512 {
		t.Fatal("scope was expanded into individual hosts or ports")
	}
}

func TestScopeInternetIsNotInternalGUAOrPrivateAlias(t *testing.T) {
	t.Parallel()
	baseline := testBaseline()
	baseline.Zones[0].Networks = append(baseline.Zones[0].Networks, netip.MustParsePrefix("2a01:4f8:100::/64"))
	baseline.ProtectedEndpoints = append(baseline.ProtectedEndpoints, EndpointBlock{
		ProtectionID: "P02", Networks: prefixes("2a01:4f8:200::22/128"), Protocol: "tcp", Ports: []uint16{22},
	})
	rule := testRule()
	rule.Direction, rule.Peer = FromDevice, Peer{Internet: true}
	rule.DestinationPorts, rule.AllDestinationPorts = nil, true
	for _, protocol := range []string{"tcp", "udp"} {
		rule.Protocol = protocol
		candidate := compileScopes(t, baseline, scopeInput(t, rule))
		for _, peer := range []string{"9.9.9.9", "1.1.1.1", "2606:4700:4700::1111"} {
			if !scopePermits(candidate, peer, 443) {
				t.Errorf("missing public %s grant for %s", protocol, peer)
			}
		}
		for _, peer := range []string{"2a01:4f8:100::10", "2a01:4f8:200::22", "10.240.2.20", "192.168.1.1",
			"100.64.0.1", "192.0.2.1", "198.18.0.1", "2001:db8::1", "3fff::1", "2002:a01:101::1",
			"fdca:1a2b:2::20", "10.250.0.20", "fdca:1a2b:64::afa:14"} {
			if scopeRepresents(candidate, peer, 443) {
				t.Errorf("Internet admitted internal/special/alias %s", peer)
			}
		}
		if !scopeRepresents(candidate, "64:ff9b::909:909", 443) {
			t.Error("public NAT64 counterpart missing")
		}
		if scopePermits(candidate, "9.9.9.9", 53) || scopePermits(candidate, "9.9.9.9", 123) != (protocol == "tcp") {
			t.Error("Internet bypassed router-owned DNS/NTP baseline")
		}
		if len(candidate.Grants) > 1024 {
			t.Fatal("Internet was expanded into hosts or ports")
		}
	}
}

func TestScopeBothDirectionsAndUnregisteredCIDR(t *testing.T) {
	t.Parallel()
	for _, direction := range []Direction{FromDevice, ToDevice} {
		rule := testRule()
		rule.Direction = direction
		rule.Peer = Peer{Addresses: []string{"10.240.0.0/16", "fdca:1a2b::/32"}}
		rule.DestinationPorts = []uint16{80, 443}
		candidate := compileScopes(t, testBaseline(), scopeInput(t, rule))
		for _, peer := range []string{"10.240.0.10", "fdca:1a2b::99", "10.240.2.10", "fdca:1a2b:2::99"} {
			if !scopePermits(candidate, peer, 80) || scopePermits(candidate, peer, 81) {
				t.Errorf("generic CIDR/port selection wrong for %s in %s", peer, direction)
			}
		}
		for _, peer := range []string{"10.240.1.10", "10.240.3.10", "10.240.4.10", "10.240.5.10", "10.240.8.10",
			"fdca:1a2b:1::10", "fdca:1a2b:4::10", "fdca:1a2b:5::10", "fdca:1a2b:8::10"} {
			if scopePermits(candidate, peer, 80) {
				t.Errorf("broad CIDR bypassed isolation for %s", peer)
			}
		}
	}
}

func TestScopeProtectedDestinationDoesNotBlockControllerSource(t *testing.T) {
	t.Parallel()
	rule := testRule()
	rule.Peer, rule.DestinationPorts = Peer{Zones: []Role{Infrastructure}}, []uint16{443}
	candidate := compileScopes(t, testBaseline(), scopeInput(t, rule))
	if !scopePermits(candidate, "10.240.2.254", 443) {
		t.Fatal("source controller administration ports confused with device listener")
	}
	baseline := testBaseline()
	baseline.ProtectedEndpoints = append(baseline.ProtectedEndpoints, EndpointBlock{
		ProtectionID: "P02", Networks: prefixes("fdca:1a2b:3::10/128"), Protocol: "tcp", Ports: []uint16{443}, DestinationOnly: true,
	})
	candidate, err := testCompiler(t, baseline).Compile(scopeInput(t, rule))
	if err != nil || len(candidate.Grants) != 0 || len(candidate.Denials) != 1 {
		t.Fatalf("protected device listener admitted: %v %+v", err, candidate.Denials)
	}
}

func TestScopeGroupUnionRevocationAndIndependentDeadlines(t *testing.T) {
	t.Parallel()
	rule := testRule()
	rule.Peer = Peer{Zones: []Role{Trusted}}
	rule.DestinationPorts = nil
	rule.DestinationPortRanges = []PortRange{{First: 8000, Last: 8010}}
	input := scopeInput(t, rule)
	other := rule
	expiry := testNow.Add(20 * time.Second)
	other.ExpiresAt = &expiry
	input.Directory.Groups = append(input.Directory.Groups, scopeGroup(t, "another-arbitrary-group", true, other))
	input.Directory.Devices[0].GroupIDs = append(input.Directory.Devices[0].GroupIDs, "another-arbitrary-group")
	candidate := compileScopes(t, testBaseline(), input)
	for _, grant := range candidate.Grants {
		if len(grant.Contributors) != 2 || grant.ExpiresAt() != testNow.Add(90*time.Second) {
			t.Fatal("group union lost independent contributor deadlines")
		}
	}
	input.Directory.Devices[0].GroupIDs = []string{"placement", "another-arbitrary-group"}
	input.Ledger = candidate.Ledger
	candidate = compileScopes(t, testBaseline(), input)
	for _, grant := range candidate.Grants {
		if len(grant.Contributors) != 1 || grant.ExpiresAt() != expiry {
			t.Fatal("membership removal did not withdraw only its contribution")
		}
	}
}

func TestScopeCandidateTamperingAndSnapshotIsolation(t *testing.T) {
	t.Parallel()
	rule := testRule()
	rule.Peer = Peer{Zones: []Role{Trusted}}
	input := scopeInput(t, rule)
	compiler := testCompiler(t, testBaseline())
	authorization, err := compiler.CompileAuthorization(t.Context(), input, CaptureAge())
	if err != nil {
		t.Fatal(err)
	}
	mutations := []func(*Grant){
		func(grant *Grant) { grant.PeerScope.Real = netip.MustParsePrefix("fdca:1a2b:4::/64") },
		func(grant *Grant) {
			grant.PeerScope.Variants = append(grant.PeerScope.Variants, netip.MustParsePrefix("fdca:1a2b:4::/64"))
		},
		func(grant *Grant) { grant.Port, grant.PortEnd = 53, 53 },
		func(grant *Grant) { grant.PortEnd = 0 },
		func(grant *Grant) { grant.Peer.Real = netip.MustParseAddr("9.9.9.9") },
		func(grant *Grant) { grant.Contributors[0].ExpiresAt = testNow.Add(time.Hour) },
	}
	for _, mutate := range mutations {
		snapshot, err := authorization.Snapshot(t.Context())
		if err != nil || len(snapshot.Grants) == 0 {
			t.Fatalf("snapshot failed: %v", err)
		}
		mutate(&snapshot.Grants[0])
		if err := compiler.CheckCandidate(t.Context(), snapshot); err == nil {
			t.Fatal("tampered scoped candidate accepted")
		}
		fresh, err := authorization.Snapshot(t.Context())
		if err != nil || compiler.CheckCandidate(t.Context(), fresh) != nil {
			t.Fatal("editable diagnostic snapshot mutated the private authorization")
		}
	}
}

func TestScopeAliasAnchoringAndForbiddenSelectors(t *testing.T) {
	t.Parallel()
	rule := testRule()
	rule.Direction = FromDevice
	for _, peer := range []Peer{{Zones: []Role{Security}}, {Zones: []Role{Assessment}}, {Zones: []Role{Untrusted}},
		{Addresses: []string{"fdca:1a2b:64::/96"}}, {Addresses: []string{"10.250.0.0/24"}}} {
		rule.Peer = peer
		candidate, err := testCompiler(t, testBaseline()).Compile(scopeInput(t, rule))
		if err != nil || len(candidate.Grants) != 0 || len(candidate.Denials) != 1 {
			t.Fatalf("forbidden selector admitted: %v %+v", err, peer)
		}
	}
	rule.Peer = Peer{Addresses: []string{"10.250.0.20/32"}}
	input := scopeInput(t, rule)
	candidate := compileScopes(t, testBaseline(), input)
	input.Ledger = candidate.Ledger
	baseline := testBaseline()
	baseline.NAT46[0].Target = netip.MustParseAddr("fdca:1a2b:2::21")
	candidate, err := testCompiler(t, baseline).Compile(input)
	if err != nil || len(candidate.Grants) != 0 || len(candidate.Denials) != 1 || candidate.Denials[0].Code != "unready_or_changed_alias" {
		t.Fatalf("alias retarget silently lent permission: %v %+v", err, candidate.Denials)
	}
}

func TestScopeQuotaAndStaleAddress(t *testing.T) {
	t.Parallel()
	rule := testRule()
	rule.Direction, rule.Peer = FromDevice, Peer{Internet: true}
	rule.DestinationPorts, rule.AllDestinationPorts = nil, true
	input := scopeInput(t, rule)
	baseline := testBaseline()
	baseline.MaximumTuples = 1
	if _, err := testCompiler(t, baseline).Compile(input); err == nil {
		t.Fatal("scoped expansion ignored quota")
	}
	input.Bindings.Records[0].Addresses[0].ObservedAt = testNow.Add(-91 * time.Second)
	if _, err := testCompiler(t, testBaseline()).Compile(input); err == nil {
		t.Fatal("stale address authorized a generic scope")
	}
}

func TestPrefixSubtractionDoesNotEnumerateHosts(t *testing.T) {
	t.Parallel()
	network := netip.MustParsePrefix("fdca:1a2b::/64")
	denied := netip.MustParsePrefix("fdca:1a2b::abcd/128")
	remaining := subtractPrefix(network, denied)
	if len(remaining) != 64 {
		t.Fatalf("subtracting one IPv6 host used %d fragments, want 64", len(remaining))
	}
	for first, prefix := range remaining {
		if prefix.Overlaps(denied) || !network.Contains(prefix.Addr()) {
			t.Fatal("subtraction widened or retained the denied host")
		}
		for _, other := range remaining[first+1:] {
			if prefix.Overlaps(other) {
				t.Fatal("subtraction produced overlapping fragments")
			}
		}
	}
	if !slices.Equal(subtractPrefix(network, network), []netip.Prefix(nil)) {
		t.Fatal("subtracting the entire prefix retained addresses")
	}
}

func TestScopeCutoutsAgreeWithExactFloor(t *testing.T) {
	t.Parallel()
	baseline := testBaseline()
	baseline.RetainedBlocks = []NetworkBlock{{ProtectionID: "P08", Networks: prefixes("10.240.2.128/28"),
		Roles: []Role{Untrusted}, SourceMAC: "02:00:00:00:00:01"}}
	compiler := testCompiler(t, baseline)
	for _, direction := range []Direction{ToDevice, FromDevice} {
		for _, protocol := range []string{"tcp", "udp"} {
			rule := testRule()
			rule.Direction, rule.Protocol, rule.Peer = direction, protocol, Peer{Zones: []Role{Infrastructure}}
			rule.DestinationPorts, rule.AllDestinationPorts = nil, true
			candidate := compileScopes(t, baseline, scopeInput(t, rule))
			for last := range 256 {
				peer := fmt.Sprintf("10.240.2.%d", last)
				for _, port := range []uint16{1, 21, 22, 23, 52, 53, 54, 80, 122, 123, 124, 442, 443, 444, 65535} {
					code := compiler.floor(floorFlow{mac: "02:00:00:00:00:01", placement: Untrusted,
						device: netip.MustParseAddr("fdca:1a2b:3::10"), peer: netip.MustParseAddr(peer), port: port, rule: rule})
					if got := scopePermits(candidate, peer, port); got != (code == "") {
						t.Fatalf("scope differs from exact floor for %s %s %s:%d: allowed=%v code=%s", direction, protocol, peer, port, got, code)
					}
				}
			}
		}
	}
}

func TestScopeBindingExpiryAndCancellation(t *testing.T) {
	t.Parallel()
	rule := testRule()
	rule.Peer = Peer{Zones: []Role{Trusted}}
	input := scopeInput(t, rule)
	input.Bindings.Records[0].Addresses[0].ValidUntil = testNow.Add(12 * time.Second)
	candidate := compileScopes(t, testBaseline(), input)
	for _, grant := range candidate.Grants {
		if grant.ExpiresAt() != testNow.Add(12*time.Second) {
			t.Fatal("generic scope extended the underlying address lease")
		}
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	compiler := testCompiler(t, testBaseline())
	if _, err := compiler.CompileContext(ctx, input); !errors.Is(err, context.Canceled) {
		t.Fatalf("scope compile ignored cancellation: %v", err)
	}
	if err := compiler.CheckCandidate(ctx, candidate); !errors.Is(err, context.Canceled) {
		t.Fatalf("scope checker ignored cancellation: %v", err)
	}
}

func FuzzScopeGroup(f *testing.F) {
	f.Add(`{"schema_version":2,"kind":"access","vlan_role":"untrusted","temporary":false,"rules":[{"id":"internet","direction":"from_device","peer":{"internet":true},"protocol":"tcp","all_destination_ports":true,"reason":"synthetic"}]}`)
	f.Fuzz(func(t *testing.T, raw string) {
		if len(raw) > AttributeLimit+1 {
			return
		}
		document, err := ParseGroup(raw)
		if err != nil {
			return
		}
		encoded, err := json.Marshal(document)
		if err != nil || len(encoded) == 0 {
			t.Fatal("validated schema could not be encoded")
		}
	})
}
