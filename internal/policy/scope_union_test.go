package policy

import (
	"net/netip"
	"testing"
	"time"
)

func TestScopeOverlappingCIDRsAndPortRangesPreserveContributors(t *testing.T) {
	t.Parallel()
	rule := testRule()
	rule.Peer, rule.DestinationPorts = Peer{Addresses: []string{"fdca:1a2b::/64"}}, nil
	rule.DestinationPortRanges = []PortRange{{First: 8000, Last: 8010}}
	input := scopeInput(t, rule)
	other := rule
	other.Peer = Peer{Addresses: []string{"fdca:1a2b::/120"}}
	other.DestinationPortRanges = []PortRange{{First: 8005, Last: 8015}}
	expiry := testNow.Add(20 * time.Second)
	other.ExpiresAt = &expiry
	input.Directory.Groups = append(input.Directory.Groups, scopeGroup(t, "overlap", true, other))
	input.Directory.Devices[0].GroupIDs = append(input.Directory.Devices[0].GroupIDs, "overlap")
	candidate := compileScopes(t, testBaseline(), input)
	for first, grant := range candidate.Grants {
		for _, other := range candidate.Grants[first+1:] {
			if grant.Device.Real == other.Device.Real && grant.Direction == other.Direction && grant.Protocol == other.Protocol &&
				grant.PeerScope.Real.Overlaps(other.PeerScope.Real) && grant.Port <= other.PortEnd && other.Port <= grant.PortEnd {
				t.Fatal("scope union left overlapping flow rectangles")
			}
		}
	}
	cases := []struct {
		peer         string
		port         uint16
		contributors int
		seconds      int
	}{
		{peer: "fdca:1a2b::10", port: 8002, contributors: 1, seconds: 90},
		{peer: "fdca:1a2b::10", port: 8008, contributors: 2, seconds: 90},
		{peer: "fdca:1a2b::10", port: 8013, contributors: 1, seconds: 20},
		{peer: "fdca:1a2b::1010", port: 8008, contributors: 1, seconds: 90},
		{peer: "fdca:1a2b::1010", port: 8013},
	}
	for _, test := range cases {
		matches := 0
		for _, grant := range candidate.Grants {
			if !grant.PeerScope.Real.Contains(netip.MustParseAddr(test.peer)) || grant.Port > test.port || grant.PortEnd < test.port {
				continue
			}
			matches++
			if len(grant.Contributors) != test.contributors || grant.ExpiresAt() != testNow.Add(time.Duration(test.seconds)*time.Second) {
				t.Errorf("wrong provenance/deadline for %s:%d", test.peer, test.port)
			}
		}
		want := 1
		if test.contributors == 0 {
			want = 0
		}
		if matches != want {
			t.Errorf("%s:%d matched %d rectangles, want %d", test.peer, test.port, matches, want)
		}
	}
	// Removing the broad group leaves only the smaller short-lived rectangle.
	input.Directory.Devices[0].GroupIDs = []string{"placement", "overlap"}
	input.Ledger = candidate.Ledger
	candidate = compileScopes(t, testBaseline(), input)
	if scopePermits(candidate, "fdca:1a2b::1010", 8008) || scopePermits(candidate, "fdca:1a2b::10", 8002) ||
		!scopePermits(candidate, "fdca:1a2b::10", 8013) {
		t.Fatal("membership revocation retained the removed CIDR or ports")
	}
}

func TestScopeUnionWithLegacyExactHost(t *testing.T) {
	t.Parallel()
	rule := testRule()
	rule.Peer = Peer{Addresses: []string{"fdca:1a2b::/64"}}
	input := scopeInput(t, rule)
	input.Directory.Groups = append(input.Directory.Groups, accessGroup(t, "legacy", false, testRule()))
	input.Directory.Devices[0].GroupIDs = append(input.Directory.Devices[0].GroupIDs, "legacy")
	candidate := compileScopes(t, testBaseline(), input)
	matched := 0
	for _, grant := range candidate.Grants {
		if grant.PeerScope.Real.Contains(netip.MustParseAddr("fdca:1a2b::10")) {
			matched++
			if len(grant.Contributors) != 2 || !grant.PeerScope.Real.IsSingleIP() {
				t.Fatal("legacy exact rule was not combined with the generic grant")
			}
		}
	}
	if matched != 1 {
		t.Fatalf("legacy host matched %d flow rectangles", matched)
	}
}
