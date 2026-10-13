package policy

import (
	"fmt"
	"net/netip"
	"slices"
	"testing"
	"time"
)

func internetRule() Rule {
	return Rule{ID: "internet", Direction: FromDevice, Peer: Peer{Internet: true}, Protocol: "tcp",
		AllDestinationPorts: true, Reason: "Synthetic Internet permission"}
}

func internetPermits(compiler *Compiler, candidate Candidate, raw string, port uint16) bool {
	address := netip.MustParseAddr(raw)
	geometry := compiler.InternetGeometry()
	if !inPrefixes(address, geometry.Allowed) || inPrefixes(address, geometry.Excluded) {
		return false
	}
	for _, grant := range candidate.Grants {
		if !grant.Internet || grant.Port > port || grant.PortEnd < port {
			continue
		}
		blocked := false
		for _, block := range geometry.Blocks {
			matchesRole := len(block.Roles) == 0 || slices.Contains(block.Roles, Untrusted)
			matchesMAC := block.SourceMAC == "" || block.SourceMAC == grant.MAC
			blocked = blocked || matchesRole && matchesMAC && inPrefixes(address, block.Networks)
		}
		if !blocked {
			return true
		}
	}
	return false
}

func TestInternetGrantCountDoesNotGrowWithProtectedPrefixes(t *testing.T) {
	t.Parallel()
	baseline := testBaseline()
	for index := range 256 {
		baseline.ProtectedEndpoints = append(baseline.ProtectedEndpoints, EndpointBlock{
			ProtectionID: "P02", Protocol: "tcp", Ports: []uint16{443},
			Networks: prefixes(fmt.Sprintf("2a01:4f8:%x::10/128", index)),
		})
	}
	for _, test := range []struct {
		name     string
		protocol string
		count    int
	}{
		{name: "tcp", protocol: "tcp", count: 2},
		{name: "udp", protocol: "udp", count: 3},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			rule := internetRule()
			rule.Protocol = test.protocol
			candidate := compileScopes(t, baseline, scopeInput(t, rule))
			if len(candidate.Grants) != test.count {
				t.Fatalf("got %d grants, want %d", len(candidate.Grants), test.count)
			}
			for _, grant := range candidate.Grants {
				if !grant.Internet || grant.PeerScope != nil || grant.Peer.Real.IsValid() || len(grant.Peer.Variants) != 0 {
					t.Fatal("Internet geometry was expanded into individual peer grants")
				}
			}
		})
	}
}

func TestInternetSharedGeometryHasIndependentCapacityBound(t *testing.T) {
	t.Parallel()
	baseline := testBaseline()
	for block := range 65 {
		networks := make([]netip.Prefix, 0, 256)
		for host := range 256 {
			networks = append(networks, netip.MustParsePrefix(fmt.Sprintf("2a01:4f8:%x::%x/128", block, host)))
		}
		baseline.ProtectedEndpoints = append(baseline.ProtectedEndpoints, EndpointBlock{
			ProtectionID: "P02", Protocol: "tcp", Ports: []uint16{443}, Networks: networks,
		})
	}
	if _, err := New(baseline); err == nil {
		t.Fatal("oversized shared Internet geometry admitted")
	}
}

func TestInternetGeometryPreservesNativeAndTranslatedExclusions(t *testing.T) {
	t.Parallel()
	baseline := testBaseline()
	baseline.ProtectedEndpoints = append(baseline.ProtectedEndpoints, EndpointBlock{
		ProtectionID: "P02", Networks: prefixes("9.9.9.9/32"), Protocol: "tcp", Ports: []uint16{22},
	})
	baseline.NAT64 = append(baseline.NAT64, NAT64{
		ID: "global-in-zone", Prefix: netip.MustParsePrefix("fdca:1a2b:0::/96"), Scope: "global",
	})
	compiler := testCompiler(t, baseline)
	candidate := compileScopes(t, baseline, scopeInput(t, internetRule()))
	for _, test := range []struct {
		name string
		peer string
		want bool
	}{
		{name: "native public", peer: "1.1.1.1", want: true},
		{name: "public IPv6", peer: "2606:4700:4700::1111", want: true},
		{name: "NAT64 public", peer: "64:ff9b::101:101", want: true},
		{name: "global translator nested in zone", peer: "fdca:1a2b::101:101", want: true},
		{name: "protected public host", peer: "9.9.9.9"},
		{name: "protected public counterpart", peer: "64:ff9b::909:909"},
		{name: "private counterpart", peer: "64:ff9b::a00:1"},
		{name: "private translator", peer: "fdca:1a2b:64::a00:1"},
		{name: "special counterpart", peer: "64:ff9b::c000:201"},
		{name: "alias pool counterpart", peer: "64:ff9b::afa:14"},
		{name: "IPv6 outside public space", peer: "4000::1"},
	} {
		t.Run(test.name, func(t *testing.T) {
			if got := internetPermits(compiler, candidate, test.peer, 443); got != test.want {
				t.Fatalf("Internet permission for %s=%t, want %t", test.peer, got, test.want)
			}
		})
	}
}

func TestInternetRetainedBlocksPreserveRoleMACAndCounterparts(t *testing.T) {
	t.Parallel()
	baseline := testBaseline()
	baseline.RetainedBlocks = []NetworkBlock{
		{ProtectionID: "P08", Networks: prefixes("9.9.9.0/24"), SourceMAC: "020000000001", InternetOnly: true},
		{ProtectionID: "P08", Networks: prefixes("1.1.1.0/24"), Roles: []Role{Trusted}},
		{ProtectionID: "P08", Networks: prefixes("8.8.8.0/24"), SourceMAC: "02:00:00:00:00:02"},
		{ProtectionID: "P08", Networks: prefixes("8.26.56.0/24"), Roles: []Role{Untrusted}},
	}
	compiler := testCompiler(t, baseline)
	candidate := compileScopes(t, baseline, scopeInput(t, internetRule()))
	for _, raw := range []string{"9.9.9.9", "64:ff9b::909:909", "8.26.56.26", "64:ff9b::81a:381a"} {
		if internetPermits(compiler, candidate, raw, 443) {
			t.Fatalf("retained restriction omitted %s", raw)
		}
	}
	for _, raw := range []string{"1.1.1.1", "8.8.8.8", "64:ff9b::101:101", "64:ff9b::808:808"} {
		if !internetPermits(compiler, candidate, raw, 443) {
			t.Fatalf("restriction for another role/device widened to %s", raw)
		}
	}
	geometry := compiler.InternetGeometry()
	geometry.Allowed[0] = netip.Prefix{}
	geometry.Excluded[0] = netip.Prefix{}
	geometry.Blocks[0].Networks[0] = netip.Prefix{}
	geometry.Blocks[1].Roles[0] = Untrusted
	if !internetPermits(compiler, candidate, "1.1.1.1", 443) || internetPermits(compiler, candidate, "9.9.9.9", 443) {
		t.Fatal("caller mutated compiler Internet geometry")
	}
}

func TestInternetSelectorCannotGrantUnsolicitedWANAccess(t *testing.T) {
	t.Parallel()
	rule := internetRule()
	rule.Direction = ToDevice
	candidate, err := testCompiler(t, testBaseline()).Compile(scopeInput(t, rule))
	if err != nil || len(candidate.Grants) != 0 || len(candidate.Denials) != 1 ||
		candidate.Denials[0].Code != "P09_unsolicited_wan" {
		t.Fatalf("inbound Internet selector accepted: %v %+v", err, candidate.Denials)
	}
}

func TestInternetDeviceProtectionsRemoveOnlyApplicablePorts(t *testing.T) {
	t.Parallel()
	for _, test := range []struct {
		name        string
		mutate      func(*Baseline)
		wantGrants  bool
		wantPort443 bool
	}{
		{name: "protected network", mutate: func(b *Baseline) {
			b.ProtectedNetworks[0].Networks = prefixes("fdca:1a2b:3::10/128")
		}},
		{name: "retained device network", mutate: func(b *Baseline) {
			b.RetainedBlocks = []NetworkBlock{{ProtectionID: "P08", Networks: prefixes("fdca:1a2b:3::10/128"), InternetOnly: true}}
		}},
		{name: "symmetric protected listener", mutate: func(b *Baseline) {
			b.ProtectedEndpoints = append(b.ProtectedEndpoints, EndpointBlock{
				ProtectionID: "P02", Networks: prefixes("fdca:1a2b:3::10/128"), Protocol: "tcp", Ports: []uint16{443},
			})
		}, wantGrants: true},
		{name: "destination-only listener", mutate: func(b *Baseline) {
			b.ProtectedEndpoints = append(b.ProtectedEndpoints, EndpointBlock{
				ProtectionID: "P02", Networks: prefixes("fdca:1a2b:3::10/128"), Protocol: "tcp", Ports: []uint16{443}, DestinationOnly: true,
			})
		}, wantGrants: true, wantPort443: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			baseline := testBaseline()
			test.mutate(&baseline)
			compiler := testCompiler(t, baseline)
			candidate, err := compiler.Compile(scopeInput(t, internetRule()))
			if err != nil || (len(candidate.Grants) != 0) != test.wantGrants {
				t.Fatalf("device protection failed: %v %+v", err, candidate.Denials)
			}
			if internetPermits(compiler, candidate, "1.1.1.1", 443) != test.wantPort443 {
				t.Fatal("device listener restriction changed wrong initiation ports")
			}
		})
	}
}

func TestInternetUnionPreservesIndependentContributorsAndQuota(t *testing.T) {
	t.Parallel()
	rule := internetRule()
	rule.AllDestinationPorts = false
	rule.DestinationPortRanges = []PortRange{{First: 8000, Last: 8010}}
	other := rule
	other.DestinationPortRanges = []PortRange{{First: 8005, Last: 8015}}
	expiry := testNow.Add(20 * time.Second)
	other.ExpiresAt = &expiry
	input := scopeInput(t, rule)
	input.Directory.Groups = append(input.Directory.Groups, scopeGroup(t, "short", true, other))
	input.Directory.Devices[0].GroupIDs = append(input.Directory.Devices[0].GroupIDs, "short")
	candidate := compileScopes(t, testBaseline(), input)
	if len(candidate.Grants) != 3 {
		t.Fatalf("got %d disjoint listener spans, want 3", len(candidate.Grants))
	}
	for _, grant := range candidate.Grants {
		wantContributors, wantExpiry := 1, testNow.Add(90*time.Second)
		if grant.Port == 8005 {
			wantContributors = 2
		}
		if grant.Port == 8011 {
			wantExpiry = expiry
		}
		if len(grant.Contributors) != wantContributors || grant.ExpiresAt() != wantExpiry {
			t.Fatal("listener union lost independent provenance or deadline")
		}
	}
	input.Directory.Devices[0].GroupIDs = []string{"placement", "short"}
	candidate = compileScopes(t, testBaseline(), input)
	if len(candidate.Grants) != 1 || candidate.Grants[0].Port != 8005 || candidate.Grants[0].ExpiresAt() != expiry {
		t.Fatal("revocation retained the removed group's Internet ports or deadline")
	}
	baseline := testBaseline()
	baseline.MaximumTuples = 1
	input = scopeInput(t, rule)
	input.Directory.Groups = append(input.Directory.Groups, scopeGroup(t, "same", false, rule))
	input.Directory.Devices[0].GroupIDs = append(input.Directory.Devices[0].GroupIDs, "same")
	candidate = compileScopes(t, baseline, input)
	if len(candidate.Grants) != 1 || len(candidate.Grants[0].Contributors) != 2 {
		t.Fatal("duplicate Internet contributions consumed tuple quota")
	}
}

func TestInternetCandidateTamperingAndEvidenceLease(t *testing.T) {
	t.Parallel()
	rule := internetRule()
	rule.Protocol = "udp"
	input := scopeInput(t, rule)
	input.Bindings.Records[0].Addresses[0].ValidUntil = testNow.Add(12 * time.Second)
	compiler := testCompiler(t, testBaseline())
	authorization, err := compiler.CompileAuthorization(t.Context(), input, CaptureAge())
	if err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		name   string
		mutate func(*Grant)
	}{
		{name: "incoming", mutate: func(g *Grant) { g.Direction = ToDevice }},
		{name: "peer host", mutate: func(g *Grant) { g.Peer.Real = netip.MustParseAddr("1.1.1.1") }},
		{name: "peer scope", mutate: func(g *Grant) { g.PeerScope = &PeerScope{Real: netip.MustParsePrefix("1.0.0.0/8")} }},
		{name: "DNS", mutate: func(g *Grant) { g.Port, g.PortEnd = 53, 53 }},
		{name: "NTP", mutate: func(g *Grant) { g.Port, g.PortEnd = 123, 123 }},
		{name: "reversed interval", mutate: func(g *Grant) { g.Port, g.PortEnd = 81, 80 }},
		{name: "reserved device network address", mutate: func(g *Grant) {
			g.Device = Endpoint{Real: netip.MustParseAddr("10.240.3.0"),
				Variants: []netip.Addr{netip.MustParseAddr("10.240.3.0"), netip.MustParseAddr("fdca:1a2b:64::af0:300")}}
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			candidate, err := authorization.Snapshot(t.Context())
			if err != nil {
				t.Fatal(err)
			}
			for _, grant := range candidate.Grants {
				if grant.ExpiresAt() != input.Bindings.Records[0].Addresses[0].ValidUntil {
					t.Fatal("Internet grant extended address evidence lifetime")
				}
			}
			test.mutate(&candidate.Grants[0])
			if compiler.CheckCandidate(t.Context(), candidate) == nil {
				t.Fatal("tampered Internet grant passed candidate checker")
			}
		})
	}
}
