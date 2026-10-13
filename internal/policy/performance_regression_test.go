package policy

import (
	"fmt"
	"net/netip"
	"slices"
	"testing"
)

func TestSharedGroupCacheRetainsDeviceDenialsAndRefreshesPerSnapshot(t *testing.T) {
	t.Parallel()
	input := testInput(t)
	bad := `{"schema_version":1,"kind":"access"}`
	input.Directory.Groups = append(input.Directory.Groups, Group{ID: "malformed", Name: "Malformed", Policy: &bad})
	input.Directory.Devices = append(input.Directory.Devices, Device{
		ID: "other-device", MAC: "02:00:00:00:00:02", Active: true,
		GroupIDs: []string{"placement", "access", "malformed"},
	})
	record := input.Bindings.Records[0]
	record.MAC, record.AssociationID = "02:00:00:00:00:02", "other-association"
	record.Addresses = slices.Clone(record.Addresses)
	record.Addresses[0].IP = netip.MustParseAddr("fdca:1a2b:3::11")
	record.Addresses[0].OwnershipID = "other-ownership"
	input.Bindings.Records = append(input.Bindings.Records, record)
	compiler := testCompiler(t, testBaseline())
	candidate, err := compiler.CompileContext(t.Context(), input)
	if err != nil || len(candidate.Grants) != 1 || len(candidate.Denials) != 1 ||
		candidate.Denials[0].DeviceID != "other-device" || candidate.Denials[0].Code != "malformed_group" {
		t.Fatalf("shared parsing changed device-level denial: %v %+v", err, candidate.Denials)
	}
	rule := testRule()
	rule.DestinationPorts = []uint16{80}
	input.Directory.Groups[1] = accessGroup(t, "access", false, rule)
	input.Ledger = candidate.Ledger
	candidate, err = compiler.CompileContext(t.Context(), input)
	if err != nil || len(candidate.Grants) != 1 || candidate.Grants[0].Port != 80 {
		t.Fatalf("group document cache survived into another snapshot: %v %+v", err, candidate.Grants)
	}
}

func TestDuplicateScopedContributorsDoNotConsumeQuota(t *testing.T) {
	t.Parallel()
	rule := testRule()
	input := scopeInput(t, rule)
	for _, id := range []string{"another", "third"} {
		input.Directory.Groups = append(input.Directory.Groups, scopeGroup(t, id, false, rule))
		input.Directory.Devices[0].GroupIDs = append(input.Directory.Devices[0].GroupIDs, id)
	}
	baseline := testBaseline()
	baseline.MaximumTuples = 1
	candidate := compileScopes(t, baseline, input)
	if len(candidate.Grants) != 1 || len(candidate.Grants[0].Contributors) != 3 {
		t.Fatal("duplicate scoped contributors consumed physical tuple quota")
	}
}

func TestOverlappingScopedPortsChargeFinalUnionNotIntermediateRules(t *testing.T) {
	t.Parallel()
	rules := []Rule{}
	for _, first := range []uint16{8000, 8001, 8002} {
		for _, last := range []uint16{8010, 8011, 8012} {
			rule := testRule()
			rule.ID = fmt.Sprintf("ports-%d-%d", first, last)
			rule.Peer = Peer{Addresses: []string{"fdca:1a2b::/64"}}
			rule.DestinationPorts = nil
			rule.DestinationPortRanges = []PortRange{{First: first, Last: last}}
			rules = append(rules, rule)
		}
	}
	baseline := testBaseline()
	baseline.MaximumTuples = 5
	candidate := compileScopes(t, baseline, scopeInput(t, rules...))
	if len(candidate.Grants) != 5 {
		t.Fatalf("got %d final listener segments, want 5", len(candidate.Grants))
	}
	for _, grant := range candidate.Grants {
		want := 3
		if grant.Port == 8001 || grant.Port == 8011 {
			want = 6
		}
		if grant.Port == 8002 {
			want = 9
		}
		if len(grant.Contributors) != want {
			t.Fatalf("listener segment %d lost independent contributors", grant.Port)
		}
	}
	baseline.MaximumTuples = 4
	if _, err := testCompiler(t, baseline).Compile(scopeInput(t, rules...)); err == nil {
		t.Fatal("actual final tuple overflow was accepted")
	}
}

func TestFinalLogicalQuotaAlsoBoundsIncompatibleRepresentations(t *testing.T) {
	t.Parallel()
	baseline := testBaseline()
	baseline.NAT46, baseline.NAT64, baseline.NAT46Pools = []NAT46{}, []NAT64{}, []netip.Prefix{}
	baseline.MaximumTuples = 1
	rule := testRule()
	rule.Peer = Peer{Addresses: []string{"10.240.0.10/32", "10.240.0.11/32"}}
	input := testInput(t)
	input.Directory.Groups[1] = accessGroup(t, "access", false, rule)
	if _, err := testCompiler(t, baseline).Compile(input); err == nil {
		t.Fatal("zero compatible physical projections bypassed logical grant quota")
	}
}

func TestScopeAliasIndexPreservesClosureReadinessAndImmutability(t *testing.T) {
	t.Parallel()
	baseline := benchmarkAliasBaseline(1024)
	baseline.NAT46[1000].Ready = false
	baseline.NAT46[1001].Target = netip.MustParseAddr("fdca:1a2b:4::20")
	compiler := testCompiler(t, baseline)
	network := netip.MustParsePrefix("fdca:1a2b:2::/64")
	scope := compiler.resolveScope(network)
	if len(scope.Variants) != 1+2*1022 {
		t.Fatalf("indexed scope lost installed counterparts: %d", len(scope.Variants))
	}
	for _, excluded := range []netip.Addr{baseline.NAT46[1000].Alias, baseline.NAT46[1001].Alias} {
		if inPrefixes(excluded, scope.Variants) {
			t.Fatal("indexed scope included an unready or out-of-scope alias")
		}
	}
	endpoint, err := Resolve(baseline, netip.MustParseAddr("fdca:1a2b:2::20"))
	if err != nil {
		t.Fatal(err)
	}
	expected := make([]netip.Prefix, 0, len(endpoint.Variants))
	for _, address := range endpoint.Variants {
		expected = append(expected, netip.PrefixFrom(address, address.BitLen()))
	}
	exact := compiler.resolveScope(netip.MustParsePrefix("fdca:1a2b:2::20/128"))
	if !slices.Equal(canonicalPrefixes(expected), exact.Variants) {
		t.Fatal("indexed scope differs from independently resolved exact endpoint")
	}
	scope.Variants[0] = netip.Prefix{}
	baseline.NAT46[0].Ready = false
	fresh := compiler.resolveScope(network)
	if len(fresh.Variants) != 1+2*1022 || !inPrefixes(netip.MustParseAddr("10.250.0.0"), fresh.Variants) {
		t.Fatal("caller changed the immutable scope alias index")
	}
}

func TestDisjointScopeUnionPreservesEveryRegionAndOrderIndependence(t *testing.T) {
	t.Parallel()
	compiler := testCompiler(t, testBaseline())
	grants := benchmarkDisjointGrants(2048)
	forward, err := compiler.normalizeScopeUnion(t.Context(), grants)
	if err != nil || len(forward) != len(grants) {
		t.Fatalf("disjoint scope union changed regions: %v, got %d", err, len(forward))
	}
	slices.Reverse(grants)
	reverse, err := compiler.normalizeScopeUnion(t.Context(), grants)
	if err != nil || len(reverse) != len(forward) {
		t.Fatalf("reverse-order scope union changed regions: %v", err)
	}
	for index, grant := range forward {
		if grantKey(grant) != grantKey(reverse[index]) || len(grant.Contributors) != 1 ||
			grant.ExpiresAt() != reverse[index].ExpiresAt() {
			t.Fatal("disjoint scope union lost contributor, expiry or canonical order")
		}
	}
}
