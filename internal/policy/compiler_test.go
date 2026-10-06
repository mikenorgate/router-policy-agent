package policy

import (
	"encoding/json"
	"net/netip"
	"slices"
	"testing"
	"time"
)

func TestCompile(t *testing.T) {
	t.Parallel()
	candidate, err := testCompiler(t, testBaseline()).Compile(testInput(t))
	if err != nil || len(candidate.Denials) != 0 || len(candidate.Grants) != 1 {
		t.Fatalf("Compile = %+v, %v", candidate, err)
	}
	grant := candidate.Grants[0]
	if grant.Direction != ToDevice || grant.Port != 6053 || grant.Peer.Real.String() != "fdca:1a2b::10" ||
		!grant.ExpiresAt().Equal(testNow.Add(90*time.Second)) || len(grant.Contributors) != 1 {
		t.Fatalf("wrong grant: %+v", grant)
	}
}

func TestCompileComposition(t *testing.T) {
	t.Parallel()
	input := testInput(t)
	deadline := testNow.Add(20 * time.Second)
	rule := testRule()
	rule.ExpiresAt = &deadline
	input.Directory.Groups = append(input.Directory.Groups, accessGroup(t, "temporary", true, rule))
	input.Directory.Devices[0].GroupIDs = append(input.Directory.Devices[0].GroupIDs, "temporary")
	compiler := testCompiler(t, testBaseline())
	candidate, err := compiler.Compile(input)
	if err != nil || len(candidate.Grants) != 1 || len(candidate.Grants[0].Contributors) != 2 {
		t.Fatalf("union = %+v, %v", candidate, err)
	}
	if !candidate.Grants[0].ExpiresAt().Equal(testNow.Add(90 * time.Second)) {
		t.Fatal("shorter contributor incorrectly cut off valid ordinary grant")
	}
	input.Directory.Devices[0].GroupIDs = []string{"placement", "temporary"}
	input.Ledger = candidate.Ledger
	candidate, err = compiler.Compile(input)
	if err != nil || len(candidate.Grants) != 1 || !candidate.Grants[0].ExpiresAt().Equal(deadline) {
		t.Fatalf("revocation of ordinary source = %+v, %v", candidate, err)
	}
	input.Now = deadline
	candidate, err = compiler.Compile(input)
	if err != nil || len(candidate.Grants) != 0 {
		t.Fatalf("expired last contributor = %+v, %v", candidate, err)
	}
}

func TestCompileDeviceDenials(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name   string
		mutate func(*Input)
		code   string
	}{
		{name: "inactive", mutate: func(i *Input) { i.Directory.Devices[0].Active = false }, code: "inactive_account"},
		{name: "missing placement", mutate: func(i *Input) { i.Directory.Devices[0].GroupIDs = []string{"access"} }, code: "ambiguous_placement_or_group_quota"},
		{name: "missing member", mutate: func(i *Input) { i.Directory.Devices[0].GroupIDs = append(i.Directory.Devices[0].GroupIDs, "absent") }, code: "missing_or_duplicate_membership"},
		{name: "duplicate placement", mutate: func(i *Input) {
			g := i.Directory.Groups[0]
			g.ID = "placement2"
			i.Directory.Groups = append(i.Directory.Groups, g)
			i.Directory.Devices[0].GroupIDs = append(i.Directory.Devices[0].GroupIDs, g.ID)
		}, code: "ambiguous_placement_or_group_quota"},
		{name: "malformed access", mutate: func(i *Input) { raw := `{}`; i.Directory.Groups[1].Policy = &raw }, code: "malformed_group"},
		{name: "missing attribute", mutate: func(i *Input) { i.Directory.Groups[1].Policy = nil }, code: "missing_network_attribute"},
		{name: "wrong actual vlan", mutate: func(i *Input) { i.Bindings.Records[0].VLAN = 12 }, code: "unqualified_binding"},
		{name: "wrong source interface", mutate: func(i *Input) { i.Bindings.Records[0].Interface = "lan12" }, code: "unqualified_binding"},
		{name: "wrong subnet", mutate: func(i *Input) { i.Bindings.Records[0].Addresses[0].IP = netip.MustParseAddr("fdca:1a2b:2::10") }, code: "unqualified_binding"},
		{name: "no ownership", mutate: func(i *Input) { i.Bindings.Records[0].Addresses = nil }, code: "unqualified_binding"},
		{name: "seven day limit", mutate: func(i *Input) {
			rule := testRule()
			expiry := testNow.Add(7*24*time.Hour + time.Second)
			rule.ExpiresAt = &expiry
			i.Directory.Groups[1] = accessGroup(t, "access", true, rule)
		}, code: "invalid_expiry"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			input := testInput(t)
			test.mutate(&input)
			candidate, err := testCompiler(t, testBaseline()).Compile(input)
			if err != nil || len(candidate.Grants) != 0 || len(candidate.Denials) != 1 || candidate.Denials[0].Code != test.code {
				t.Fatalf("Compile = %+v, %v; want denial %s", candidate, err, test.code)
			}
		})
	}
}

func TestCompileGlobalFailures(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name   string
		mutate func(*Input)
	}{
		{name: "incomplete directory", mutate: func(i *Input) { i.Directory.Complete = false }},
		{name: "stale directory", mutate: func(i *Input) { i.Directory.ObservedAt = testNow.Add(-90 * time.Second) }},
		{name: "future directory", mutate: func(i *Input) { i.Directory.ObservedAt = testNow.Add(time.Second) }},
		{name: "stale bindings", mutate: func(i *Input) { i.Bindings.ObservedAt = testNow.Add(-90 * time.Second) }},
		{name: "incomplete bindings", mutate: func(i *Input) { i.Bindings.Complete = false }},
		{name: "ndp only", mutate: func(i *Input) { i.Bindings.Records[0].Addresses[0].Source = "ndp" }},
		{name: "expired ownership", mutate: func(i *Input) { i.Bindings.Records[0].Addresses[0].ValidUntil = testNow }},
		{name: "old association", mutate: func(i *Input) { i.Bindings.Records[0].AssociatedAt = testNow.Add(-90 * time.Second) }},
		{name: "duplicate MAC", mutate: func(i *Input) { i.Directory.Devices = append(i.Directory.Devices, i.Directory.Devices[0]) }},
		{name: "duplicate address", mutate: func(i *Input) {
			i.Bindings.Records[0].Addresses = append(i.Bindings.Records[0].Addresses, i.Bindings.Records[0].Addresses[0])
		}},
		{name: "unsafe clock", mutate: func(i *Input) { i.Ledger.LastValidated = testNow.Add(time.Second) }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			input := testInput(t)
			test.mutate(&input)
			if candidate, err := testCompiler(t, testBaseline()).Compile(input); err == nil {
				t.Fatalf("invalid global input accepted: %+v", candidate)
			}
		})
	}
}

func TestProtectedFloorAndAliases(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name, peer, protocol string
		port                 uint16
		direction            Direction
		code                 string
	}{
		{name: "native security", peer: "fdca:1a2b:4::40/128", protocol: "tcp", port: 6053, direction: ToDevice, code: "P07_security_router_owned"},
		{name: "security46", peer: "10.250.0.40/32", protocol: "tcp", port: 443, direction: FromDevice, code: "P07_security_router_owned"},
		{name: "security64", peer: "fdca:1a2b:64::af0:40a/128", protocol: "tcp", port: 443, direction: FromDevice, code: "P07_security_router_owned"},
		{name: "security64of46", peer: "fdca:1a2b:64::afa:28/128", protocol: "tcp", port: 443, direction: FromDevice, code: "P07_security_router_owned"},
		{name: "assessment", peer: "fdca:1a2b:5::10/128", protocol: "tcp", port: 443, direction: FromDevice, code: "P07_isolated_or_unclassified_peer"},
		{name: "unknown private", peer: "10.242.0.1/32", protocol: "tcp", port: 443, direction: FromDevice, code: "P07_isolated_or_unclassified_peer"},
		{name: "out of band", peer: "10.241.0.1/32", protocol: "tcp", port: 443, direction: FromDevice, code: "P07_isolated_or_unclassified_peer"},
		{name: "router admin", peer: "10.240.2.254/32", protocol: "tcp", port: 443, direction: FromDevice, code: "P02_protected_endpoint"},
		{name: "same host non admin port", peer: "10.240.2.254/32", protocol: "tcp", port: 6053, direction: ToDevice},
		{name: "same port ordinary host", peer: "10.240.2.100/32", protocol: "tcp", port: 443, direction: FromDevice},
		{name: "service plane", peer: "10.240.2.200/32", protocol: "tcp", port: 443, direction: FromDevice, code: "P03_retained_network_block"},
		{name: "dns", peer: "9.9.9.9/32", protocol: "udp", port: 53, direction: FromDevice, code: "P06_router_dns_ntp"},
		{name: "ntp", peer: "9.9.9.9/32", protocol: "udp", port: 123, direction: FromDevice, code: "P06_router_dns_ntp"},
		{name: "https internet", peer: "9.9.9.9/32", protocol: "tcp", port: 443, direction: FromDevice},
		{name: "internet incoming", peer: "9.9.9.9/32", protocol: "tcp", port: 443, direction: ToDevice, code: "P09_unsolicited_wan"},
		{name: "same vlan", peer: "fdca:1a2b:3::20/128", protocol: "tcp", port: 443, direction: ToDevice, code: "same_vlan_not_router_enforceable"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			input := testInput(t)
			rule := testRule()
			rule.Peer.Addresses, rule.Protocol, rule.DestinationPorts, rule.Direction = []string{test.peer}, test.protocol, []uint16{test.port}, test.direction
			input.Directory.Groups[1] = accessGroup(t, "access", false, rule)
			candidate, err := testCompiler(t, testBaseline()).Compile(input)
			if err != nil {
				t.Fatal(err)
			}
			if test.code == "" {
				if len(candidate.Grants) != 1 || len(candidate.Denials) != 0 {
					t.Fatalf("permit missing: %+v", candidate)
				}
			} else if len(candidate.Grants) != 0 || len(candidate.Denials) != 1 || candidate.Denials[0].Code != test.code {
				t.Fatalf("protected flow accepted or wrong denial: %+v", candidate)
			}
		})
	}
}

func TestAliasRetargetCannotTransferPermission(t *testing.T) {
	t.Parallel()
	input := testInput(t)
	rule := testRule()
	rule.Direction = FromDevice
	rule.Peer.Addresses = []string{"10.250.0.20/32"}
	rule.DestinationPorts = []uint16{443}
	input.Directory.Groups[1] = accessGroup(t, "access", false, rule)
	baseline := testBaseline()
	candidate, err := testCompiler(t, baseline).Compile(input)
	if err != nil || len(candidate.Grants) != 1 {
		t.Fatalf("first alias = %+v, %v", candidate, err)
	}
	input.Ledger = candidate.Ledger
	baseline.NAT46[0].Target = netip.MustParseAddr("fdca:1a2b:2::21")
	candidate, err = testCompiler(t, baseline).Compile(input)
	if err != nil || len(candidate.Grants) != 0 || candidate.Denials[0].Code != "unready_or_changed_alias" {
		t.Fatalf("alias permission transferred: %+v, %v", candidate, err)
	}
}

func TestNativeRuleDropsRetargetedAlias(t *testing.T) {
	t.Parallel()
	input := testInput(t)
	rule := testRule()
	rule.Direction = FromDevice
	rule.Peer.Addresses = []string{"fdca:1a2b:2::20/128"}
	input.Directory.Groups[1] = accessGroup(t, "access", false, rule)
	baseline := testBaseline()
	baseline.NAT46[0].Target = netip.MustParseAddr("fdca:1a2b:2::21")
	candidate, err := testCompiler(t, baseline).Compile(input)
	if err != nil || len(candidate.Grants) != 1 || len(candidate.Grants[0].Peer.Variants) != 1 {
		t.Fatalf("native policy retained stale alias: %+v, %v", candidate, err)
	}
}

func TestDeadlinesDoNotSlide(t *testing.T) {
	t.Parallel()
	input := testInput(t)
	rule := testRule()
	expiry := testNow.Add(7 * 24 * time.Hour)
	rule.ExpiresAt = &expiry
	input.Directory.Groups[1] = accessGroup(t, "access", true, rule)
	compiler := testCompiler(t, testBaseline())
	candidate, err := compiler.Compile(input)
	if err != nil || len(candidate.Grants) != 1 {
		t.Fatalf("first validation: %+v, %v", candidate, err)
	}
	input.Ledger, input.Now = candidate.Ledger, testNow.Add(24*time.Hour)
	input.Directory.ObservedAt, input.Bindings.ObservedAt = input.Now, input.Now
	input.Bindings.Records[0].AssociatedAt = input.Now
	input.Bindings.Records[0].Addresses[0].ObservedAt = input.Now
	input.Bindings.Records[0].Addresses[0].ValidUntil = input.Now.Add(time.Hour)
	newExpiry := expiry.Add(time.Hour)
	rule.ExpiresAt = &newExpiry
	input.Directory.Groups[1] = accessGroup(t, "access", true, rule)
	candidate, err = compiler.Compile(input)
	if err != nil || len(candidate.Grants) != 0 || candidate.Denials[0].Code != "invalid_expiry" {
		t.Fatalf("seven day deadline slid: %+v, %v", candidate, err)
	}
}

func TestBindingAndDirectoryEventsDoNotRenewLease(t *testing.T) {
	t.Parallel()
	input := testInput(t)
	input.Now = testNow.Add(40 * time.Second)
	baseline := testBaseline()
	baseline.Generation = "map-update"
	candidate, err := testCompiler(t, baseline).Compile(input)
	if err != nil || len(candidate.Grants) != 1 || !candidate.Grants[0].ExpiresAt().Equal(testNow.Add(90*time.Second)) {
		t.Fatalf("mapping event renewed stale directory lease: %+v, %v", candidate, err)
	}
}

func TestQuotaRejectsWholeCandidate(t *testing.T) {
	t.Parallel()
	baseline := testBaseline()
	baseline.MaximumTuples = 1
	input := testInput(t)
	rule := testRule()
	rule.DestinationPorts = []uint16{6053, 80}
	input.Directory.Groups[1] = accessGroup(t, "access", false, rule)
	if candidate, err := testCompiler(t, baseline).Compile(input); err == nil || len(candidate.Grants) != 0 {
		t.Fatalf("partial over-quota candidate accepted: %+v, %v", candidate, err)
	}
	// Identical independent contributors consume one tuple, not two.
	input = testInput(t)
	input.Directory.Groups = append(input.Directory.Groups, accessGroup(t, "access2", false, testRule()))
	input.Directory.Devices[0].GroupIDs = append(input.Directory.Devices[0].GroupIDs, "access2")
	candidate, err := testCompiler(t, baseline).Compile(input)
	if err != nil || len(candidate.Grants) != 1 || len(candidate.Grants[0].Contributors) != 2 {
		t.Fatalf("duplicate contributors consumed quota: %+v, %v", candidate, err)
	}
}

func TestBaselineCopyAndDecode(t *testing.T) {
	t.Parallel()
	baseline := testBaseline()
	compiler := testCompiler(t, baseline)
	baseline.ProtectedEndpoints[0].Ports[0] = 6053
	candidate, err := compiler.Compile(testInput(t))
	if err != nil || len(candidate.Grants) != 1 {
		t.Fatal("caller mutated compiler baseline")
	}
	data, err := json.Marshal(baseline)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := DecodeBaseline(data)
	if err != nil || !slices.Equal(decoded.ProtectedEndpoints[0].Ports, []uint16{6053, 443}) {
		t.Fatalf("baseline decode = %+v, %v", decoded, err)
	}
}

func TestKnownNetworkGroupCannotLoseItsAttribute(t *testing.T) {
	t.Parallel()
	input := testInput(t)
	compiler := testCompiler(t, testBaseline())
	candidate, err := compiler.Compile(input)
	if err != nil {
		t.Fatal(err)
	}
	input.Ledger = candidate.Ledger
	input.Directory.Groups[1].Policy = nil
	input.Directory.Groups[1].IsNetwork = false
	candidate, err = compiler.Compile(input)
	if err != nil || len(candidate.Grants) != 0 || candidate.Denials[0].Code != "missing_network_attribute" {
		t.Fatalf("known network group fell back to ordinary group: %+v, %v", candidate, err)
	}
}
