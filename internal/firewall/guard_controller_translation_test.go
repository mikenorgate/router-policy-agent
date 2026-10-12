package firewall

import (
	"net/netip"
	"slices"
	"strings"
	"testing"

	"github.com/mikenorgate/router-policy-agent/internal/policy"
)

func translatedControllerLayout(t *testing.T, ready bool, icmp ...bool) *guardLayout {
	t.Helper()
	if len(icmp) > 1 {
		t.Fatal("fixture accepts at most one ICMP option")
	}
	baseline := translatedControllerBaseline(t, ready, len(icmp) == 1 && icmp[0])
	layout, err := newGuardLayout(baseline)
	if err != nil {
		t.Fatal(err)
	}
	*baseline.ControllerInitiators[0].NAT64Paths[0].PostroutingSource = netip.MustParseAddr("10.240.3.11")
	return layout
}

func translatedControllerBaseline(t *testing.T, ready, icmpEnabled bool) policy.Baseline {
	t.Helper()
	_, _, baseline, _ := renderFixture(t)
	source := netip.MustParseAddr("10.240.3.1")
	baseline.ControllerInitiators = []policy.ControllerInitiator{{
		ID: "synthetic-controller", SourceInterface: "lan10",
		ICMPEnabled: icmpEnabled,
		Addresses:   []netip.Addr{netip.MustParseAddr("10.240.0.10"), netip.MustParseAddr("fdca:1a2b::10")},
		NAT64Paths: []policy.ControllerNAT64Path{{
			TranslatorID: "private64", Interface: "nat64-test", MappingIDs: []string{"controller-map"}, PostroutingSource: &source,
		}},
	}}
	baseline.NAT46 = append(baseline.NAT46, policy.NAT46{
		ID: "controller-map", Alias: netip.MustParseAddr("10.250.0.10"), Target: netip.MustParseAddr("fdca:1a2b::10"), Ready: ready,
	})
	return baseline
}

func TestControllerNAT64GuardGeometry(t *testing.T) {
	t.Parallel()
	for _, ready := range []bool{false, true} {
		layout := translatedControllerLayout(t, ready)
		expected := 2
		if ready {
			expected = 4
		}
		if len(layout.controllers) != expected || !slices.Contains(layout.interfaces, "nat64-test") {
			t.Fatal("controller translation readiness did not constrain its exact legs")
		}
		if !slices.Contains(layout.controllerAliases, netip.MustParseAddr("10.250.0.10")) {
			t.Fatal("unready translation lost its deny identity")
		}
		if ready {
			aliasLeg, mappedLeg := layout.controllers[2], layout.controllers[3]
			if aliasLeg.target.String() != "fdca:1a2b:64::af0:300/120" || aliasLeg.targetInterface != "nat64-test" {
				t.Fatal("translated destination widened beyond native untrusted geometry")
			}
			if mappedLeg.source.String() != "10.250.0.10" || mappedLeg.sourceInterface != "nat64-test" ||
				mappedLeg.egressSource.String() != "10.240.3.1" || mappedLeg.targetInterface != "lan13" {
				t.Fatal("pre-routing mapped identity or post-routing source was changed or aliased")
			}
			replyRules := strings.Join(layout.controllerEgressRules("nat64-test"), "\n")
			if !strings.Contains(replyRules, "ip daddr 10.250.0.10 return") || strings.Contains(replyRules, "ip daddr 10.240.3.1") {
				t.Fatal("reverse NAT44 egress did not restore the exact mapped controller identity")
			}
		}
		for _, rule := range layout.controllerForwardRules("return", false) {
			if strings.Contains(rule, "10.250.0.0/24") || strings.Contains(rule, "64:ff9b::/96") {
				t.Fatal("controller capability admitted an alias pool or global translator")
			}
		}
	}
}
