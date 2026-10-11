package firewall

import (
	"bytes"
	"net/netip"
	"strings"
	"testing"

	"github.com/mikenorgate/router-policy-agent/internal/policy"
)

func nativeControllerLayout(t *testing.T) *guardLayout {
	t.Helper()
	_, _, baseline, _ := renderFixture(t)
	baseline.ControllerInitiators = []policy.ControllerInitiator{{
		ID: "synthetic-controller", SourceInterface: "lan10",
		Addresses: []netip.Addr{netip.MustParseAddr("10.240.0.10"), netip.MustParseAddr("fdca:1a2b::10")},
	}}
	layout, err := newGuardLayout(baseline)
	if err != nil {
		t.Fatal(err)
	}
	baseline.ControllerInitiators[0].Addresses[0] = netip.MustParseAddr("10.240.0.11")
	return layout
}

func TestControllerGuardOwnsExactNativeGeometry(t *testing.T) {
	t.Parallel()
	layout := nativeControllerLayout(t)
	program, err := layout.program(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if len(layout.controllers) != 2 || bytes.Contains(program, []byte("10.240.0.11")) {
		t.Fatal("controller geometry retained caller-owned addresses or unexpected legs")
	}
	for _, rule := range layout.controllerForwardRules("return", false) {
		if !strings.Contains(rule, `iifname "lan10" oifname "lan13"`) &&
			!strings.Contains(rule, `iifname "lan13" oifname "lan10"`) {
			t.Fatal("controller rule permits an unrelated ingress or egress")
		}
		if strings.Contains(rule, "ct direction reply") && !strings.Contains(rule, "ct state established ") {
			t.Fatal("controller reply permits a new or unrelated flow")
		}
	}
	for _, family := range []string{"inet", "netdev"} {
		if _, err := layout.schema(family); err != nil {
			t.Fatal(err)
		}
	}
	if len(layout.controllerEgressRules("lan14")) != 0 || len(layout.controllerEgressRules("lan15")) != 0 {
		t.Fatal("controller capability reaches security or assessment")
	}
	if len(guardBridgeRules()) != 4 {
		t.Fatal("controller tags widened the directory bridge")
	}
	for _, leg := range layout.controllers {
		for _, reply := range []bool{false, true} {
			mark := controllerMark(leg, reply)
			if mark&0x00ff0000 != 0 || mark&0xffff == 0 {
				t.Fatal("controller mark collides with preserved bits or has no exact leg")
			}
		}
	}
}

func TestControllerGuardDisabledLayout(t *testing.T) {
	t.Parallel()
	_, _, baseline, _ := renderFixture(t)
	plain, err := newGuardLayout(baseline)
	if err != nil {
		t.Fatal(err)
	}
	baseline.ControllerInitiators = []policy.ControllerInitiator{}
	empty, err := newGuardLayout(baseline)
	if err != nil {
		t.Fatal(err)
	}
	want, err := plain.program(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	actual, err := empty.program(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(actual, want) || len(empty.controllers) != 0 ||
		len(empty.controllerForwardRules("return", false)) != 0 || len(empty.controllerIdentityDrops()) != 0 {
		t.Fatal("empty controller capability changed the disabled layout")
	}
}
