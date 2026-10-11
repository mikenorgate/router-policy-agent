package firewall

import (
	"encoding/json"
	"net/netip"
	"strings"
	"testing"

	"github.com/mikenorgate/router-policy-agent/internal/policy"
)

func bootstrapBaseline(t *testing.T) policy.Baseline {
	t.Helper()
	_, _, baseline, _ := renderFixture(t)
	baseline.Zones[0].Interfaces = []string{"trusted0"}
	baseline.ProtectedNetworks = append(baseline.ProtectedNetworks, policy.NetworkBlock{
		ProtectionID: "P03", Networks: []netip.Prefix{
			netip.MustParsePrefix("10.240.0.10/32"), netip.MustParsePrefix("fdca:1a2b::10/128"),
		},
	})
	baseline.BootstrapPaths = []policy.BootstrapPath{{
		Interface: "lan13", ServiceInterface: "lan10",
		GatewayAddresses: []netip.Addr{
			netip.MustParseAddr("10.240.3.1"), netip.MustParseAddr("fdca:1a2b:3::1"), netip.MustParseAddr("fe80::1"),
		},
		DNSAddresses: []netip.Addr{netip.MustParseAddr("10.240.0.10"), netip.MustParseAddr("fdca:1a2b::10")},
		NTPAddresses: []netip.Addr{netip.MustParseAddr("10.240.0.10"), netip.MustParseAddr("fdca:1a2b::10")},
	}}
	return baseline
}

func TestBootstrapGeometryIsImageOwnedAndNarrow(t *testing.T) {
	t.Parallel()
	baseline := bootstrapBaseline(t)
	layout, err := newGuardLayout(baseline)
	if err != nil {
		t.Fatal(err)
	}
	baseline.BootstrapPaths[0].DNSAddresses[0] = netip.MustParseAddr("192.0.2.53")
	lines, _ := layout.bootstrapForward("return")
	if len(lines) != 12 {
		t.Fatal("bootstrap geometry has unexpected services")
	}
	for _, line := range lines {
		if strings.Contains(line, "192.0.2.53") || strings.Contains(line, "tcp dport 123") {
			t.Fatal("bootstrap retained caller data or authorized TCP NTP")
		}
		if strings.Contains(line, "ct direction reply") && !strings.Contains(line, "ct state established") {
			t.Fatal("bootstrap allows unsolicited service replies")
		}
	}
	for _, device := range []string{"lan11", "lan14", "lan15"} {
		lines, _ := layout.bootstrapEgress(device)
		if len(lines) != 0 {
			t.Fatal("bootstrap exemptions escaped the managed interface")
		}
	}
}

func TestBootstrapRejectsUnprotectedOrOverbroadConfiguration(t *testing.T) {
	t.Parallel()
	for _, test := range []struct {
		name   string
		mutate func(*policy.Baseline)
	}{
		{name: "trusted client", mutate: func(b *policy.Baseline) { b.BootstrapPaths[0].Interface = "lan11" }},
		{name: "zone as service", mutate: func(b *policy.Baseline) { b.BootstrapPaths[0].ServiceInterface = "lan14" }},
		{name: "unsafe interface", mutate: func(b *policy.Baseline) { b.BootstrapPaths[0].ServiceInterface = "a;accept" }},
		{name: "external DNS", mutate: func(b *policy.Baseline) { b.BootstrapPaths[0].DNSAddresses[0] = netip.MustParseAddr("192.0.2.53") }},
		{name: "external NTP", mutate: func(b *policy.Baseline) { b.BootstrapPaths[0].NTPAddresses[0] = netip.MustParseAddr("192.0.2.123") }},
		{name: "foreign gateway", mutate: func(b *policy.Baseline) { b.BootstrapPaths[0].GatewayAddresses[0] = netip.MustParseAddr("10.240.0.1") }},
		{name: "missing NTP", mutate: func(b *policy.Baseline) { b.BootstrapPaths[0].NTPAddresses = nil }},
		{name: "duplicate interface", mutate: func(b *policy.Baseline) { b.BootstrapPaths = append(b.BootstrapPaths, b.BootstrapPaths[0]) }},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			baseline := bootstrapBaseline(t)
			test.mutate(&baseline)
			data, err := json.Marshal(baseline)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := policy.DecodeBaseline(data); err == nil {
				t.Fatal("unsafe bootstrap configuration accepted")
			}
		})
	}
}
