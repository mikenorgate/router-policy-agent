package policy

import (
	"net/netip"
	"testing"
)

func TestDirectedBroadcastAndNetworkHosts(t *testing.T) {
	t.Parallel()
	for _, peer := range []string{
		"10.240.2.0/32", "10.240.2.255/32", "fdca:1a2b:64::af0:200/128", "fdca:1a2b:64::af0:2ff/128",
	} {
		t.Run(peer, func(t *testing.T) {
			t.Parallel()
			input := testInput(t)
			rule := testRule()
			rule.Direction, rule.Peer.Addresses = FromDevice, []string{peer}
			input.Directory.Groups[1] = accessGroup(t, "access", false, rule)
			candidate, err := testCompiler(t, testBaseline()).Compile(input)
			if err != nil || len(candidate.Grants) != 0 || len(candidate.Denials) != 1 ||
				candidate.Denials[0].Code != "P04_non_host_zone_address" {
				t.Fatalf("zone broadcast policy: %#v, %v", candidate.Denials, err)
			}
		})
	}
	for _, address := range []string{"10.240.3.0", "10.240.3.255"} {
		t.Run(address, func(t *testing.T) {
			t.Parallel()
			input := testInput(t)
			input.Bindings.Records[0].Addresses[0].IP = netip.MustParseAddr(address)
			input.Bindings.Records[0].Addresses[0].Source = "kea_dhcp4"
			candidate, err := testCompiler(t, testBaseline()).Compile(input)
			if err != nil || len(candidate.Grants) != 0 || candidate.Denials[0].Code != "unqualified_binding" {
				t.Fatalf("zone broadcast binding: %#v, %v", candidate.Denials, err)
			}
		})
	}
	t.Run("point to point endpoints remain hosts", func(t *testing.T) {
		baseline := testBaseline()
		baseline.Zones[0].Networks = prefixes("10.240.0.0/31")
		for _, address := range []string{"10.240.0.0", "10.240.0.1"} {
			if reservedZoneHost(baseline, netip.MustParseAddr(address)) {
				t.Fatal("point to point endpoint classified as broadcast")
			}
		}
	})
}
