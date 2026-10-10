//go:build integration && kernel

package radius

import (
	"net/netip"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/mikenorgate/router-policy-agent/internal/kea"
)

// The disposable runner creates these synthetic interfaces before dropping ALL
// capabilities. This test never changes network state or contacts a live LAN.
func TestPlacementNativeCapabilityFree(t *testing.T) {
	if os.Getenv("ROUTER_POLICY_PLACEMENT_TEST") != "isolated" {
		t.Skip("requires dedicated network-isolated placement fixture")
	}
	status, err := os.ReadFile("/proc/self/status")
	if err != nil || !strings.Contains(string(status), "CapEff:\t0000000000000000") ||
		!strings.Contains(string(status), "CapBnd:\t0000000000000000") {
		t.Fatal("native observation must run without effective or bounding capabilities")
	}
	options := PlacementOptions{Interface: "placement22", Parent: "placement0", VLAN: 22, Timeout: 3 * time.Second}
	observed, err := capturePlacement(t.Context(), options)
	if err != nil || len(observed.neighbors) != 1 {
		t.Fatalf("actual iproute2 observation rejected: %v", err)
	}
	now := time.Now().UTC()
	session := Session{
		MAC: "02:aa:bb:cc:dd:ee", NAS: netip.MustParseAddr("198.51.100.42"), AssociationID: strings.Repeat("a", 64),
		StartedAt: now.Add(-20 * time.Second), ObservedAt: now.Add(-10 * time.Second),
		ValidUntil: now.Add(80 * time.Second), IPv4: netip.MustParseAddr("192.0.2.80"),
	}
	lease := kea.Observation{ObservedAt: now, Leases: []kea.Lease{{
		IP: session.IPv4, MAC: session.MAC, SubnetID: 22, UpdatedAt: now.Add(-time.Minute), ValidUntil: now.Add(time.Hour),
	}}}
	scope := LeaseScope{SubnetID: 22, Prefix: netip.MustParsePrefix("192.0.2.0/24"), VLAN: 22}
	candidate, err := MatchIPv4(session, lease, scope, now)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := bindPlacement(candidate, observed, scope, options, now); err != nil {
		t.Fatal("matching real kernel observation did not produce a proposed binding")
	}
	for _, name := range []string{"wrong vlan", "wrong parent", "missing interface"} {
		t.Run(name, func(t *testing.T) {
			value := options
			switch name {
			case "wrong vlan":
				value.VLAN = 23
			case "wrong parent":
				value.Parent = "other"
			case "missing interface":
				value.Interface = "absent22"
			}
			if got, err := capturePlacement(t.Context(), value); err == nil || got.identity != "" || len(got.neighbors) != 0 {
				t.Fatal("wrong actual geometry returned placement evidence")
			}
		})
	}
}
