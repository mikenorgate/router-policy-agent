//go:build integration && kernel && linux

package firewall

import (
	"bytes"
	"context"
	"errors"
	"net/netip"
	"slices"
	"testing"
	"time"

	"github.com/mikenorgate/router-policy-agent/internal/state"
)

// This qualifies native revocation through the coordinator using test-only nft
// adapters. It does not retarget a real translator, qualify P01-P10, or enable
// the guarded production executor. Its audit checks only the fixed owned guard.
func TestKernelWriterTransitionSealsNativePermitsBeforeUpdate(t *testing.T) {
	requireKernelIsolation(t)
	t.Cleanup(func() { requireKernelIsolation(t) })
	ctx, cancel := context.WithTimeout(t.Context(), 25*time.Second)
	defer cancel()
	setupPacketLinks(ctx, t)
	layout, process := setupClassifiedGuardFixture(ctx, t, []string{"lan10", "lan13"})
	gate, root, _ := generationGateFixture(t)
	packetNft(ctx, t, `
table inet writer_legacy_fixture {
 chain forward { type filter hook forward priority 0; policy drop;
  ct state established accept; meta l4proto udp udp dport 6053 accept;
 }
}
table netdev writer_endpoint_fixture {
 chain peer { type filter hook ingress device "peer0" priority 0; policy drop; }
 chain device_endpoint { type filter hook ingress device "device0" priority 0; policy drop; }
}
table inet writer_unrelated_fixture {
 set retained { type ipv4_addr; elements = { 10.243.0.10 }; }
 chain retained_rule { ip saddr @retained drop; }
}`)
	t.Cleanup(func() {
		cleanup, cancel := context.WithTimeout(context.WithoutCancel(t.Context()), 2*time.Second)
		defer cancel()
		packetNft(cleanup, t, `delete table inet writer_legacy_fixture;
delete table netdev writer_endpoint_fixture; delete table inet writer_unrelated_fixture`)
	})
	unrelated := kernelFixtureCommand(ctx, t, "list", "table", "inet", "writer_unrelated_fixture")
	peer, device := packetSocket(t, "peer0"), packetSocket(t, "device0")
	history := state.EmptyClassification()
	previous, target := writerGenerationFixture(), transitionTargetFixture()
	for _, family := range []struct{ name, peer, device string }{
		{name: "ipv4", peer: "10.240.0.10", device: "10.240.3.10"},
		{name: "ipv6", peer: "fdca:1a2b::10", device: "fdca:1a2b:3::10"},
	} {
		t.Run(family.name, func(t *testing.T) {
			deviceIP, peerIP := netip.MustParseAddr(family.device), netip.MustParseAddr(family.peer)
			logical, additions := classifiedLogicalFixture(t, guardPacketBatch(t, deviceIP, peerIP, true))
			history.MACs = append(history.MACs, additions.MACs...)
			history.IPv4 = append(history.IPv4, additions.IPv4...)
			history.IPv6 = append(history.IPv6, additions.IPv6...)
			for _, values := range []*[]string{&history.MACs, &history.IPv4, &history.IPv6} {
				slices.Sort(*values)
				*values = slices.Compact(*values)
			}
			active, err := prepareClassifiedGuards(ctx, &preparedBatch{data: logical}, history)
			if err != nil {
				t.Fatal(err)
			}
			applyClassifiedGuardFixture(ctx, t, process, layout, active)
			request := packetFrame(t, packetDatagram{
				source: peerIP, destination: deviceIP,
				sourceMAC: "02:00:00:00:00:10", destinationMAC: "02:00:00:00:01:10",
				sourcePort: 41600, destinationPort: 6053, payload: "synthetic-writer-flow",
			})
			reply := packetFrame(t, packetDatagram{
				source: deviceIP, destination: peerIP,
				sourceMAC: "02:00:00:00:00:13", destinationMAC: "02:00:00:00:01:13",
				sourcePort: 6053, destinationPort: 41600, payload: "synthetic-writer-reply",
			})
			checkTraffic := func(ctx context.Context, allowed bool) {
				sendPacket(ctx, t, peer, request)
				receivePacket(ctx, t, device, request, allowed)
				sendPacket(ctx, t, device, reply)
				receivePacket(ctx, t, peer, reply, allowed)
			}
			checkTraffic(ctx, true)
			steps := transitionSteps{
				revoke: func(bounded context.Context) error {
					sealed, err := prepareGuardSeal(bounded, history)
					if err != nil {
						return err
					}
					applyClassifiedGuardFixture(bounded, t, process, layout, sealed)
					return nil
				},
				update: func(bounded context.Context) error {
					pending := readGenerationFixture(t, root)
					if pending.Ready || pending.Sequence != previous.Sequence+1 {
						return errors.New("synthetic owner update lacks closed coordination state")
					}
					// Existing traffic must already be cut off before the owner is
					// permitted to change an alias or protected forwarding path.
					checkTraffic(bounded, false)
					assertClassifiedGuardInventory(bounded, t, process, layout, history, false)
					return nil
				},
				audit: func(bounded context.Context) (generationTarget, error) {
					assertClassifiedGuardInventory(bounded, t, process, layout, history, false)
					return target, nil
				},
			}
			ready, err := gate.transition(
				ctx,
				previous,
				target,
				steps,
			)
			if err != nil {
				t.Fatal(err)
			}
			previous = ready
			// Publishing readiness is not permission or restoration of old leases.
			checkTraffic(ctx, false)
			assertClassifiedGuardInventory(ctx, t, process, layout, history, false)
		})
	}
	after := kernelFixtureCommand(ctx, t, "list", "table", "inet", "writer_unrelated_fixture")
	if !bytes.Equal(unrelated, after) {
		t.Fatal("owning transition changed unrelated kernel objects")
	}
}
