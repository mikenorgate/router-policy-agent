//go:build integration && kernel && linux

package firewall

import (
	"context"
	"encoding/json"
	"fmt"
	"net/netip"
	"strings"
	"testing"
	"time"
)

// This is the native guard contract, not qualification of translated traffic,
// address ownership, or a production router's source/protected policy.
func TestKernelNativeControllerBaseline(t *testing.T) {
	requireKernelIsolation(t)
	t.Cleanup(func() { requireKernelIsolation(t) })
	ctx, cancel := context.WithTimeout(t.Context(), 45*time.Second)
	defer cancel()
	setupPacketLinks(ctx, t)
	layout := nativeControllerLayout(t)
	for _, name := range []string{"lan11", "lan12", "lan14", "lan15"} {
		packetIP(ctx, t, "link", "add", name, "type", "dummy")
		t.Cleanup(func() {
			cleanup, cancel := context.WithTimeout(context.WithoutCancel(t.Context()), 2*time.Second)
			defer cancel()
			packetIP(cleanup, t, "link", "delete", name)
		})
	}
	program, err := layout.program(ctx)
	if err != nil {
		t.Fatal(err)
	}
	packetNft(ctx, t, string(program))
	t.Cleanup(func() {
		cleanup, cancel := context.WithTimeout(context.WithoutCancel(t.Context()), 2*time.Second)
		defer cancel()
		packetNft(cleanup, t, "delete table inet "+ownedTable+"; delete table netdev "+ownedTable)
	})
	process, err := openProcess(ctx, "/usr/sbin/nft")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := process.close(); err != nil {
			t.Error(err)
		}
	})
	if _, err := process.inspectGuards(ctx, layout); err != nil {
		t.Fatalf("controller text did not match actual kernel schema: %v", err)
	}
	packetNft(ctx, t, `
table netdev controller_endpoint_fixture {
 counter changed_handoff {}
 chain change_egress { type filter hook egress device "lan13" priority -10; policy accept; }
 chain peer_endpoint { type filter hook ingress device "peer0" priority 0; policy drop; }
 chain device_endpoint { type filter hook ingress device "device0" priority 0; policy drop; }
}
table inet controller_router_fixture {
 set protected4 { type ipv4_addr; }
 set protected6 { type ipv6_addr; }
 counter protected_drop {}
 counter changed_handoff {}
 chain change_forward { type filter hook forward priority 100; policy accept; }
 chain controller_allow {
  meta l4proto { tcp, udp } iifname "lan10" oifname "lan13" ip saddr 10.240.0.10 ip daddr 10.240.3.0/24 ct direction original ct state { new, established } accept
  meta l4proto { tcp, udp } iifname "lan13" oifname "lan10" ip saddr 10.240.3.0/24 ip daddr 10.240.0.10 ct direction reply ct state established accept
  meta l4proto { tcp, udp } iifname "lan10" oifname "lan13" ip6 saddr fdca:1a2b::10 ip6 daddr fdca:1a2b:3::/64 ct direction original ct state { new, established } accept
  meta l4proto { tcp, udp } iifname "lan13" oifname "lan10" ip6 saddr fdca:1a2b:3::/64 ip6 daddr fdca:1a2b::10 ct direction reply ct state established accept
 }
 chain router_forward {
  type filter hook forward priority 0; policy drop;
  ip saddr @protected4 counter name protected_drop drop
  ip daddr @protected4 counter name protected_drop drop
  ip6 saddr @protected6 counter name protected_drop drop
  ip6 daddr @protected6 counter name protected_drop drop
  jump controller_allow
`+strings.Join(guardBridgeRules(), "\n")+`
 }
}
`)
	t.Cleanup(func() {
		cleanup, cancel := context.WithTimeout(context.WithoutCancel(t.Context()), 2*time.Second)
		defer cancel()
		packetNft(cleanup, t, "delete table netdev controller_endpoint_fixture; delete table inet controller_router_fixture")
	})
	peer, device := packetSocket(t, "peer0"), packetSocket(t, "device0")
	for _, family := range []struct{ name, peer, device, neighbor, otherController string }{
		{"ipv4", "10.240.0.10", "10.240.3.10", "10.240.3.11", "10.240.0.11"},
		{"ipv6", "fdca:1a2b::10", "fdca:1a2b:3::10", "fdca:1a2b:3::11", "fdca:1a2b::11"},
	} {
		t.Run(family.name, func(t *testing.T) {
			peerIP, deviceIP := netip.MustParseAddr(family.peer), netip.MustParseAddr(family.device)
			exchange := func(fromPeer bool, source, target netip.Addr, sourcePort, targetPort uint16, tcp bool, flags byte, sequence, ack uint32, allowed bool) {
				t.Helper()
				input, output, sourceMAC, routerMAC := device, peer, "02:00:00:00:00:13", "02:00:00:00:01:13"
				if fromPeer {
					input, output, sourceMAC, routerMAC = peer, device, "02:00:00:00:00:10", "02:00:00:00:01:10"
				}
				frame := packetFrame(t, packetDatagram{source: source, destination: target,
					sourceMAC: sourceMAC, destinationMAC: routerMAC, sourcePort: sourcePort, destinationPort: targetPort,
					isTCP: tcp, tcpFlags: flags, sequence: sequence, acknowledgment: ack,
					payload: fmt.Sprintf("synthetic-controller-%s-%d-%d-%t", family.name, sourcePort, targetPort, allowed),
				})
				sendPacket(ctx, t, input, frame)
				receivePacket(ctx, t, output, frame, allowed)
			}
			controllerUDP := func(port uint16, target netip.Addr, allowed bool) {
				t.Helper()
				exchange(true, peerIP, target, port, 6053, false, 0, 0, 0, allowed)
				exchange(false, target, peerIP, 6053, port, false, 0, 0, 0, allowed)
			}
			// No to-device directory grant: only genuine device initiation is leased.
			applyGuardFixture(ctx, t, oneGuardDirection(t, guardPacketBatch(t, deviceIP, peerIP, true), "from"))
			controllerUDP(47000, deviceIP, true)
			exchange(false, deviceIP, peerIP, 47001, 6053, false, 0, 0, 0, true)
			exchange(true, peerIP, deviceIP, 6053, 47001, false, 0, 0, 0, true)
			// Removing every runtime lease must preserve static controller geometry
			// and historical classification, without preserving device initiation.
			prepared, err := prepareGuards(ctx, &preparedBatch{data: clearBatch(t)})
			if err != nil {
				t.Fatal(err)
			}
			applyGuardFixture(ctx, t, prepared.batch.data)
			inventory, err := process.inspectGuards(ctx, layout)
			if err != nil || inventory.leases != 0 || len(inventory.cohort) != 1 {
				t.Fatalf("seal changed immutable controller geometry or deny history: %v", err)
			}
			controllerUDP(47000, deviceIP, true)
			controllerUDP(47002, deviceIP, true)
			controllerUDP(47003, netip.MustParseAddr(family.neighbor), true)
			exchange(false, deviceIP, peerIP, 47001, 6053, false, 0, 0, 0, false)
			exchange(false, deviceIP, peerIP, 47004, 6053, false, 0, 0, 0, false)
			exchange(true, peerIP, deviceIP, 6053, 47001, false, 0, 0, 0, false)
			// A TCP handshake remains possible with every directory lease sealed.
			exchange(true, peerIP, deviceIP, 47005, 6053, true, 0x02, 100, 0, true)
			exchange(false, deviceIP, peerIP, 6053, 47005, true, 0x12, 200, 101, true)
			exchange(true, peerIP, deviceIP, 47005, 6053, true, 0x10, 101, 201, true)
			exchange(false, deviceIP, peerIP, 47006, 6053, true, 0x10, 100, 1, false)
			exchange(true, netip.MustParseAddr(family.otherController), deviceIP, 47007, 6053, false, 0, 0, 0, false)
			// The exact identity arriving on the wrong ingress cannot get a tag.
			exchange(false, peerIP, deviceIP, 47008, 6053, false, 0, 0, 0, false)
			for _, hook := range []struct{ family, table, chain string }{
				{"inet", "controller_router_fixture", "change_forward"},
				{"netdev", "controller_endpoint_fixture", "change_egress"},
			} {
				// A mismatched leg must not fall through either the late forward
				// guard or final physical egress, even after the router accepted.
				packetNft(ctx, t, "add rule "+hook.family+" "+hook.table+" "+hook.chain+
					" meta l4proto udp udp sport 47010 meta mark & 0xff000000 == 0xb1000000 counter name changed_handoff meta mark set 0xb100ffff")
				exchange(true, peerIP, deviceIP, 47010, 6053, false, 0, 0, 0, false)
				data := kernelFixtureCommand(ctx, t, "list", "counter", hook.family, hook.table, "changed_handoff")
				var listing struct {
					Objects []struct {
						Counter *struct {
							Packets uint64 `json:"packets"`
						} `json:"counter"`
					} `json:"nftables"`
				}
				if err := json.Unmarshal(data, &listing); err != nil {
					t.Fatal(err)
				}
				if len(listing.Objects) != 2 || listing.Objects[1].Counter == nil || listing.Objects[1].Counter.Packets != 1 {
					t.Fatalf("changed controller handoff did not reach %s mutation counter", hook.family)
				}
				packetNft(ctx, t, "flush chain "+hook.family+" "+hook.table+" "+hook.chain+
					"; reset counter "+hook.family+" "+hook.table+" changed_handoff")
			}
			set := "protected6"
			if peerIP.Is4() {
				set = "protected4"
			}
			before := guardFixtureCounter(ctx, t, "controller_router_fixture", "protected_drop")
			packetNft(ctx, t, "add element inet controller_router_fixture "+set+" { "+deviceIP.String()+" }")
			controllerUDP(47000, deviceIP, false)
			controllerUDP(47009, deviceIP, false)
			// Two packets belong to the established flow; the new original also
			// reaches the router floor. Its unsolicited reply is denied earlier.
			if guardFixtureCounter(ctx, t, "controller_router_fixture", "protected_drop") != before+3 {
				t.Fatal("controller capability bypassed router-owned protected checks")
			}
			packetNft(ctx, t, "flush set inet controller_router_fixture "+set)
		})
	}
	// Provisional controller marks are not a new cross-table directory bridge.
	packetNft(ctx, t, "flush chain inet controller_router_fixture controller_allow")
	frame := packetFrame(t, packetDatagram{source: netip.MustParseAddr("10.240.0.10"), destination: netip.MustParseAddr("10.240.3.10"),
		sourceMAC: "02:00:00:00:00:10", destinationMAC: "02:00:00:00:01:10", sourcePort: 47100, destinationPort: 6053,
		payload: "synthetic-missing-controller-router-policy"})
	sendPacket(ctx, t, peer, frame)
	receivePacket(ctx, t, device, frame, false)
}
