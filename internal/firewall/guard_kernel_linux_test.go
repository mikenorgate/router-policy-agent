//go:build integration && kernel && linux

package firewall

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/netip"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/mikenorgate/router-policy-agent/internal/binding"
	"github.com/mikenorgate/router-policy-agent/internal/policy"
)

func TestKernelNativeGuardPermitAndRevoke(t *testing.T) {
	requireKernelIsolation(t)
	t.Cleanup(func() { requireKernelIsolation(t) })
	ctx, cancel := context.WithTimeout(t.Context(), 60*time.Second)
	defer cancel()
	setupPacketLinks(ctx, t)
	for _, name := range []string{"lan11", "lan12", "lan14", "lan15"} {
		packetIP(ctx, t, "link", "add", name, "type", "dummy")
		t.Cleanup(func() {
			cleanup, cancel := context.WithTimeout(context.WithoutCancel(t.Context()), 2*time.Second)
			defer cancel()
			packetIP(cleanup, t, "link", "delete", name)
		})
	}
	_, _, baseline, _ := renderFixture(t)
	layout, err := newGuardLayout(baseline)
	if err != nil {
		t.Fatal(err)
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
	// The router fixture is a separate table: it cannot jump to our regular
	// permit chain. Its default drop needs the image-owned provisional bridge;
	// independent protected drops precede its stateful and bridge accepts.
	bridge := make([]string, 0, 4)
	for _, rule := range guardBridgeRules() {
		bridge = append(bridge, strings.TrimSuffix(rule, "accept")+"counter name fixture_bridge_accept accept")
	}
	packetNft(ctx, t, `
table netdev guard_endpoint_fixture {
 chain peer_endpoint { type filter hook ingress device "peer0" priority 0; policy drop; }
 chain device_endpoint { type filter hook ingress device "device0" priority 0; policy drop; }
}
table inet guard_router_fixture {
 set protected4 { type ipv4_addr . inet_service; }
 set protected6 { type ipv6_addr . inet_service; }
 counter fixture_protected_drop {}
 counter fixture_bridge_accept {}
 counter fixture_stateful_accept {}
 chain fixture_stateful {
  ct state established counter name fixture_stateful_accept accept
 }
 chain fixture_bridge {
`+strings.Join(bridge, "\n")+`
 }
 chain fixture_application {
  type filter hook forward priority 0; policy drop;
  meta l4proto { tcp, udp } ip saddr . ct original proto-dst @protected4 counter name fixture_protected_drop drop
  meta l4proto { tcp, udp } ip daddr . ct original proto-dst @protected4 counter name fixture_protected_drop drop
  meta l4proto { tcp, udp } ip6 saddr . ct original proto-dst @protected6 counter name fixture_protected_drop drop
  meta l4proto { tcp, udp } ip6 daddr . ct original proto-dst @protected6 counter name fixture_protected_drop drop
  jump fixture_stateful
  jump fixture_bridge
  meta l4proto udp udp dport 6060 accept
 }
}
`)
	t.Cleanup(func() {
		cleanup, cancel := context.WithTimeout(context.WithoutCancel(t.Context()), 2*time.Second)
		defer cancel()
		packetNft(cleanup, t, "delete table netdev guard_endpoint_fixture; delete table inet guard_router_fixture")
	})
	peer, device := packetSocket(t, "peer0"), packetSocket(t, "device0")
	for _, family := range []struct{ name, peer, device string }{
		{name: "ipv4", peer: "10.240.0.10", device: "10.240.3.10"},
		{name: "ipv6", peer: "fdca:1a2b::10", device: "fdca:1a2b:3::10"},
	} {
		t.Run(family.name, func(t *testing.T) {
			peerIP, deviceIP := netip.MustParseAddr(family.peer), netip.MustParseAddr(family.device)
			flows := []struct {
				name                        string
				fromPeer                    bool
				sourcePort, destinationPort uint16
			}{
				{name: "peer original", fromPeer: true, sourcePort: 40200, destinationPort: 6053},
				{name: "device reply", sourcePort: 6053, destinationPort: 40200},
				{name: "device original", sourcePort: 40201, destinationPort: 6053},
				{name: "peer reply", fromPeer: true, sourcePort: 6053, destinationPort: 40201},
			}
			// Remove only the fixture's shortcut so all four direction tags,
			// including correlated replies, must use the cross-table bridge.
			packetNft(ctx, t, "flush chain inet guard_router_fixture fixture_stateful")
			bridgeBefore := guardFixtureCounter(ctx, t, "guard_router_fixture", "fixture_bridge_accept")
			for _, permitted := range []bool{true, false} {
				batch := guardPacketBatch(t, deviceIP, peerIP, permitted)
				applyGuardFixture(ctx, t, batch)
				for _, flow := range flows {
					input, output, source, target := device, peer, deviceIP, peerIP
					sourceMAC, routerMAC := "02:00:00:00:00:13", "02:00:00:00:01:13"
					if flow.fromPeer {
						input, output, source, target = peer, device, peerIP, deviceIP
						sourceMAC, routerMAC = "02:00:00:00:00:10", "02:00:00:00:01:10"
					}
					frame := packetFrame(t, packetDatagram{
						source: source, destination: target, sourceMAC: sourceMAC, destinationMAC: routerMAC,
						sourcePort: flow.sourcePort, destinationPort: flow.destinationPort,
						payload: family.name + "-" + flow.name,
					})
					sendPacket(ctx, t, input, frame)
					receivePacket(ctx, t, output, frame, permitted)
				}
			}
			if guardFixtureCounter(ctx, t, "guard_router_fixture", "fixture_bridge_accept") != bridgeBefore+4 {
				t.Fatal("all four leased direction tags did not traverse the separate router bridge")
			}
			packetNft(ctx, t, "add rule inet guard_router_fixture fixture_stateful "+
				"ct state established counter name fixture_stateful_accept accept")
			t.Run("early permission does not override a missing router bridge", func(t *testing.T) {
				applyGuardFixture(ctx, t, guardPacketBatch(t, deviceIP, peerIP, true))
				packetNft(ctx, t, "flush chain inet guard_router_fixture fixture_bridge")
				t.Cleanup(func() {
					cleanup, cancel := context.WithTimeout(context.WithoutCancel(t.Context()), 2*time.Second)
					defer cancel()
					for _, rule := range bridge {
						packetNft(cleanup, t, "add rule inet guard_router_fixture fixture_bridge "+rule)
					}
				})
				for _, fromPeer := range []bool{true, false} {
					input, output, source, target := device, peer, deviceIP, peerIP
					sourceMAC, routerMAC, port := "02:00:00:00:00:13", "02:00:00:00:01:13", uint16(41600)
					if fromPeer {
						input, output, source, target = peer, device, peerIP, deviceIP
						sourceMAC, routerMAC, port = "02:00:00:00:00:10", "02:00:00:00:01:10", 41601
					}
					frame := packetFrame(t, packetDatagram{
						source: source, destination: target, sourceMAC: sourceMAC, destinationMAC: routerMAC,
						sourcePort: port, destinationPort: 6053, payload: "synthetic-missing-bridge",
					})
					sendPacket(ctx, t, input, frame)
					receivePacket(ctx, t, output, frame, false)
				}
			})
			t.Run("neighboring listener does not inherit permission", func(t *testing.T) {
				applyGuardFixture(ctx, t, guardPacketBatch(t, deviceIP, peerIP, true))
				for _, fromPeer := range []bool{true, false} {
					input, output, source, target := device, peer, deviceIP, peerIP
					sourceMAC, routerMAC, port := "02:00:00:00:00:13", "02:00:00:00:01:13", uint16(41500)
					if fromPeer {
						input, output, source, target = peer, device, peerIP, deviceIP
						sourceMAC, routerMAC, port = "02:00:00:00:00:10", "02:00:00:00:01:10", 41501
					}
					for _, isTCP := range []bool{true, false} {
						frame := packetFrame(t, packetDatagram{
							source: source, destination: target, sourceMAC: sourceMAC, destinationMAC: routerMAC,
							sourcePort: port, destinationPort: 6054, isTCP: isTCP, tcpFlags: 0x02, sequence: 100,
							payload: "synthetic-neighboring-listener",
						})
						sendPacket(ctx, t, input, frame)
						receivePacket(ctx, t, output, frame, false)
					}
				}
			})
			t.Run("protected endpoint wins over granted established flow", func(t *testing.T) {
				applyGuardFixture(ctx, t, guardPacketBatch(t, deviceIP, peerIP, true))
				protectedBefore := guardFixtureCounter(ctx, t, "guard_router_fixture", "fixture_protected_drop")
				for _, blocked := range []bool{false, true} {
					before := guardStatefulCount(ctx, t)
					if blocked {
						set := "protected6"
						if peerIP.Is4() {
							set = "protected4"
						}
						packetNft(ctx, t, "add element inet guard_router_fixture "+set+" { "+peerIP.String()+" . 6053 }")
						t.Cleanup(func() {
							cleanup, cancel := context.WithTimeout(context.WithoutCancel(t.Context()), 2*time.Second)
							defer cancel()
							packetNft(cleanup, t, "flush set inet guard_router_fixture "+set)
						})
					}
					for _, flow := range flows {
						input, output, source, target := device, peer, deviceIP, peerIP
						sourceMAC, routerMAC := "02:00:00:00:00:13", "02:00:00:00:01:13"
						if flow.fromPeer {
							input, output, source, target = peer, device, peerIP, deviceIP
							sourceMAC, routerMAC = "02:00:00:00:00:10", "02:00:00:00:01:10"
						}
						frame := packetFrame(t, packetDatagram{
							source: source, destination: target, sourceMAC: sourceMAC, destinationMAC: routerMAC,
							sourcePort: flow.sourcePort, destinationPort: flow.destinationPort,
							payload: "synthetic-protected-" + flow.name,
						})
						sendPacket(ctx, t, input, frame)
						receivePacket(ctx, t, output, frame, !blocked)
					}
					if blocked && guardStatefulCount(ctx, t) != before {
						t.Fatal("protected established traffic reached the router shortcut")
					}
				}
				if guardFixtureCounter(ctx, t, "guard_router_fixture", "fixture_protected_drop") != protectedBefore+4 {
					t.Fatal("granted established flows did not encounter the independent protected endpoint gate")
				}
			})
			t.Run("retained tag cannot authorize a tuple changed after bridge", func(t *testing.T) {
				requireKernelHeaderMutation(t)
				applyGuardFixture(ctx, t, guardPacketBatch(t, deviceIP, peerIP, true))
				address, unknown := "ip6", "fdca:1a2b:3::11"
				if deviceIP.Is4() {
					address, unknown = "ip", "10.240.3.11"
				}
				// The first counter proves the provisional tag and changed tuple
				// reach the late guard. The second detects a fallthrough there,
				// independently of final MAC checks or transport checksum handling.
				packetNft(ctx, t, fmt.Sprintf(`
table inet guard_recheck_fixture {
 counter before_confirmation {}
 counter changed_tuple {}
 counter after_confirmation {}
 chain mutate {
  type filter hook forward priority 100; policy accept;
  meta l4proto udp udp sport 41400 %s daddr %s meta mark & 0xff000000 == 0xa3000000 counter name before_confirmation %s daddr set %s
 }
 chain changed {
  type filter hook forward priority 101; policy accept;
  meta l4proto udp udp sport 41400 %s daddr %s meta mark & 0xff000000 == 0xa3000000 counter name changed_tuple
 }
 chain observe {
  type filter hook forward priority 151; policy accept;
  meta l4proto udp udp sport 41400 counter name after_confirmation
 }
}`,
					address,
					deviceIP,
					address,
					unknown,
					address,
					unknown,
				))
				t.Cleanup(func() {
					cleanup, cancel := context.WithTimeout(context.WithoutCancel(t.Context()), 2*time.Second)
					defer cancel()
					packetNft(cleanup, t, "delete table inet guard_recheck_fixture")
				})
				frame := packetFrame(t, packetDatagram{
					source: peerIP, destination: deviceIP,
					sourceMAC: "02:00:00:00:00:10", destinationMAC: "02:00:00:00:01:10",
					sourcePort: 41400, destinationPort: 6053, payload: "synthetic-changed-tuple",
				})
				sendPacket(ctx, t, peer, frame)
				receivePacket(ctx, t, device, frame, false)
				if guardFixtureCounter(ctx, t, "guard_recheck_fixture", "before_confirmation") != 1 ||
					guardFixtureCounter(ctx, t, "guard_recheck_fixture", "changed_tuple") != 1 ||
					guardFixtureCounter(ctx, t, "guard_recheck_fixture", "after_confirmation") != 0 {
					t.Fatal("changed tuple did not encounter a closed late leased guard")
				}
			})
			t.Run("lease withdrawn between hooks is rechecked in every direction", func(t *testing.T) {
				applyGuardFixture(ctx, t, guardPacketBatch(t, deviceIP, peerIP, true))
				address, suffix := "ip6", "6_udp"
				if deviceIP.Is4() {
					address, suffix = "ip", "4_udp"
				}
				// Deliberately remove only the queried physical lease after the
				// early check. Final mirrors remain live: an egress check cannot
				// substitute for the late guard. These are test-only fault rules,
				// not production packet-controlled mutation or lease renewal.
				withdraw := []string{
					"add counter inet router_policy_agent fixture_withdrawal",
					"add chain inet router_policy_agent fixture_withdrawal { type filter hook forward priority 100; policy accept; }",
				}
				for _, direction := range []string{"from", "to"} {
					name := "lease_" + direction + suffix
					sourceDirection, targetDirection := "reply", "original"
					if direction == "from" {
						sourceDirection, targetDirection = "original", "reply"
					}
					sourceCounter := "fixture_" + direction + "_" + sourceDirection
					targetCounter := "fixture_" + direction + "_" + targetDirection
					withdraw = append(withdraw,
						"add counter inet router_policy_agent "+sourceCounter,
						"add counter inet router_policy_agent "+targetCounter,
						"add rule inet router_policy_agent fixture_withdrawal meta l4proto udp ct direction "+sourceDirection+" "+
							"iifname . ether saddr . "+address+" saddr . "+address+" daddr . ct original proto-dst @"+name+
							" counter name fixture_withdrawal counter name "+sourceCounter+" delete @"+name+" { "+
							"iifname . ether saddr . "+address+" saddr . "+address+" daddr . ct original proto-dst }",
						"add rule inet router_policy_agent fixture_withdrawal meta l4proto udp ct direction "+targetDirection+" "+
							"oifname . "+address+" daddr . "+address+" saddr . ct original proto-dst @inbound_"+name+
							" counter name fixture_withdrawal counter name "+targetCounter+" delete @inbound_"+name+" { "+
							"oifname . "+address+" daddr . "+address+" saddr . ct original proto-dst }",
					)
				}
				packetNft(ctx, t, strings.Join(withdraw, "\n")+`
table inet guard_recheck_fixture {
 counter after_confirmation {}
 chain observe {
  type filter hook forward priority 151; policy accept;
  meta l4proto udp counter name after_confirmation
 }
}`)
				t.Cleanup(func() {
					cleanup, cancel := context.WithTimeout(context.WithoutCancel(t.Context()), 2*time.Second)
					defer cancel()
					packetNft(cleanup, t, "flush chain inet router_policy_agent fixture_withdrawal; "+
						"delete chain inet router_policy_agent fixture_withdrawal; "+
						"delete counter inet router_policy_agent fixture_withdrawal; "+
						"delete table inet guard_recheck_fixture")
					for _, counter := range []string{
						"fixture_from_original", "fixture_from_reply", "fixture_to_original", "fixture_to_reply",
					} {
						packetNft(cleanup, t, "delete counter inet router_policy_agent "+counter)
					}
				})
				for _, flow := range flows {
					input, output, source, target := device, peer, deviceIP, peerIP
					sourceMAC, routerMAC := "02:00:00:00:00:13", "02:00:00:00:01:13"
					if flow.fromPeer {
						input, output, source, target = peer, device, peerIP, deviceIP
						sourceMAC, routerMAC = "02:00:00:00:00:10", "02:00:00:00:01:10"
					}
					frame := packetFrame(t, packetDatagram{
						source: source, destination: target, sourceMAC: sourceMAC, destinationMAC: routerMAC,
						sourcePort: flow.sourcePort, destinationPort: flow.destinationPort,
						payload: "synthetic-between-hooks-" + flow.name,
					})
					sendPacket(ctx, t, input, frame)
					receivePacket(ctx, t, output, frame, false)
				}
				if guardFixtureCounter(ctx, t, ownedTable, "fixture_withdrawal") != 4 ||
					guardFixtureCounter(ctx, t, "guard_recheck_fixture", "after_confirmation") != 0 {
					t.Fatal("late guard did not recheck all four physical lease directions")
				}
				for _, counter := range []string{
					"fixture_from_original", "fixture_from_reply", "fixture_to_original", "fixture_to_reply",
				} {
					if guardFixtureCounter(ctx, t, ownedTable, counter) != 1 {
						t.Fatal("between-hook withdrawal did not exercise each initiation and correlated reply independently")
					}
				}
			})
			t.Run("tcp established flow revocation", func(t *testing.T) {
				applyGuardFixture(ctx, t, guardPacketBatch(t, deviceIP, peerIP, true))
				for _, fromPeer := range []bool{true, false} {
					first, second, source, target := device, peer, deviceIP, peerIP
					firstMAC, firstRouter := "02:00:00:00:00:13", "02:00:00:00:01:13"
					secondMAC, secondRouter := "02:00:00:00:00:10", "02:00:00:00:01:10"
					port := uint16(40301)
					if fromPeer {
						first, second, source, target = peer, device, peerIP, deviceIP
						firstMAC, firstRouter, secondMAC, secondRouter = secondMAC, secondRouter, firstMAC, firstRouter
						port = 40300
					}
					for _, step := range []struct {
						flags         byte
						sequence, ack uint32
						isReply       bool
					}{
						{flags: 0x02, sequence: 100},
						{flags: 0x12, sequence: 200, ack: 101, isReply: true},
						{flags: 0x10, sequence: 101, ack: 201},
						{flags: 0x18, sequence: 101, ack: 201},
					} {
						input, output := first, second
						datagram := packetDatagram{
							source: source, destination: target, sourceMAC: firstMAC, destinationMAC: firstRouter,
							sourcePort: port, destinationPort: 6053, isTCP: true,
							tcpFlags: step.flags, sequence: step.sequence, acknowledgment: step.ack,
						}
						if step.flags == 0x18 {
							datagram.payload = "synthetic-tcp-data"
						}
						if step.isReply {
							input, output = second, first
							datagram.source, datagram.destination = target, source
							datagram.sourceMAC, datagram.destinationMAC = secondMAC, secondRouter
							datagram.sourcePort, datagram.destinationPort = 6053, port
						}
						frame := packetFrame(t, datagram)
						sendPacket(ctx, t, input, frame)
						receivePacket(ctx, t, output, frame, true)
					}
				}
				statefulBefore := guardStatefulCount(ctx, t)
				if statefulBefore == 0 {
					t.Fatal("test did not exercise the established fast path")
				}
				for _, permitted := range []bool{true, false} {
					if !permitted {
						applyGuardFixture(ctx, t, guardPacketBatch(t, deviceIP, peerIP, false))
					}
					for _, flow := range []struct {
						fromPeer               bool
						sourcePort, targetPort uint16
					}{
						{fromPeer: true, sourcePort: 40300, targetPort: 6053},
						{sourcePort: 6053, targetPort: 40300},
						{sourcePort: 40301, targetPort: 6053},
						{fromPeer: true, sourcePort: 6053, targetPort: 40301},
					} {
						input, output, source, target := device, peer, deviceIP, peerIP
						sourceMAC, routerMAC := "02:00:00:00:00:13", "02:00:00:00:01:13"
						if flow.fromPeer {
							input, output, source, target = peer, device, peerIP, deviceIP
							sourceMAC, routerMAC = "02:00:00:00:00:10", "02:00:00:00:01:10"
						}
						sequence, ack := uint32(119), uint32(201)
						if flow.sourcePort == 6053 {
							sequence, ack = 201, 119
						}
						frame := packetFrame(t, packetDatagram{
							source: source, destination: target, sourceMAC: sourceMAC, destinationMAC: routerMAC,
							sourcePort: flow.sourcePort, destinationPort: flow.targetPort, isTCP: true,
							tcpFlags: 0x10, sequence: sequence, acknowledgment: ack,
						})
						sendPacket(ctx, t, input, frame)
						receivePacket(ctx, t, output, frame, permitted)
					}
					if permitted {
						statefulBefore = guardStatefulCount(ctx, t)
					}
				}
				if guardStatefulCount(ctx, t) != statefulBefore {
					t.Fatal("revoked TCP traffic reached the established shortcut")
				}
				frame := packetFrame(t, packetDatagram{
					source: peerIP, destination: deviceIP,
					sourceMAC: "02:00:00:00:00:10", destinationMAC: "02:00:00:00:01:10",
					sourcePort: 40400, destinationPort: 6053, isTCP: true, tcpFlags: 0x02, sequence: 300,
				})
				sendPacket(ctx, t, peer, frame)
				receivePacket(ctx, t, device, frame, false)
			})
			t.Run("kernel expiry retains closed classification", func(t *testing.T) {
				batch := guardPacketBatch(t, deviceIP, peerIP, true)
				applyGuardFixture(ctx, t, shortGuardFixture(t, batch))
				frame := packetFrame(t, packetDatagram{
					source: peerIP, destination: deviceIP,
					sourceMAC: "02:00:00:00:00:10", destinationMAC: "02:00:00:00:01:10",
					sourcePort: 40500, destinationPort: 6053, payload: "synthetic-expiring-flow",
				})
				sendPacket(ctx, t, peer, frame)
				receivePacket(ctx, t, device, frame, true)
				waitKernelFixture(ctx, t, 1200*time.Millisecond)
				sendPacket(ctx, t, peer, frame)
				receivePacket(ctx, t, device, frame, false)
				for _, family := range []string{"inet", "netdev"} {
					inventory := kernelFixtureCommand(ctx, t, "list", "table", family, ownedTable)
					if elementCount(t, inventory, cohortSet) != 1 {
						t.Fatal("lease expiry erased managed classification")
					}
				}
			})
			t.Run("reverse initiation requires its own grant", func(t *testing.T) {
				for _, allowed := range []string{"from", "to"} {
					batch := oneGuardDirection(t, guardPacketBatch(t, deviceIP, peerIP, true), allowed)
					applyGuardFixture(ctx, t, batch)
					for _, fromPeer := range []bool{true, false} {
						input, output, source, target := device, peer, deviceIP, peerIP
						sourceMAC, routerMAC := "02:00:00:00:00:13", "02:00:00:00:01:13"
						port := uint16(40700)
						if allowed == "to" {
							port = 40800
						}
						if fromPeer {
							input, output, source, target = peer, device, peerIP, deviceIP
							sourceMAC, routerMAC, port = "02:00:00:00:00:10", "02:00:00:00:01:10", port+1
						}
						frame := packetFrame(t, packetDatagram{
							source: source, destination: target, sourceMAC: sourceMAC, destinationMAC: routerMAC,
							sourcePort: port, destinationPort: 6053, payload: "synthetic-direction-" + allowed,
						})
						sendPacket(ctx, t, input, frame)
						receivePacket(ctx, t, output, frame, fromPeer == (allowed == "to"))
					}
				}
			})
			t.Run("unknown device address cannot use legacy permit", func(t *testing.T) {
				applyGuardFixture(ctx, t, guardPacketBatch(t, deviceIP, peerIP, false))
				unknown := netip.MustParseAddr("fdca:1a2b:3::11")
				if deviceIP.Is4() {
					unknown = netip.MustParseAddr("10.240.3.11")
				}
				for _, fromPeer := range []bool{true, false} {
					input, output, source, target := device, peer, unknown, peerIP
					sourceMAC, routerMAC := "02:00:00:00:00:13", "02:00:00:00:01:13"
					if fromPeer {
						input, output, source, target = peer, device, peerIP, unknown
						sourceMAC, routerMAC = "02:00:00:00:00:10", "02:00:00:00:01:10"
					}
					frame := packetFrame(t, packetDatagram{
						source: source, destination: target, sourceMAC: sourceMAC, destinationMAC: routerMAC,
						sourcePort: 40900, destinationPort: 6060, payload: "synthetic-unknown-address",
					})
					sendPacket(ctx, t, input, frame)
					receivePacket(ctx, t, output, frame, false)
				}
			})
			t.Run("address reuse does not transfer permission", func(t *testing.T) {
				applyGuardFixture(ctx, t, guardPacketBatch(t, deviceIP, peerIP, true))
				packetIP(ctx, t, "link", "set", "device0", "address", "02:00:00:00:00:14")
				packetIP(ctx, t, "neighbor", "replace", deviceIP.String(), "lladdr", "02:00:00:00:00:14", "dev", "lan13", "nud", "permanent")
				defer func() {
					cleanup, cancel := context.WithTimeout(context.WithoutCancel(t.Context()), 2*time.Second)
					defer cancel()
					packetIP(cleanup, t, "link", "set", "device0", "address", "02:00:00:00:00:13")
					packetIP(cleanup, t, "neighbor", "replace", deviceIP.String(), "lladdr", "02:00:00:00:00:13", "dev", "lan13", "nud", "permanent")
				}()
				for _, permitted := range []bool{true, false} {
					if !permitted {
						applyGuardFixture(ctx, t, guardPacketBatch(t, deviceIP, peerIP, false))
					}
					frame := packetFrame(t, packetDatagram{
						source: peerIP, destination: deviceIP,
						sourceMAC: "02:00:00:00:00:10", destinationMAC: "02:00:00:00:01:10",
						sourcePort: 41000, destinationPort: 6053, payload: "synthetic-new-occupant",
					})
					sendPacket(ctx, t, peer, frame)
					receivePacket(ctx, t, device, frame, false)
				}
			})
			t.Run("unrelated legacy flow remains working", func(t *testing.T) {
				applyGuardFixture(ctx, t, guardPacketBatch(t, deviceIP, peerIP, false))
				unrelated := netip.MustParseAddr("fdca:1a2b:3::12")
				if deviceIP.Is4() {
					unrelated = netip.MustParseAddr("10.240.3.12")
				}
				packetIP(ctx, t, "link", "set", "device0", "address", "02:00:00:00:00:14")
				packetIP(ctx, t, "neighbor", "add", unrelated.String(), "lladdr", "02:00:00:00:00:14", "dev", "lan13", "nud", "permanent")
				defer func() {
					cleanup, cancel := context.WithTimeout(context.WithoutCancel(t.Context()), 2*time.Second)
					defer cancel()
					packetIP(cleanup, t, "link", "set", "device0", "address", "02:00:00:00:00:13")
					packetIP(cleanup, t, "neighbor", "delete", unrelated.String(), "dev", "lan13")
				}()
				other := packetSocket(t, "device0")
				for _, isReply := range []bool{false, true} {
					input, output, source, target := peer, other, peerIP, unrelated
					sourceMAC, routerMAC, sourcePort, targetPort := "02:00:00:00:00:10", "02:00:00:00:01:10", uint16(41100), uint16(6060)
					if isReply {
						input, output, source, target = other, peer, unrelated, peerIP
						sourceMAC, routerMAC, sourcePort, targetPort = "02:00:00:00:00:14", "02:00:00:00:01:13", targetPort, sourcePort
					}
					frame := packetFrame(t, packetDatagram{
						source: source, destination: target, sourceMAC: sourceMAC, destinationMAC: routerMAC,
						sourcePort: sourcePort, destinationPort: targetPort, payload: "synthetic-unrelated-flow",
					})
					sendPacket(ctx, t, input, frame)
					receivePacket(ctx, t, output, frame, true)
				}
			})
		})
	}
}

// Linux restricts payload writes in user namespaces. Rootless runners still
// exercise the native bridge and actual between-hook lease withdrawal. CI must
// require the header-changing test as well; insufficient isolation/capabilities
// for the general kernel suite remain errors, not skips.
func requireKernelHeaderMutation(t *testing.T) {
	t.Helper()
	data, err := os.ReadFile("/proc/self/uid_map")
	if err != nil {
		t.Fatal(err)
	}
	initial := []string{"0", "0", "4294967295"}
	if strings.Join(strings.Fields(string(data)), " ") == strings.Join(initial, " ") {
		return
	}
	if os.Getenv("ROUTER_POLICY_REQUIRE_HEADER_TEST") == "1" {
		t.Fatal("required header mutation test needs an isolated runner in the initial user namespace")
	}
	t.Skip("packet-header mutation requires the initial user namespace; mandatory in CI")
}

func guardStatefulCount(ctx context.Context, t *testing.T) uint64 {
	t.Helper()
	return guardFixtureCounter(ctx, t, "guard_router_fixture", "fixture_stateful_accept")
}

func guardFixtureCounter(ctx context.Context, t *testing.T, table, name string) uint64 {
	t.Helper()
	data := kernelFixtureCommand(ctx, t, "list", "counter", "inet", table, name)
	var decoded struct {
		Objects []struct {
			Counter *struct {
				Packets uint64 `json:"packets"`
			} `json:"counter"`
		} `json:"nftables"`
	}
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatal(err)
	}
	for _, object := range decoded.Objects {
		if object.Counter != nil {
			return object.Counter.Packets
		}
	}
	t.Fatal("synthetic guard counter absent")
	return 0
}

func oneGuardDirection(t *testing.T, data []byte, direction string) []byte {
	t.Helper()
	var guarded guardChanges
	if err := json.Unmarshal(data, &guarded); err != nil {
		t.Fatal(err)
	}
	logical := guardChanges{Commands: make([]change, 0)}
	for _, command := range guarded.Commands {
		if command.Flush != nil && ownedReference(command.Flush.Set) && isGrantSet(command.Flush.Set.Name) {
			logical.Commands = append(logical.Commands, command)
		}
		if command.Add != nil {
			value := command.Add.Element
			if value.Family == "inet" && (value.Name == cohortSet || strings.HasPrefix(value.Name, "lease_"+direction)) {
				logical.Commands = append(logical.Commands, command)
			}
		}
	}
	source, err := json.Marshal(logical)
	if err != nil {
		t.Fatal(err)
	}
	prepared, err := prepareGuards(t.Context(), &preparedBatch{data: source})
	if err != nil {
		t.Fatal(err)
	}
	return prepared.batch.data
}

func guardPacketBatch(t *testing.T, device, peer netip.Addr, permitted bool) []byte {
	t.Helper()
	renderer, replacement, _, input := renderFixture(t)
	anchor := policy.CaptureAge()
	now := time.Now().UTC()
	input.Now, input.Directory.ObservedAt, input.Bindings.ObservedAt = now, now, now
	input.Directory.Groups = input.Directory.Groups[:1]
	input.Directory.Devices[0].MAC, input.Directory.Devices[0].Active = "02:00:00:00:00:13", permitted
	input.Directory.Devices[0].GroupIDs = []string{input.Directory.Groups[0].ID}
	for _, direction := range []policy.Direction{policy.FromDevice, policy.ToDevice} {
		for _, protocol := range []string{"tcp", "udp"} {
			id := string(direction) + "-" + protocol
			group := rendererAccessGroup(
				t,
				id,
				false,
				policy.Rule{ID: id, Direction: direction,
					Peer:     policy.Peer{Addresses: []string{fmt.Sprintf("%s/%d", peer, peer.BitLen())}},
					Protocol: protocol, DestinationPorts: []uint16{6053}, Reason: "Synthetic packet qualification"},
			)
			input.Directory.Groups = append(input.Directory.Groups, group)
			input.Directory.Devices[0].GroupIDs = append(input.Directory.Devices[0].GroupIDs, id)
		}
	}
	source := "qualified_ipv6"
	if device.Is4() {
		source = "kea_dhcp4"
	}
	input.Bindings.Records[0].MAC, input.Bindings.Records[0].AssociatedAt = "02:00:00:00:00:13", now
	input.Bindings.Records[0].Addresses = []binding.Address{{
		IP: device, Source: source, OwnershipID: "synthetic-packet-owner",
		ObservedAt: now, ValidUntil: now.Add(time.Hour),
	}}
	authorization, err := renderer.compiler.CompileAuthorization(t.Context(), input, anchor)
	if err != nil {
		t.Fatal(err)
	}
	candidate, err := authorization.Snapshot(t.Context())
	if err != nil || (permitted && len(candidate.Grants) != 4) || (!permitted && len(candidate.Grants) != 0) {
		t.Fatalf("synthetic packet policy did not compile its exact permissions: %v", err)
	}
	replacement.authorization, replacement.now, replacement.cohort = authorization, time.Now().UTC(), []string{"02:00:00:00:00:13"}
	logical, err := renderer.prepare(t.Context(), replacement)
	if err != nil {
		t.Fatal(err)
	}
	prepared, err := prepareGuards(t.Context(), logical)
	if err != nil {
		t.Fatal(err)
	}
	if err := validateGuardBatch(t.Context(), prepared.batch.data); err != nil {
		t.Fatal(err)
	}
	return prepared.batch.data
}

// This fixture shortens all physical leases together to exercise actual kernel
// expiry. It is not a production lifetime override or UTC/suspend qualification.
func shortGuardFixture(t *testing.T, data []byte) []byte {
	t.Helper()
	var decoded guardChanges
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatal(err)
	}
	changed := false
	for index := range decoded.Commands {
		command := &decoded.Commands[index]
		if command.Add == nil {
			continue
		}
		name := command.Add.Element.Name
		if name == cohortSet || name == classified4Set || name == classified6Set {
			continue
		}
		for index, raw := range command.Add.Element.Values {
			var value struct {
				Element struct {
					Value   json.RawMessage `json:"val"`
					Timeout int             `json:"timeout"`
				} `json:"elem"`
			}
			if err := json.Unmarshal(raw, &value); err != nil {
				t.Fatal(err)
			}
			value.Element.Timeout = 1
			encoded, err := json.Marshal(value)
			if err != nil {
				t.Fatal(err)
			}
			command.Add.Element.Values[index], changed = encoded, true
		}
	}
	if !changed {
		t.Fatal("expiry fixture did not shorten its leases")
	}
	short, err := json.Marshal(decoded)
	if err != nil {
		t.Fatal(err)
	}
	return short
}

func applyGuardFixture(ctx context.Context, t *testing.T, data []byte) {
	t.Helper()
	if err := validateGuardBatch(ctx, data); err != nil {
		t.Fatal(err)
	}
	executeGuardFixture(ctx, t, data)
}

// This executor is only for acknowledged disposable kernel tests. Production
// guarded mutation remains unavailable until its independent writer/floor gate.
func executeGuardFixture(ctx context.Context, t *testing.T, data []byte) {
	t.Helper()
	command := exec.CommandContext(ctx, "/usr/sbin/nft", "--json", "--file", "-")
	command.Env = []string{"LC_ALL=C", "PATH=/usr/sbin:/usr/bin"}
	command.Stdin = bytes.NewReader(data)
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("isolated synthetic guarded transaction failed: %v, %s", err, output)
	}
}
