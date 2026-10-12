//go:build integration && kernel && linux

package firewall

import (
	"context"
	"fmt"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/mikenorgate/router-policy-agent/internal/binding"
	"github.com/mikenorgate/router-policy-agent/internal/policy"
)

func scopePacketBatch(t *testing.T, device netip.Addr, network netip.Prefix) []byte {
	t.Helper()
	renderer, replacement, _, input := renderFixture(t)
	anchor, now := policy.CaptureAge(), time.Now().UTC()
	input.Now, input.Directory.ObservedAt, input.Bindings.ObservedAt = now, now, now
	input.Directory.Groups = input.Directory.Groups[:1]
	input.Directory.Devices[0].MAC = "02:00:00:00:00:13"
	input.Directory.Devices[0].GroupIDs = []string{input.Directory.Groups[0].ID}
	for _, direction := range []policy.Direction{policy.FromDevice, policy.ToDevice} {
		for _, protocol := range []string{"tcp", "udp"} {
			id := string(direction) + "-" + protocol
			group := rendererAccessGroup(t, id, false, policy.Rule{
				ID: id, Direction: direction, Protocol: protocol,
				Peer:                  policy.Peer{Addresses: []string{network.String()}},
				DestinationPortRanges: []policy.PortRange{{First: 6053, Last: 6055}},
				Reason:                "Synthetic interval packet qualification",
			})
			raw := strings.Replace(*group.Policy, `"schema_version":1`, `"schema_version":2`, 1)
			group.Policy = &raw
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
		IP: device, Source: source, OwnershipID: "synthetic-interval-owner",
		ObservedAt: now, ValidUntil: now.Add(time.Hour),
	}}
	authorization, err := renderer.compiler.CompileAuthorization(t.Context(), input, anchor)
	if err != nil {
		t.Fatal(err)
	}
	candidate, err := authorization.Snapshot(t.Context())
	if err != nil || len(candidate.Grants) != 4 || len(candidate.Denials) != 0 {
		t.Fatalf("synthetic interval policy failed: %v; grants=%d denials=%d", err, len(candidate.Grants), len(candidate.Denials))
	}
	replacement.authorization, replacement.now = authorization, time.Now().UTC()
	replacement.cohort = []string{"02:00:00:00:00:13"}
	logical, err := renderer.prepare(t.Context(), replacement)
	if err != nil {
		t.Fatal(err)
	}
	prepared, err := prepareGuards(t.Context(), logical)
	if err != nil {
		t.Fatal(err)
	}
	return prepared.batch.data
}

func TestKernelScopedPermitsAndRevocation(t *testing.T) {
	requireKernelIsolation(t)
	t.Cleanup(func() { requireKernelIsolation(t) })
	ctx, cancel := context.WithTimeout(t.Context(), 60*time.Second)
	defer cancel()
	setupPacketLinks(ctx, t)
	layout, process := setupClassifiedGuardFixture(ctx, t, []string{"lan10", "lan13"})
	packetNft(ctx, t, `
table netdev interval_endpoints {
 chain peer { type filter hook ingress device "peer0" priority 0; policy drop; }
 chain device_endpoint { type filter hook ingress device "device0" priority 0; policy drop; }
}
table inet interval_router {
 set protected4 { type ipv4_addr; }
 set protected6 { type ipv6_addr; }
 chain forward { type filter hook forward priority 0; policy drop;
  ip saddr @protected4 drop; ip daddr @protected4 drop;
  ip6 saddr @protected6 drop; ip6 daddr @protected6 drop;
  ct state established accept;
`+strings.Join(guardBridgeRules(), "\n")+`
 }
}`)
	t.Cleanup(func() {
		cleanup, cancel := context.WithTimeout(context.WithoutCancel(t.Context()), 2*time.Second)
		defer cancel()
		packetNft(cleanup, t, "delete table netdev interval_endpoints; delete table inet interval_router")
	})
	peer, device := packetSocket(t, "peer0"), packetSocket(t, "device0")
	for _, family := range []struct{ name, peer, device, network, inside, outside string }{
		{name: "ipv4", peer: "10.240.0.10", device: "10.240.3.10", network: "10.240.0.8/29", inside: "10.240.0.11", outside: "10.240.0.16"},
		{name: "ipv6", peer: "fdca:1a2b::10", device: "fdca:1a2b:3::10", network: "fdca:1a2b::10/124", inside: "fdca:1a2b::11", outside: "fdca:1a2b::20"},
	} {
		t.Run(family.name, func(t *testing.T) {
			deviceIP, peerIP := netip.MustParseAddr(family.device), netip.MustParseAddr(family.peer)
			batch := scopePacketBatch(t, deviceIP, netip.MustParsePrefix(family.network))
			applyGuardFixture(ctx, t, batch)
			inventory, err := process.inspectGuards(ctx, layout)
			if err != nil || inventory.leases == 0 {
				t.Fatalf("native interval read-back failed: %v", err)
			}
			exchange := func(target netip.Addr, port, ephemeral uint16, fromPeer, reply, tcp, allowed bool) {
				t.Helper()
				input, output, source, destination := device, peer, deviceIP, target
				packet := packetDatagram{sourcePort: ephemeral, destinationPort: port,
					sourceMAC: "02:00:00:00:00:13", destinationMAC: "02:00:00:00:01:13",
					isTCP: tcp, tcpFlags: 0x02, sequence: 100,
					payload: fmt.Sprintf("synthetic-interval-%d-%t-%t", port, fromPeer, reply)}
				if fromPeer {
					input, output, source, destination = peer, device, target, deviceIP
					packet.sourceMAC, packet.destinationMAC = "02:00:00:00:00:10", "02:00:00:00:01:10"
				}
				if reply {
					packet.sourcePort, packet.destinationPort = port, ephemeral
					packet.tcpFlags, packet.sequence, packet.acknowledgment = 0x12, 200, 101
				}
				packet.source, packet.destination = source, destination
				frame := packetFrame(t, packet)
				sendPacket(ctx, t, input, frame)
				receivePacket(ctx, t, output, frame, allowed)
			}
			for _, tcp := range []bool{false, true} {
				for _, port := range []uint16{6053, 6054, 6055} {
					for _, initiatedByPeer := range []bool{false, true} {
						ephemeral := uint16(45000) + port + 10
						if initiatedByPeer {
							ephemeral++
						}
						exchange(peerIP, port, ephemeral, initiatedByPeer, false, tcp, true)
						exchange(peerIP, port, ephemeral, !initiatedByPeer, true, tcp, true)
					}
				}
				for _, port := range []uint16{6052, 6056} {
					exchange(peerIP, port, 52000+port-6052, true, false, tcp, false)
					exchange(peerIP, port, 52100+port-6052, false, false, tcp, false)
				}
			}
			for _, target := range []string{family.inside, family.outside} {
				packetIP(ctx, t, "neighbor", "add", target, "lladdr", "02:00:00:00:00:10", "dev", "lan10", "nud", "permanent")
				exchange(netip.MustParseAddr(target), 6054, 53000, true, false, false, target == family.inside)
				exchange(netip.MustParseAddr(target), 6054, 53001, false, false, false, target == family.inside)
			}
			// A valid IP interval does not authorize a different physical device.
			packetIP(ctx, t, "neighbor", "replace", family.device, "lladdr", "02:00:00:00:00:14", "dev", "lan13", "nud", "permanent")
			exchange(peerIP, 6054, 54000, true, false, false, false)
			packetIP(ctx, t, "neighbor", "replace", family.device, "lladdr", "02:00:00:00:00:13", "dev", "lan13", "nud", "permanent")
			set := "protected6"
			if deviceIP.Is4() {
				set = "protected4"
			}
			packetNft(ctx, t, "add element inet interval_router "+set+" { "+family.peer+" }")
			exchange(peerIP, 6054, 55000, true, false, false, false)
			exchange(peerIP, 6054, 55001, false, false, false, false)
			packetNft(ctx, t, "flush set inet interval_router "+set)
			// Revocation closes established flows; permanent classification stays.
			exchange(peerIP, 6054, 56000, true, false, false, true)
			exchange(peerIP, 6054, 56000, false, true, false, true)
			cleared, err := prepareGuards(ctx, &preparedBatch{data: clearBatch(t)})
			if err != nil {
				t.Fatal(err)
			}
			applyGuardFixture(ctx, t, cleared.batch.data)
			exchange(peerIP, 6054, 56000, true, false, false, false)
			exchange(peerIP, 6054, 56000, false, true, false, false)
			applyGuardFixture(ctx, t, shortGuardFixture(t, batch))
			exchange(peerIP, 6054, 56000, true, false, false, true)
			waitKernelFixture(ctx, t, 1200*time.Millisecond)
			exchange(peerIP, 6054, 56000, true, false, false, false)
			exchange(peerIP, 6054, 56000, false, true, false, false)
			inventory, err = process.inspectGuards(ctx, layout)
			if err != nil || inventory.leases != 0 || len(inventory.cohort) != 1 {
				t.Fatalf("interval expiry erased history or retained a lease: %v", err)
			}
		})
	}
}
