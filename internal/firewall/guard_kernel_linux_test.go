//go:build integration && kernel && linux

package firewall

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/netip"
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
	// Fixture-only endpoint drops prevent same-namespace recirculation. The
	// later chain proves an early guard accept is not the permitting path.
	packetNft(ctx, t, `
table netdev guard_endpoint_fixture {
 chain peer_endpoint { type filter hook ingress device "peer0" priority 0; policy drop; }
 chain device_endpoint { type filter hook ingress device "device0" priority 0; policy drop; }
}
add chain inet router_policy_agent fixture_application { type filter hook forward priority 0; policy drop; }
add counter inet router_policy_agent fixture_stateful_accept
add rule inet router_policy_agent fixture_application ct state established counter name fixture_stateful_accept accept
add rule inet router_policy_agent fixture_application jump permit_flow
add rule inet router_policy_agent fixture_application meta l4proto udp udp dport 6060 accept
`)
	t.Cleanup(func() {
		cleanup, cancel := context.WithTimeout(context.WithoutCancel(t.Context()), 2*time.Second)
		defer cancel()
		packetNft(cleanup, t, "delete table netdev guard_endpoint_fixture")
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

func guardStatefulCount(ctx context.Context, t *testing.T) uint64 {
	t.Helper()
	data := kernelFixtureCommand(ctx, t, "list", "counter", "inet", ownedTable, "fixture_stateful_accept")
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
	t.Fatal("synthetic stateful counter absent")
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
	command := exec.CommandContext(ctx, "/usr/sbin/nft", "--json", "--file", "-")
	command.Env = []string{"LC_ALL=C", "PATH=/usr/sbin:/usr/bin"}
	command.Stdin = bytes.NewReader(data)
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("isolated synthetic guarded transaction failed: %v, %s", err, output)
	}
}
