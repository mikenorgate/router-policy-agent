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

func internetPacketBatch(t *testing.T, device netip.Addr, baseline policy.Baseline) []byte {
	t.Helper()
	_, _, _, input := renderFixture(t)
	anchor, now := policy.CaptureAge(), time.Now().UTC()
	input.Now, input.Directory.ObservedAt, input.Bindings.ObservedAt = now, now, now
	input.Directory.Groups = input.Directory.Groups[:1]
	input.Directory.Devices[0].MAC = "02:00:00:00:00:13"
	input.Directory.Devices[0].GroupIDs = []string{input.Directory.Groups[0].ID}
	for _, protocol := range []string{"tcp", "udp"} {
		group := rendererAccessGroup(t, "internet-"+protocol, false, policy.Rule{
			ID: "public", Direction: policy.FromDevice, Peer: policy.Peer{Internet: true},
			Protocol: protocol, AllDestinationPorts: true, Reason: "Synthetic Internet packet qualification",
		})
		raw := strings.Replace(*group.Policy, `"schema_version":1`, `"schema_version":2`, 1)
		group.Policy = &raw
		input.Directory.Groups = append(input.Directory.Groups, group)
		input.Directory.Devices[0].GroupIDs = append(input.Directory.Devices[0].GroupIDs, group.ID)
	}
	source := "qualified_ipv6"
	if device.Is4() {
		source = "kea_dhcp4"
	}
	input.Bindings.Records[0].MAC, input.Bindings.Records[0].AssociatedAt = input.Directory.Devices[0].MAC, now
	input.Bindings.Records[0].Addresses = []binding.Address{{
		IP: device, Source: source, OwnershipID: "synthetic-public-owner", ObservedAt: now, ValidUntil: now.Add(time.Hour),
	}}
	renderer, err := newRenderer(baseline)
	if err != nil {
		t.Fatal(err)
	}
	authorization, err := renderer.compiler.CompileAuthorization(t.Context(), input, anchor)
	if err != nil {
		t.Fatal(err)
	}
	logical, err := renderer.prepare(t.Context(), replacement{
		authorization: authorization, now: time.Now().UTC(), cohort: []string{input.Directory.Devices[0].MAC},
	})
	if err != nil {
		t.Fatal(err)
	}
	prepared, err := prepareGuards(t.Context(), logical)
	if err != nil {
		t.Fatal(err)
	}
	return prepared.batch.data
}

func TestKernelCompactInternetPermitsAndIsolation(t *testing.T) {
	requireKernelIsolation(t)
	t.Cleanup(func() { requireKernelIsolation(t) })
	ctx, cancel := context.WithTimeout(t.Context(), 90*time.Second)
	defer cancel()
	setupPacketLinks(ctx, t)
	_, _, baseline, _ := renderFixture(t)
	baseline.Zones[0].Networks = append(baseline.Zones[0].Networks, netip.MustParsePrefix("2a01:4f8:100::/64"))
	baseline.RetainedBlocks = append(baseline.RetainedBlocks, policy.NetworkBlock{
		ProtectionID: "P08", SourceMAC: "02:00:00:00:00:13", Roles: []policy.Role{policy.Untrusted},
		InternetOnly: true, Networks: []netip.Prefix{netip.MustParsePrefix("9.9.9.8/32"), netip.MustParsePrefix("2606:4700:4700::1000/128")},
	})
	layout, err := newGuardLayout(baseline)
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range layout.interfaces {
		if name == "lan10" || name == "lan13" {
			continue
		}
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
	packetNft(ctx, t, `table netdev internet_endpoints {
 chain peer { type filter hook ingress device "peer0" priority 0; policy drop; }
 chain device_endpoint { type filter hook ingress device "device0" priority 0; policy drop; }
}
table inet internet_router {
 chain forward { type filter hook forward priority 0; policy drop;
 ct state established accept;
`+strings.Join(guardBridgeRules(), "\n")+`
 }
}`)
	t.Cleanup(func() {
		cleanup, cancel := context.WithTimeout(context.WithoutCancel(t.Context()), 2*time.Second)
		defer cancel()
		packetNft(cleanup, t, "delete table netdev internet_endpoints; delete table inet internet_router")
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
	peer, device := packetSocket(t, "peer0"), packetSocket(t, "device0")
	for _, family := range []struct {
		name, device string
		peers        []string
	}{
		{name: "ipv4", device: "10.240.3.10", peers: []string{"9.9.9.9", "9.9.9.8", "10.240.0.10", "198.18.0.1"}},
		{name: "ipv6", device: "fdca:1a2b:3::10", peers: []string{
			"2606:4700:4700::1111", "2606:4700:4700::1000", "2a01:4f8:100::10", "2001:db8::1",
			"64:ff9b::909:909", "64:ff9b::afa:14", "fdca:1a2b:64::afa:14",
		}},
	} {
		t.Run(family.name, func(t *testing.T) {
			bound := netip.MustParseAddr(family.device)
			applyGuardFixture(ctx, t, internetPacketBatch(t, bound, baseline))
			if _, err := process.inspectGuards(ctx, layout); err != nil {
				t.Fatalf("Internet kernel readback failed: %v", err)
			}
			for index, destination := range family.peers {
				address := netip.MustParseAddr(destination)
				route := []string{"route", "replace", netip.PrefixFrom(address, address.BitLen()).String(), "dev", "lan10"}
				if !address.Is4() {
					route = append([]string{"-6"}, route...)
				}
				packetIP(ctx, t, route...)
				packetIP(ctx, t, "neighbor", "replace", destination, "lladdr", "02:00:00:00:00:10", "dev", "lan10", "nud", "permanent")
				allowed := index == 0 || destination == "64:ff9b::909:909"
				port := uint16(41000 + index)
				original := packetFrame(t, packetDatagram{
					source: bound, destination: address, sourceMAC: "02:00:00:00:00:13", destinationMAC: "02:00:00:00:01:13",
					sourcePort: port, destinationPort: 443, payload: fmt.Sprintf("synthetic-public-%s", destination),
				})
				sendPacket(ctx, t, device, original)
				receivePacket(ctx, t, peer, original, allowed)
				if !allowed {
					continue
				}
				reply := packetFrame(t, packetDatagram{
					source: address, destination: bound, sourceMAC: "02:00:00:00:00:10", destinationMAC: "02:00:00:00:01:10",
					sourcePort: 443, destinationPort: port, payload: "synthetic-correlated-public-reply",
				})
				sendPacket(ctx, t, peer, reply)
				receivePacket(ctx, t, device, reply, true)
			}
			public := netip.MustParseAddr(family.peers[0])
			unsolicited := packetFrame(t, packetDatagram{
				source: public, destination: bound, sourceMAC: "02:00:00:00:00:10", destinationMAC: "02:00:00:00:01:10",
				sourcePort: 443, destinationPort: 49999, payload: "synthetic-unsolicited-public",
			})
			sendPacket(ctx, t, peer, unsolicited)
			receivePacket(ctx, t, device, unsolicited, false)
			revocation, err := prepareGuards(ctx, &preparedBatch{data: clearBatch(t)})
			if err != nil {
				t.Fatal(err)
			}
			applyGuardFixture(ctx, t, revocation.batch.data)
			reply := packetFrame(t, packetDatagram{
				source: public, destination: bound, sourceMAC: "02:00:00:00:00:10", destinationMAC: "02:00:00:00:01:10",
				sourcePort: 443, destinationPort: 41000, payload: "synthetic-revoked-established",
			})
			sendPacket(ctx, t, peer, reply)
			receivePacket(ctx, t, device, reply, false)
		})
	}
	packetNft(ctx, t, "flush set inet "+ownedTable+" internet_excluded4")
	if _, err := process.inspectGuards(ctx, layout); err == nil {
		t.Fatal("modified shared exclusions were accepted")
	}
}
