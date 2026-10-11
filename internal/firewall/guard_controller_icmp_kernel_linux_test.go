//go:build integration && kernel && translationkernel && linux

package firewall

import (
	"context"
	"net/netip"
	"testing"
)

func qualifyControllerICMP(ctx context.Context, t *testing.T, peer, device packetEndpoint, enabled bool) {
	t.Helper()
	controller, alias := netip.MustParseAddr("fdca:1a2b::10"), netip.MustParseAddr("fdca:1a2b:64::af0:30a")
	target, gateway := netip.MustParseAddr("10.240.3.10"), netip.MustParseAddr("10.240.3.1")
	echo := packetDatagram{
		source: controller, destination: alias,
		sourceMAC: "02:00:00:00:00:10", destinationMAC: "02:00:00:00:01:10",
		isICMP: true, icmpType: 128, icmpData: 0xc7380001, payload: "synthetic-controller-echo",
	}
	sendPacket(ctx, t, peer, packetFrame(t, echo))
	echo.source, echo.destination, echo.icmpType = gateway, target, 8
	receivePacket(ctx, t, device, packetFrame(t, echo), enabled, 61)
	echo.source, echo.destination, echo.icmpType = target, gateway, 0
	echo.sourceMAC, echo.destinationMAC = "02:00:00:00:00:13", "02:00:00:00:01:13"
	sendPacket(ctx, t, device, packetFrame(t, echo))
	echo.source, echo.destination, echo.icmpType = alias, controller, 129
	receivePacket(ctx, t, peer, packetFrame(t, echo), enabled, 61)

	// Quote only the complete IP header and UDP header. The UDP flow already
	// crossed both guarded families with directory leases sealed. A different
	// Untrusted source models an intermediate router, not a destination grant.
	quoted := packetDatagram{
		source: gateway, destination: target,
		sourceMAC: "02:00:00:00:00:10", destinationMAC: "02:00:00:00:01:10",
		sourcePort: 48000, destinationPort: 6053, payload: "synthetic-controller-translated-request",
	}
	errorPacket := func(port uint16, kind byte, allowed bool) {
		t.Helper()
		quoted.sourcePort = port
		quoted.source, quoted.destination = gateway, target
		quote4 := packetFrame(t, quoted)[14:42]
		packet := packetDatagram{
			source: netip.MustParseAddr("10.240.3.11"), destination: gateway,
			sourceMAC: "02:00:00:00:00:13", destinationMAC: "02:00:00:00:01:13",
			isICMP: true, icmpType: kind, icmpCode: 4, icmpData: 1280, payload: string(quote4),
		}
		sendPacket(ctx, t, device, packetFrame(t, packet))
		quoted.source, quoted.destination = controller, alias
		quote6 := packetFrame(t, quoted)[14:62]
		packet.source, packet.destination = netip.MustParseAddr("fdca:1a2b:64::af0:30b"), controller
		packet.icmpType, packet.icmpCode, packet.icmpData, packet.payload = 2, 0, 1300, string(quote6)
		receivePacket(ctx, t, peer, packetFrame(t, packet), allowed, 61)
	}
	errorPacket(48000, 3, enabled)
	if !enabled {
		return
	}
	if guardFixtureCounter(ctx, t, "translation_router_fixture", "related4") != 1 ||
		guardFixtureCounter(ctx, t, "translation_router_fixture", "related6") != 1 {
		t.Fatal("translated PMTU did not obtain independent authority in both families")
	}
	errorPacket(48099, 3, false)
	errorPacket(48000, 5, false)
	before := guardFixtureCounter(ctx, t, "translation_router_fixture", "protected_drop")
	packetNft(ctx, t, "add element inet translation_router_fixture protected4 { 10.240.3.10 }")
	errorPacket(48000, 3, false)
	if guardFixtureCounter(ctx, t, "translation_router_fixture", "protected_drop") != before+1 {
		t.Fatal("related ICMP bypassed protection of its quoted target")
	}
	packetNft(ctx, t, "flush set inet translation_router_fixture protected4")
	before = guardFixtureCounter(ctx, t, "translation_router_fixture", "protected_drop")
	packetNft(ctx, t, "add element inet translation_router_fixture protected6 { fdca:1a2b:64::af0:30a }")
	errorPacket(48000, 3, false)
	if guardFixtureCounter(ctx, t, "translation_router_fixture", "protected_drop") != before+1 {
		t.Fatal("translated related ICMP bypassed protection of its quoted IPv6 target")
	}
	packetNft(ctx, t, "flush set inet translation_router_fixture protected6")
}

func qualifyNativeControllerEcho(ctx context.Context, t *testing.T, peer, device packetEndpoint, enabled bool) {
	t.Helper()
	for _, test := range []struct {
		name, controller, device string
		request, reply           byte
	}{
		{name: "ipv4", controller: "10.240.0.10", device: "10.240.3.10", request: 8},
		{name: "ipv6", controller: "fdca:1a2b::10", device: "fdca:1a2b:3::10", request: 128, reply: 129},
	} {
		t.Run(test.name+" native echo", func(t *testing.T) {
			packet := packetDatagram{
				source: netip.MustParseAddr(test.controller), destination: netip.MustParseAddr(test.device),
				sourceMAC: "02:00:00:00:00:10", destinationMAC: "02:00:00:00:01:10",
				isICMP: true, icmpType: test.request, icmpData: 0xc7390001, payload: "synthetic-native-echo",
			}
			sendPacket(ctx, t, peer, packetFrame(t, packet))
			receivePacket(ctx, t, device, packetFrame(t, packet), enabled)
			packet.source, packet.destination, packet.icmpType = packet.destination, packet.source, test.reply
			packet.sourceMAC, packet.destinationMAC = "02:00:00:00:00:13", "02:00:00:00:01:13"
			sendPacket(ctx, t, device, packetFrame(t, packet))
			receivePacket(ctx, t, peer, packetFrame(t, packet), enabled)
		})
	}
}
