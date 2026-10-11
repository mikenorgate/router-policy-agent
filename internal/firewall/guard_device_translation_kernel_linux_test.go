//go:build integration && kernel && translationkernel && linux

package firewall

import (
	"context"
	"net/netip"
	"testing"
	"time"
)

func qualifyTranslatedCallbacks(
	ctx context.Context,
	t *testing.T,
	layout *guardLayout,
	process *process,
	peer, device packetEndpoint,
) func() {
	t.Helper()
	replace := func(prepared *preparedGuardBatch) {
		t.Helper()
		if err := validatePreparedGuardBatch(ctx, prepared); err != nil {
			t.Fatal(err)
		}
		executeGuardFixture(ctx, t, prepared.batch.data)
		if _, err := process.inspectGuards(ctx, layout); err != nil {
			t.Fatalf("actual translated mirror inventory differs: %v", err)
		}
	}
	apply := func(active bool) {
		t.Helper()
		current, logical := translatedDeviceGrantFixture(t, true, active, true)
		prepared, err := prepareMappedGuards(ctx, logical, nil, current.translationPaths)
		if err != nil {
			t.Fatal(err)
		}
		replace(prepared)
	}
	exchange := func(packet packetDatagram, fromDevice, allowed bool) {
		t.Helper()
		input, output := device, peer
		packet.sourceMAC, packet.destinationMAC = "02:00:00:00:00:13", "02:00:00:00:01:13"
		packet.source, packet.destination = netip.MustParseAddr("10.240.3.10"), netip.MustParseAddr("10.250.0.10")
		if !fromDevice {
			input, output = peer, device
			packet.sourceMAC, packet.destinationMAC = "02:00:00:00:00:10", "02:00:00:00:01:10"
			packet.source, packet.destination = netip.MustParseAddr("fdca:1a2b::10"), netip.MustParseAddr("fdca:1a2b:64::af0:30a")
		}
		sendPacket(ctx, t, input, packetFrame(t, packet))
		packet.source, packet.destination = netip.MustParseAddr("fdca:1a2b:64::af0:30a"), netip.MustParseAddr("fdca:1a2b::10")
		if !fromDevice {
			packet.source, packet.destination = netip.MustParseAddr("10.250.0.10"), netip.MustParseAddr("10.240.3.10")
		}
		receivePacket(ctx, t, output, packetFrame(t, packet), allowed, 61)
	}
	request := packetDatagram{sourcePort: 49100, destinationPort: 6053, payload: "synthetic-device-callback"}
	reply := packetDatagram{sourcePort: 6053, destinationPort: 49100, payload: "synthetic-callback-response"}
	apply(true)
	for _, flow := range []struct {
		name string
		tcp  bool
	}{
		{name: "udp"}, {name: "tcp", tcp: true},
	} {
		t.Run(flow.name+" translated callback", func(t *testing.T) {
			t.Helper()
			request.isTCP, reply.isTCP = flow.tcp, flow.tcp
			request.tcpFlags, reply.tcpFlags = 0x02, 0x12
			request.sequence, reply.sequence, reply.acknowledgment = 100, 200, 101
			exchange(request, true, true)
			exchange(reply, false, true)
			if flow.tcp {
				request.tcpFlags, request.sequence, request.acknowledgment = 0x10, 101, 201
				exchange(request, true, true)
			}
		})
	}
	// Neither a neighboring listener nor a neighboring device inherits the
	// compiled exact grant. The independent protected floor remains ahead of
	// the provisional bridge and controller-address terminal drops.
	wrong := request
	wrong.isTCP, wrong.destinationPort, wrong.sourcePort = false, 6054, 49101
	exchange(wrong, true, false)
	spoof := packetDatagram{
		source: netip.MustParseAddr("10.240.3.10"), destination: netip.MustParseAddr("10.250.0.10"),
		sourceMAC: "02:00:00:00:00:14", destinationMAC: "02:00:00:00:01:13",
		sourcePort: 49102, destinationPort: 6053, payload: "synthetic-wrong-device-mac",
	}
	sendPacket(ctx, t, device, packetFrame(t, spoof))
	spoof.source, spoof.destination = netip.MustParseAddr("fdca:1a2b:64::af0:30a"), netip.MustParseAddr("fdca:1a2b::10")
	receivePacket(ctx, t, peer, packetFrame(t, spoof), false, 61)
	before := guardFixtureCounter(ctx, t, "translation_router_fixture", "protected_drop")
	packetNft(ctx, t, "add element inet translation_router_fixture protected4 { 10.250.0.10 }")
	request.isTCP, request.sourcePort = false, 49103
	exchange(request, true, false)
	if guardFixtureCounter(ctx, t, "translation_router_fixture", "protected_drop") != before+1 {
		t.Fatal("device callback bypassed independent protected alias denial")
	}
	packetNft(ctx, t, "flush set inet translation_router_fixture protected4")
	before = guardFixtureCounter(ctx, t, "translation_router_fixture", "protected_drop")
	packetNft(ctx, t, "add element inet translation_router_fixture protected6 { fdca:1a2b::10 }")
	exchange(request, true, false)
	if guardFixtureCounter(ctx, t, "translation_router_fixture", "protected_drop") != before+1 {
		t.Fatal("translated callback bypassed independent protected target denial")
	}
	packetNft(ctx, t, "flush set inet translation_router_fixture protected6")
	// Delete the queried TUN lease between hooks, leaving final mirrors live.
	// The late check must deny even after a provisional router accept.
	packetNft(ctx, t, "add chain inet "+ownedTable+" translation_fault { type filter hook forward priority 149; policy accept; }")
	packetNft(ctx, t, "add rule inet "+ownedTable+" translation_fault "+
		"meta mark & 0xff000000 == 0xc1000000 udp sport 49104 "+
		"delete @transit_from6_udp { iifname . ip6 saddr . ip6 daddr . ct original proto-dst }")
	request.sourcePort = 49104
	exchange(request, true, false)
	packetNft(ctx, t, "delete chain inet "+ownedTable+" translation_fault")
	apply(true)
	// Final TUN egress also rechecks the physical-leg projection, without
	// pretending a TUN frame carries the original Ethernet MAC.
	packetNft(ctx, t, "flush set netdev "+ownedTable+" transit_request4_udp")
	request.sourcePort = 49105
	exchange(request, true, false)
	apply(true)
	// Use the backend's denial-only inventory and sealing preparation, retaining
	// permanent MAC/address history while removing every translated mirror.
	ruleset, err := process.run(ctx, commandInput{op: inspectWholeRuleset})
	if err != nil {
		t.Fatal(err)
	}
	inventory, history, err := inspectSealingGuards(ctx, layout, ruleset)
	if err != nil {
		t.Fatal(err)
	}
	sealed, err := prepareMappedGuardSeal(ctx, history, layout.translationPaths)
	if err != nil {
		t.Fatal(err)
	}
	if err := validateGuardSeal(ctx, sealed); err != nil {
		t.Fatal(err)
	}
	if err := inventory.checkPreparedReplacement(ctx, sealed); err != nil {
		t.Fatal(err)
	}
	replace(sealed)
	request.sourcePort = 49100
	exchange(request, true, false)
	exchange(reply, false, false)
	apply(false)
	request.sourcePort = 49100
	reply.tcpFlags, reply.sequence, reply.acknowledgment = 0x10, 201, 101
	for _, tcp := range []bool{false, true} {
		request.isTCP, reply.isTCP = tcp, tcp
		exchange(request, true, false)
		exchange(reply, false, false)
	}
	// Shorten only this disposable fixture's logical leases, before projection.
	// Actual kernel expiry must stop an existing translated UDP connection in
	// both directions without a reader refresh or a conntrack flush.
	current, logical := translatedDeviceGrantFixture(t, true, true, true)
	logical.data = shortGuardFixture(t, logical.data)
	short, err := prepareMappedGuards(ctx, logical, nil, current.translationPaths)
	if err != nil {
		t.Fatal(err)
	}
	replace(short)
	request.isTCP, reply.isTCP = false, false
	exchange(request, true, true)
	exchange(reply, false, true)
	waitKernelFixture(ctx, t, 1200*time.Millisecond)
	exchange(request, true, false)
	exchange(reply, false, false)
	if observed, err := process.inspectGuards(ctx, layout); err != nil || observed.leases != 0 {
		t.Fatalf("expired translated mirrors remain: %v", err)
	}
	// Root-owned controller initiation must remain independent of account
	// revocation; the caller's existing controller tests exercise it afterward.
	apply(true)
	request.isTCP, reply.isTCP = false, false
	exchange(request, true, true)
	exchange(reply, false, true)
	return func() {
		t.Helper()
		exchange(request, true, false)
		exchange(reply, false, false)
	}
}
