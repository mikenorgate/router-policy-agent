//go:build integration && kernel && translationkernel && linux

package firewall

import (
	"context"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// This bridge belongs only to the synthetic router fixture. Production bridge
// ordering and protected denies remain the independently reviewed image owner's
// responsibility, not a helper-generated firewall change.
func (layout *guardLayout) translatedBridgeRules() []string {
	lines := []string{}
	if len(layout.translationPaths) != 0 {
		for _, tag := range []string{translatedOriginalTag, translatedReplyTag} {
			lines = append(lines, "meta mark & 0xff000000 == "+tag+" accept")
		}
	}
	return lines
}

// The opt-in runner must supply a qualified TAYGA at this fixed test-only path
// and /dev/net/tun. Ordinary kernel tests do not simulate translation or skip a
// failed translator. All addresses, links, maps and router rules are synthetic.
func TestKernelControllerTAYGARoundTrip(t *testing.T) {
	runControllerTranslationPackets(t, false)
}

func TestKernelControllerTAYGAICMP(t *testing.T) {
	runControllerTranslationPackets(t, true)
}

func TestKernelDeviceTAYGACallbacks(t *testing.T) {
	runControllerTranslationPackets(t, false, true)
}

func TestKernelDeviceTAYGAScopedCallbacks(t *testing.T) {
	runControllerTranslationPackets(t, false, true, true)
}

func runControllerTranslationPackets(t *testing.T, icmpEnabled bool, callbacks ...bool) {
	t.Helper()
	requireKernelIsolation(t)
	t.Cleanup(func() { requireKernelIsolation(t) })
	ctx, cancel := context.WithTimeout(t.Context(), 45*time.Second)
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
	packetIP(ctx, t, "tuntap", "add", "dev", "nat64-test", "mode", "tun")
	t.Cleanup(func() {
		cleanup, cancel := context.WithTimeout(context.WithoutCancel(t.Context()), 2*time.Second)
		defer cancel()
		packetIP(cleanup, t, "link", "delete", "nat64-test")
	})
	packetIP(ctx, t, "link", "set", "nat64-test", "up")
	packetIP(ctx, t, "address", "add", "10.250.0.1/32", "dev", "nat64-test")
	packetIP(ctx, t, "-6", "address", "add", "fdca:1a2b:ffff::1/128", "dev", "nat64-test", "nodad")
	packetIP(ctx, t, "route", "add", "10.250.0.0/24", "dev", "nat64-test")
	packetIP(ctx, t, "-6", "route", "add", "fdca:1a2b:64::/96", "dev", "nat64-test")
	layout := translatedControllerLayout(t, true, icmpEnabled)
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
		t.Fatalf("actual TUN/translation guard schema differs: %v", err)
	}
	packetNft(ctx, t, `
table netdev translation_endpoint_fixture {
 chain peer_endpoint { type filter hook ingress device "peer0" priority 0; policy drop; }
 chain device_endpoint { type filter hook ingress device "device0" priority 0; policy drop; }
}
table inet translation_router_fixture {
 set protected4 { type ipv4_addr; }
 set protected6 { type ipv6_addr; }
 counter protected_drop {}
 counter original6 {}
 counter original4 {}
 counter reply4 {}
 counter reply6 {}
 counter changed_handoff {}
 counter related4 {}
 counter related6 {}
 chain change_forward { type filter hook forward priority 149; policy accept; }
 chain observe {
  type filter hook forward priority -149; policy accept;
  iifname "lan10" ip6 saddr fdca:1a2b::10 ip6 daddr fdca:1a2b:64::af0:30a meta mark & 0xff00ffff == 0xb1000003 counter name original6
  iifname "nat64-test" ip saddr 10.250.0.10 ip daddr 10.240.3.10 meta mark & 0xff00ffff == 0xb1000004 counter name original4
  iifname "lan13" ip saddr 10.240.3.10 ip daddr 10.250.0.10 meta mark & 0xff00ffff == 0xb2000004 counter name reply4
  iifname "nat64-test" ip6 saddr fdca:1a2b:64::af0:30a ip6 daddr fdca:1a2b::10 meta mark & 0xff00ffff == 0xb2000003 counter name reply6
  iifname "lan13" meta l4proto icmp ct state related meta mark & 0xff00ffff == 0xb2000004 counter name related4
  iifname "nat64-test" meta l4proto ipv6-icmp ct state related meta mark & 0xff00ffff == 0xb2000003 counter name related6
 }
 chain forward {
  type filter hook forward priority 0; policy drop;
  ip saddr @protected4 counter name protected_drop drop
  ip daddr @protected4 counter name protected_drop drop
  ip6 saddr @protected6 counter name protected_drop drop
  ip6 daddr @protected6 counter name protected_drop drop
  ct state related ct original ip daddr @protected4 counter name protected_drop drop
  ct state related ct original ip6 daddr @protected6 counter name protected_drop drop
  iifname "lan10" oifname "nat64-test" ip6 saddr fdca:1a2b::10 ip6 daddr fdca:1a2b:64::af0:300/120 meta l4proto { tcp, udp } ct direction original ct state { new, established } accept
  iifname "nat64-test" oifname "lan10" ip6 saddr fdca:1a2b:64::af0:300/120 ip6 daddr fdca:1a2b::10 meta l4proto { tcp, udp } ct direction reply ct state established accept
  iifname "nat64-test" oifname "lan13" ip saddr 10.250.0.10 ip daddr 10.240.3.0/24 meta l4proto { tcp, udp } ct direction original ct state { new, established } accept
  iifname "lan13" oifname "nat64-test" ip saddr 10.240.3.0/24 ip daddr 10.250.0.10 meta l4proto { tcp, udp } ct direction reply ct state established accept
  iifname "lan10" oifname "nat64-test" ip6 saddr fdca:1a2b::10 ip6 daddr fdca:1a2b:64::af0:300/120 meta l4proto ipv6-icmp ct direction original ct state { new, established } accept
  iifname "nat64-test" oifname "lan10" ip6 saddr fdca:1a2b:64::af0:300/120 ip6 daddr fdca:1a2b::10 meta l4proto ipv6-icmp ct direction reply ct state established accept
  iifname "nat64-test" oifname "lan13" ip saddr 10.250.0.10 ip daddr 10.240.3.0/24 meta l4proto icmp ct direction original ct state { new, established } accept
  iifname "lan13" oifname "nat64-test" ip saddr 10.240.3.0/24 ip daddr 10.250.0.10 meta l4proto icmp ct direction reply ct state established accept
  iifname "nat64-test" oifname "lan10" ip6 daddr fdca:1a2b::10 ct original ip6 saddr fdca:1a2b::10 ct original ip6 daddr fdca:1a2b:64::af0:300/120 meta l4proto ipv6-icmp ct protocol { tcp, udp } ct direction reply ct state related accept
  iifname "lan13" oifname "nat64-test" ip daddr 10.250.0.10 ct original ip saddr 10.250.0.10 ct original ip daddr 10.240.3.0/24 meta l4proto icmp ct protocol { tcp, udp } ct direction reply ct state related accept
  iifname "lan10" oifname "lan13" ip saddr 10.240.0.10 ip daddr 10.240.3.0/24 meta l4proto icmp ct direction original ct state { new, established } accept
  iifname "lan13" oifname "lan10" ip saddr 10.240.3.0/24 ip daddr 10.240.0.10 meta l4proto icmp ct direction reply ct state established accept
  iifname "lan10" oifname "lan13" ip6 saddr fdca:1a2b::10 ip6 daddr fdca:1a2b:3::/64 meta l4proto ipv6-icmp ct direction original ct state { new, established } accept
  iifname "lan13" oifname "lan10" ip6 saddr fdca:1a2b:3::/64 ip6 daddr fdca:1a2b::10 meta l4proto ipv6-icmp ct direction reply ct state established accept
`+strings.Join(append(guardBridgeRules(), layout.translatedBridgeRules()...), "\n")+`
  ip saddr 10.250.0.10 drop
  ip daddr 10.250.0.10 drop
  ip6 saddr fdca:1a2b::10 drop
  ip6 daddr fdca:1a2b::10 drop
 }
}
table ip translation_nat44_fixture {
 chain source_nat {
  type nat hook postrouting priority 100; policy accept;
  iifname "nat64-test" oifname "lan13" ip saddr 10.250.0.10 ip daddr 10.240.3.0/24 snat to 10.240.3.1
 }
}
`)
	t.Cleanup(func() {
		cleanup, cancel := context.WithTimeout(context.WithoutCancel(t.Context()), 2*time.Second)
		defer cancel()
		packetNft(cleanup, t, "delete table netdev translation_endpoint_fixture; delete table inet translation_router_fixture; delete table ip translation_nat44_fixture")
	})
	configuration := filepath.Join(t.TempDir(), "tayga.conf")
	if err := os.WriteFile(configuration, []byte(`tun-device nat64-test
ipv4-addr 10.250.0.1
ipv6-addr fdca:1a2b:ffff::1
prefix fdca:1a2b:64::/96
map 10.250.0.10 fdca:1a2b::10
`), 0o600); err != nil {
		t.Fatal(err)
	}
	logs, err := os.OpenRoot(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := logs.Close(); err != nil {
			t.Error(err)
		}
	})
	logFile, err := logs.Create("translator.log")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := logFile.Close(); err != nil {
			t.Error(err)
		}
	})
	// #nosec G204 -- Fixed binary and synthetic config in an acknowledged empty namespace.
	translator := exec.CommandContext(ctx, "/usr/local/sbin/tayga", "--nodetach", "--stdout", "--config", configuration)
	translator.Stdout, translator.Stderr = logFile, logFile
	translator.Env = []string{"LC_ALL=C", "PATH=/usr/sbin:/usr/bin"}
	if err := translator.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		// The deferred test cancellation terminates the child before cleanup.
		if err := translator.Wait(); err != nil && ctx.Err() == nil {
			t.Error(err)
		}
	})
	t.Cleanup(func() {
		if !t.Failed() {
			return
		}
		cleanup, cancel := context.WithTimeout(context.WithoutCancel(t.Context()), 2*time.Second)
		defer cancel()
		for _, name := range []string{"original6", "original4", "reply4", "reply6"} {
			t.Logf("%s packets: %d", name, guardFixtureCounter(cleanup, t, "translation_router_fixture", name))
		}
		log, err := logs.ReadFile("translator.log")
		if err == nil {
			t.Logf("synthetic translator log: %s", log)
		}
	})
	ready, stopReady := context.WithTimeout(ctx, 2*time.Second)
	defer stopReady()
	for {
		if ready.Err() != nil {
			log, err := logs.ReadFile("translator.log")
			if err != nil {
				t.Fatal(err)
			}
			t.Fatalf("translator did not become ready: %s", log)
		}
		link, err := net.InterfaceByName("nat64-test")
		if err != nil {
			t.Fatal(err)
		}
		if link.Flags&net.FlagRunning != 0 {
			break
		}
		waitKernelFixture(ctx, t, 10*time.Millisecond)
	}
	peer, device := packetSocket(t, "peer0"), packetSocket(t, "device0")
	controller, target := netip.MustParseAddr("fdca:1a2b::10"), netip.MustParseAddr("10.240.3.10")
	alias, gateway := netip.MustParseAddr("fdca:1a2b:64::af0:30a"), netip.MustParseAddr("10.240.3.1")
	// A managed device with deny history and no directory permissions.
	applyGuardFixture(ctx, t, guardPacketBatch(t, target, netip.MustParseAddr("10.240.0.10"), false))
	request := func(port uint16, tcp bool, flags byte, sequence, ack uint32, allowed bool) {
		t.Helper()
		packet := packetDatagram{source: controller, destination: alias,
			sourceMAC: "02:00:00:00:00:10", destinationMAC: "02:00:00:00:01:10",
			sourcePort: port, destinationPort: 6053, isTCP: tcp, tcpFlags: flags,
			sequence: sequence, acknowledgment: ack, payload: "synthetic-controller-translated-request",
		}
		sendPacket(ctx, t, peer, packetFrame(t, packet))
		packet.source, packet.destination = gateway, target
		receivePacket(ctx, t, device, packetFrame(t, packet), allowed, 61)
	}
	reply := func(port uint16, tcp bool, flags byte, sequence, ack uint32, allowed bool) {
		t.Helper()
		packet := packetDatagram{source: target, destination: gateway,
			sourceMAC: "02:00:00:00:00:13", destinationMAC: "02:00:00:00:01:13",
			sourcePort: 6053, destinationPort: port, isTCP: tcp, tcpFlags: flags,
			sequence: sequence, acknowledgment: ack, payload: "synthetic-controller-translated-reply",
		}
		sendPacket(ctx, t, device, packetFrame(t, packet))
		packet.source, packet.destination = alias, controller
		receivePacket(ctx, t, peer, packetFrame(t, packet), allowed, 61)
	}
	request(48000, false, 0, 0, 0, true)
	reply(48000, false, 0, 0, 0, true)
	sealed, err := prepareGuards(ctx, &preparedBatch{data: clearBatch(t)})
	if err != nil {
		t.Fatal(err)
	}
	applyGuardFixture(ctx, t, sealed.batch.data)
	request(48000, false, 0, 0, 0, true)
	reply(48000, false, 0, 0, 0, true)
	request(48001, true, 0x02, 100, 0, true)
	reply(48001, true, 0x12, 200, 101, true)
	request(48001, true, 0x10, 101, 201, true)
	for _, counter := range []struct {
		name     string
		expected uint64
	}{
		{name: "original6", expected: 4}, {name: "original4", expected: 4},
		{name: "reply4", expected: 3}, {name: "reply6", expected: 3},
	} {
		if guardFixtureCounter(ctx, t, "translation_router_fixture", counter.name) != counter.expected {
			t.Fatalf("independent translated leg did not obtain its own %s authority", counter.name)
		}
	}
	reply(48002, false, 0, 0, 0, false)
	packetNft(ctx, t, "add rule inet translation_router_fixture change_forward iifname nat64-test ip saddr 10.250.0.10 udp sport 48004 counter name changed_handoff meta mark set 0xb100ffff")
	request(48004, false, 0, 0, 0, false)
	if guardFixtureCounter(ctx, t, "translation_router_fixture", "changed_handoff") != 1 {
		t.Fatal("translated packet did not reach the late handoff mutation")
	}
	packetNft(ctx, t, "flush chain inet translation_router_fixture change_forward")
	packetNft(ctx, t, "add element inet translation_router_fixture protected6 { fdca:1a2b:64::af0:30a }")
	request(48000, false, 0, 0, 0, false)
	if guardFixtureCounter(ctx, t, "translation_router_fixture", "protected_drop") != 1 {
		t.Fatal("controller alias leg bypassed independent protected IPv6 checks")
	}
	packetNft(ctx, t, "flush set inet translation_router_fixture protected6")
	packetNft(ctx, t, "add element inet translation_router_fixture protected4 { 10.240.3.10 }")
	request(48000, false, 0, 0, 0, false)
	reply(48000, false, 0, 0, 0, false)
	request(48003, false, 0, 0, 0, false)
	if guardFixtureCounter(ctx, t, "translation_router_fixture", "protected_drop") != 4 {
		t.Fatal("translated controller access bypassed independent protected IPv4 checks")
	}
	if _, err := process.inspectGuards(ctx, layout); err != nil {
		t.Fatal(err)
	}
	packetNft(ctx, t, "flush set inet translation_router_fixture protected4")
	verifyWithdrawnCallbacks := func() {}
	if len(callbacks) != 0 && callbacks[0] {
		verifyWithdrawnCallbacks = qualifyTranslatedCallbacks(ctx, t, layout, process, peer, device, callbacks[1:]...)
	}
	qualifyControllerICMP(ctx, t, peer, device, icmpEnabled)
	qualifyNativeControllerEcho(ctx, t, peer, device, icmpEnabled)
	// An unavailable exact source map removes both translated permit legs,
	// retaining deny identities even for an already-established connection.
	unready := translatedControllerLayout(t, false, icmpEnabled)
	unreadyProgram, err := unready.program(ctx)
	if err != nil {
		t.Fatal(err)
	}
	packetNft(ctx, t, "delete table inet "+ownedTable+"; delete table netdev "+ownedTable+"; "+string(unreadyProgram))
	packetNft(ctx, t, "flush set inet translation_router_fixture protected4")
	request(48000, false, 0, 0, 0, false)
	reply(48000, false, 0, 0, 0, false)
	qualifyControllerICMP(ctx, t, peer, device, false)
	verifyWithdrawnCallbacks()
	if _, err := process.inspectGuards(ctx, unready); err != nil {
		t.Fatal(err)
	}
}
