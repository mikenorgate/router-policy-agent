//go:build integration && kernel && linux

package firewall

import (
	"context"
	"encoding/json"
	"fmt"
	"net/netip"
	"testing"
	"time"
)

func TestKernelBootstrapDNSAndNTPWithoutGrants(t *testing.T) {
	requireKernelIsolation(t)
	t.Cleanup(func() { requireKernelIsolation(t) })
	ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
	defer cancel()
	setupPacketLinks(ctx, t)
	layout, err := newGuardLayout(bootstrapBaseline(t))
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"trusted0", "lan11", "lan12", "lan14", "lan15"} {
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
	packetNft(ctx, t, `table netdev bootstrap_endpoint_fixture {
 chain service_endpoint { type filter hook ingress device "peer0" priority 0; policy drop; }
 chain client_endpoint { type filter hook ingress device "device0" priority 0; policy drop; }
}`)
	packetNft(ctx, t, `table inet bootstrap_redirect_fixture {
 chain forced_services { type nat hook prerouting priority -100; policy accept;
  iifname "lan13" ip daddr 192.0.2.123 udp dport { 53, 123 } dnat ip to 10.240.0.10
  iifname "lan13" ip6 daddr 2001:db8::123 udp dport { 53, 123 } dnat ip6 to fdca:1a2b::10
 }
}`)
	t.Cleanup(func() {
		cleanup, cancel := context.WithTimeout(context.WithoutCancel(t.Context()), 2*time.Second)
		defer cancel()
		packetNft(cleanup, t, "delete table inet "+ownedTable+"; delete table netdev "+ownedTable+
			"; delete table netdev bootstrap_endpoint_fixture; delete table inet bootstrap_redirect_fixture")
	})
	process, err := openProcess(ctx, "/usr/sbin/nft")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = process.close() })
	if _, err := process.inspectGuards(ctx, layout); err != nil {
		for _, family := range []string{"inet", "netdev"} {
			data := kernelFixtureCommand(ctx, t, "list", "table", family, ownedTable)
			var listing struct {
				Objects []map[string]json.RawMessage `json:"nftables"`
			}
			if err := json.Unmarshal(data, &listing); err != nil {
				t.Fatal(err)
			}
			schema, err := layout.schema(family)
			if err != nil {
				t.Fatal(err)
			}
			positions := map[string]int{}
			for _, object := range listing.Objects {
				var rule struct {
					Chain       string `json:"chain"`
					Expressions []any  `json:"expr"`
				}
				if raw, ok := object["rule"]; ok {
					if err := json.Unmarshal(raw, &rule); err != nil {
						t.Fatal(err)
					}
					index := positions[rule.Chain]
					positions[rule.Chain]++
					actual, _ := json.Marshal(rule.Expressions)
					wanted, _ := json.Marshal(schema.rules[rule.Chain][index])
					if string(actual) != string(wanted) {
						t.Fatalf("%s/%s/%d\nactual: %s\nwant: %s", family, rule.Chain, index, actual, wanted)
					}
				}
			}
		}
		t.Fatalf("bootstrap program did not match actual kernel schema: %v", err)
	}
	service, client := packetSocket(t, "peer0"), packetSocket(t, "device0")
	for _, family := range []struct{ server, client string }{
		{server: "10.240.0.10", client: "10.240.3.10"},
		{server: "fdca:1a2b::10", client: "fdca:1a2b:3::10"},
	} {
		t.Run(family.client, func(t *testing.T) {
			serverIP, clientIP := netip.MustParseAddr(family.server), netip.MustParseAddr(family.client)
			batch := guardPacketBatch(t, clientIP, serverIP, false)
			applyGuardFixture(ctx, t, batch)
			for index, port := range []uint16{53, 123, 853, 443} {
				allowed := port == 53 || port == 123
				clientPort := uint16(48000 + index)
				for _, reply := range []bool{false, true} {
					input, output, source, target := client, service, clientIP, serverIP
					sourceMAC, routerMAC := "02:00:00:00:00:13", "02:00:00:00:01:13"
					sourcePort, targetPort := clientPort, port
					if reply {
						input, output, source, target = service, client, serverIP, clientIP
						sourceMAC, routerMAC = "02:00:00:00:00:10", "02:00:00:00:01:10"
						sourcePort, targetPort = port, clientPort
					}
					frame := packetFrame(t, packetDatagram{
						source: source, destination: target, sourceMAC: sourceMAC, destinationMAC: routerMAC,
						sourcePort: sourcePort, destinationPort: targetPort,
						payload: fmt.Sprintf("synthetic-bootstrap-%d-%t", port, reply),
					})
					sendPacket(ctx, t, input, frame)
					receivePacket(ctx, t, output, frame, allowed)
				}
			}
			// Merely choosing UDP source port 123 cannot initiate a connection
			// to a classified device: only a tracked service reply is exempt.
			frame := packetFrame(t, packetDatagram{
				source: serverIP, destination: clientIP,
				sourceMAC: "02:00:00:00:00:10", destinationMAC: "02:00:00:00:01:10",
				sourcePort: 123, destinationPort: 49000, payload: "unsolicited-synthetic-ntp",
			})
			sendPacket(ctx, t, service, frame)
			receivePacket(ctx, t, client, frame, false)
			redirected := netip.MustParseAddr("192.0.2.123")
			if clientIP.Is6() {
				redirected = netip.MustParseAddr("2001:db8::123")
			}
			for _, port := range []uint16{53, 123} {
				request := packetDatagram{
					source: clientIP, destination: redirected,
					sourceMAC: "02:00:00:00:00:13", destinationMAC: "02:00:00:00:01:13",
					sourcePort: 49100 + port, destinationPort: port, payload: fmt.Sprintf("redirected-service-%d", port),
				}
				frame := packetFrame(t, request)
				request.destination = serverIP
				sendPacket(ctx, t, client, frame)
				receivePacket(ctx, t, service, packetFrame(t, request), true)
				reply := packetDatagram{
					source: serverIP, destination: clientIP,
					sourceMAC: "02:00:00:00:00:10", destinationMAC: "02:00:00:00:01:10",
					sourcePort: port, destinationPort: 49100 + port, payload: fmt.Sprintf("redirected-reply-%d", port),
				}
				frame = packetFrame(t, reply)
				reply.source = redirected
				sendPacket(ctx, t, service, frame)
				receivePacket(ctx, t, client, packetFrame(t, reply), true)
			}
		})
	}
}
