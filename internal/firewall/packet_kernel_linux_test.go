//go:build integration && kernel && linux

package firewall

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os/exec"
	"strings"
	"syscall"
	"testing"
	"time"
)

// This is a packet-field qualification fixture, not the production guard.
// Raw endpoints are intentionally not local IP addresses: packets must route
// between veth pairs through forward, postrouting and final Ethernet egress.
func TestKernelRoutedPacketIdentityAndFinalEgressDrop(t *testing.T) {
	requireKernelIsolation(t)
	t.Cleanup(func() { requireKernelIsolation(t) })
	ctx, cancel := context.WithTimeout(t.Context(), 15*time.Second)
	defer cancel()
	setupPacketLinks(ctx, t)
	peer := packetSocket(t, "peer0")
	device := packetSocket(t, "device0")
	for _, family := range []struct {
		name                  string
		peer, device, unknown string
	}{
		{name: "ipv4", peer: "10.240.0.10", device: "10.240.3.10", unknown: "10.240.3.11"},
		{name: "ipv6", peer: "fdca:1a2b::10", device: "fdca:1a2b:3::10", unknown: "fdca:1a2b:3::11"},
	} {
		t.Run(family.name, func(t *testing.T) {
			setupPacketCounters(ctx, t)
			peerIP, deviceIP := netip.MustParseAddr(family.peer), netip.MustParseAddr(family.device)
			// The first flow is initiated by the peer; the second by the device.
			packets := []struct {
				name                        string
				fromPeer                    bool
				sourcePort, destinationPort uint16
			}{
				{name: "peer initiation", fromPeer: true, sourcePort: 40000, destinationPort: 6053},
				{name: "device correlated reply", sourcePort: 6053, destinationPort: 40000},
				{name: "device initiation", sourcePort: 40001, destinationPort: 6053},
				{name: "peer correlated reply", fromPeer: true, sourcePort: 6053, destinationPort: 40001},
			}
			for _, packet := range packets {
				t.Run(packet.name, func(t *testing.T) {
					input, output := device, peer
					source, destination := deviceIP, peerIP
					sourceMAC, routerMAC := "02:00:00:00:00:13", "02:00:00:00:01:13"
					if packet.fromPeer {
						input, output = peer, device
						source, destination = peerIP, deviceIP
						sourceMAC, routerMAC = "02:00:00:00:00:10", "02:00:00:00:01:10"
					}
					frame := packetFrame(t, packetDatagram{
						source: source, destination: destination,
						sourceMAC: sourceMAC, destinationMAC: routerMAC,
						sourcePort: packet.sourcePort, destinationPort: packet.destinationPort,
						payload: "synthetic-" + family.name + "-" + packet.name,
					})
					sendPacket(ctx, t, input, frame)
					receivePacket(ctx, t, output, frame, true)
				})
			}
			assertPacketCounters(ctx, t, map[string]uint64{
				"forward_router_mac": 2, "forward_device_mac": 0, "forward_source_mac": 2,
				"legacy_accept": 4, "final_device_mac": 2, "final_peer_mac": 2,
				"device_handoff": 2, "peer_handoff": 2,
				"device_original": 1, "device_reply": 1, "peer_original": 1, "peer_reply": 1,
				"final_drop": 0,
			})
			// Even after a forward accept, final egress can close the permanent
			// device identity for new, established and unknown-address traffic.
			packetNft(ctx, t, `add rule netdev packet_observation device_egress `+
				`ether daddr 02:00:00:00:00:13 counter name final_drop drop`)
			for index, target := range []string{family.device, family.device, family.unknown} {
				port := uint16(40000)
				if index != 0 {
					port = 40100
				}
				frame := packetFrame(t, packetDatagram{
					source: peerIP, destination: netip.MustParseAddr(target),
					sourceMAC: "02:00:00:00:00:10", destinationMAC: "02:00:00:00:01:10",
					sourcePort: port, destinationPort: 6053,
					payload: fmt.Sprintf("synthetic-%s-dropped-%d", family.name, index),
				})
				sendPacket(ctx, t, peer, frame)
				receivePacket(ctx, t, device, frame, false)
			}
			assertPacketCounters(ctx, t, map[string]uint64{
				"forward_router_mac": 5, "forward_device_mac": 0,
				"legacy_accept": 7, "final_device_mac": 5, "final_drop": 3,
			})
		})
	}
}

func setupPacketLinks(ctx context.Context, t *testing.T) {
	t.Helper()
	for _, link := range []struct {
		router, endpoint, routerMAC, endpointMAC, v4, v6 string
	}{
		{router: "lan10", endpoint: "peer0", routerMAC: "02:00:00:00:01:10",
			endpointMAC: "02:00:00:00:00:10", v4: "10.240.0.1/24", v6: "fdca:1a2b::1/64"},
		{router: "lan13", endpoint: "device0", routerMAC: "02:00:00:00:01:13",
			endpointMAC: "02:00:00:00:00:13", v4: "10.240.3.1/24", v6: "fdca:1a2b:3::1/64"},
	} {
		packetIP(ctx, t, "link", "add", link.router, "type", "veth", "peer", "name", link.endpoint)
		// Register deletion immediately; a partial setup must not leave links
		// behind for a shuffled test that requires an empty namespace.
		t.Cleanup(func() {
			cleanup, cancel := context.WithTimeout(context.WithoutCancel(t.Context()), 2*time.Second)
			defer cancel()
			packetIP(cleanup, t, "link", "delete", link.router)
		})
		packetIP(ctx, t, "link", "set", link.router, "address", link.routerMAC)
		packetIP(ctx, t, "link", "set", link.endpoint, "address", link.endpointMAC)
		packetIP(ctx, t, "address", "add", link.v4, "dev", link.router)
		packetIP(ctx, t, "-6", "address", "add", link.v6, "dev", link.router, "nodad")
		packetIP(ctx, t, "link", "set", link.router, "up")
		packetIP(ctx, t, "link", "set", link.endpoint, "up")
	}
	for _, neighbor := range []struct{ address, mac, link string }{
		{address: "10.240.0.10", mac: "02:00:00:00:00:10", link: "lan10"},
		{address: "fdca:1a2b::10", mac: "02:00:00:00:00:10", link: "lan10"},
		{address: "10.240.3.10", mac: "02:00:00:00:00:13", link: "lan13"},
		{address: "fdca:1a2b:3::10", mac: "02:00:00:00:00:13", link: "lan13"},
		{address: "10.240.3.11", mac: "02:00:00:00:00:13", link: "lan13"},
		{address: "fdca:1a2b:3::11", mac: "02:00:00:00:00:13", link: "lan13"},
	} {
		packetIP(ctx, t, "neighbor", "add", neighbor.address, "lladdr", neighbor.mac,
			"dev", neighbor.link, "nud", "permanent")
	}
}

func packetIP(ctx context.Context, t *testing.T, arguments ...string) {
	t.Helper()
	// #nosec G204 -- Synthetic test-only operations in an acknowledged empty namespace.
	command := exec.CommandContext(ctx, "/usr/sbin/ip", arguments...)
	command.Env = []string{"LC_ALL=C", "PATH=/usr/sbin:/usr/bin"}
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("isolated virtual-link fixture failed: %v, %s", err, output)
	}
}

func setupPacketCounters(ctx context.Context, t *testing.T) {
	t.Helper()
	packetNft(ctx, t, `
table inet packet_observation {
 counter forward_router_mac {}
 counter forward_device_mac {}
 counter forward_source_mac {}
 counter legacy_accept {}
 counter device_original {}
 counter device_reply {}
 counter peer_original {}
 counter peer_reply {}
 chain forward {
  type filter hook forward priority 0; policy accept;
  meta mark set 0
  iifname "lan10" meta l4proto udp ether daddr 02:00:00:00:01:10 counter name forward_router_mac
  iifname "lan10" meta l4proto udp ether daddr 02:00:00:00:00:13 counter name forward_device_mac
  iifname "lan13" meta l4proto udp ether saddr 02:00:00:00:00:13 counter name forward_source_mac
  oifname "lan13" meta l4proto udp ct direction original ct state new ct original proto-dst 6053 counter name device_original meta mark set 0xa201
  oifname "lan13" meta l4proto udp ct direction reply ct state established ct original proto-dst 6053 counter name device_reply meta mark set 0xa201
  oifname "lan10" meta l4proto udp ct direction original ct state new ct original proto-dst 6053 counter name peer_original meta mark set 0xa201
  oifname "lan10" meta l4proto udp ct direction reply ct state established ct original proto-dst 6053 counter name peer_reply meta mark set 0xa201
  meta l4proto udp counter name legacy_accept accept
 }
}
table netdev packet_observation {
 counter final_device_mac {}
 counter final_peer_mac {}
 counter final_drop {}
 counter device_handoff {}
 counter peer_handoff {}
 # Packet taps observe endpoint delivery before these fixture-only drops.
 # Prevent the unconfigured raw endpoints from routing a received frame again.
 chain peer_endpoint {
  type filter hook ingress device "peer0" priority 0; policy drop;
 }
 chain device_endpoint {
  type filter hook ingress device "device0" priority 0; policy drop;
 }
 chain device_egress {
  type filter hook egress device "lan13" priority 0; policy accept;
  meta l4proto udp ether daddr 02:00:00:00:00:13 counter name final_device_mac
  meta l4proto udp meta mark 0xa201 counter name device_handoff
 }
 chain peer_egress {
  type filter hook egress device "lan10" priority 0; policy accept;
  meta l4proto udp ether daddr 02:00:00:00:00:10 counter name final_peer_mac
  meta l4proto udp meta mark 0xa201 counter name peer_handoff
 }
}`)
	t.Cleanup(func() {
		cleanup, cancel := context.WithTimeout(context.WithoutCancel(t.Context()), 2*time.Second)
		defer cancel()
		packetNft(cleanup, t, `delete table inet packet_observation; delete table netdev packet_observation`)
	})
}

func packetNft(ctx context.Context, t *testing.T, program string) {
	t.Helper()
	command := exec.CommandContext(ctx, "/usr/sbin/nft", "--file", "-")
	command.Env = []string{"LC_ALL=C", "PATH=/usr/sbin:/usr/bin"}
	command.Stdin = strings.NewReader(program)
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("isolated packet-observation fixture failed: %v, %s", err, output)
	}
}

func assertPacketCounters(ctx context.Context, t *testing.T, expected map[string]uint64) {
	t.Helper()
	observed := make(map[string]uint64, len(expected))
	for _, family := range []string{"inet", "netdev"} {
		data := kernelFixtureCommand(ctx, t, "list", "table", family, "packet_observation")
		var inventory struct {
			Objects []struct {
				Counter *struct {
					Name    string `json:"name"`
					Packets uint64 `json:"packets"`
				} `json:"counter"`
			} `json:"nftables"`
		}
		if err := json.Unmarshal(data, &inventory); err != nil {
			t.Fatal(err)
		}
		for _, object := range inventory.Objects {
			if object.Counter != nil {
				observed[object.Counter.Name] = object.Counter.Packets
			}
		}
	}
	for name, packets := range expected {
		if got, present := observed[name]; !present || got != packets {
			t.Errorf("packet counter %s: got %d (present=%t), want %d", name, got, present, packets)
		}
	}
}

type packetDatagram struct {
	source, destination         netip.Addr
	sourceMAC, destinationMAC   string
	sourcePort, destinationPort uint16
	payload                     string
	isTCP                       bool
	tcpFlags                    byte
	sequence, acknowledgment    uint32
}

func packetFrame(t *testing.T, datagram packetDatagram) []byte {
	t.Helper()
	if datagram.source.Is4() != datagram.destination.Is4() || len(datagram.payload) > 128 {
		t.Fatal("invalid synthetic packet geometry")
	}
	transportHeader, transportProtocol := 8, byte(17)
	if datagram.isTCP {
		transportHeader, transportProtocol = 20, 6
	}
	transport := make([]byte, transportHeader+len(datagram.payload))
	binary.BigEndian.PutUint16(transport[0:2], datagram.sourcePort)
	binary.BigEndian.PutUint16(transport[2:4], datagram.destinationPort)
	// The payload cap bounds the TCP/UDP segment to at most 148 bytes.
	if len(transport) > 65535 {
		t.Fatal("synthetic datagram length exceeds the wire field")
	}
	length := uint16(len(transport) & 0xffff)
	checksumOffset := 6
	if datagram.isTCP {
		binary.BigEndian.PutUint32(transport[4:8], datagram.sequence)
		binary.BigEndian.PutUint32(transport[8:12], datagram.acknowledgment)
		transport[12], transport[13] = 0x50, datagram.tcpFlags
		binary.BigEndian.PutUint16(transport[14:16], 4096)
		checksumOffset = 16
	} else {
		binary.BigEndian.PutUint16(transport[4:6], length)
	}
	copy(transport[transportHeader:], datagram.payload)
	ip := make([]byte, 40)
	protocol := uint16(0x86dd)
	pseudo := make([]byte, 40)
	if datagram.source.Is4() {
		protocol = 0x0800
		ip, pseudo = make([]byte, 20), make([]byte, 12)
		ip[0], ip[8], ip[9] = 0x45, 64, transportProtocol
		binary.BigEndian.PutUint16(ip[2:4], 20+length)
		source, destination := datagram.source.As4(), datagram.destination.As4()
		copy(ip[12:16], source[:])
		copy(ip[16:20], destination[:])
		binary.BigEndian.PutUint16(ip[10:12], packetChecksum(ip))
		copy(pseudo[0:4], source[:])
		copy(pseudo[4:8], destination[:])
		pseudo[9] = transportProtocol
		binary.BigEndian.PutUint16(pseudo[10:12], length)
	} else {
		ip[0], ip[6], ip[7] = 0x60, transportProtocol, 64
		binary.BigEndian.PutUint16(ip[4:6], length)
		source, destination := datagram.source.As16(), datagram.destination.As16()
		copy(ip[8:24], source[:])
		copy(ip[24:40], destination[:])
		copy(pseudo[0:16], source[:])
		copy(pseudo[16:32], destination[:])
		binary.BigEndian.PutUint32(pseudo[32:36], uint32(length))
		pseudo[39] = transportProtocol
	}
	checksum := packetChecksum(append(pseudo, transport...))
	if checksum == 0 {
		checksum = 0xffff
	}
	binary.BigEndian.PutUint16(transport[checksumOffset:checksumOffset+2], checksum)
	frame := make([]byte, 14, 14+len(ip)+len(transport))
	for index, address := range []string{datagram.destinationMAC, datagram.sourceMAC} {
		mac, err := net.ParseMAC(address)
		if err != nil || len(mac) != 6 {
			t.Fatal("invalid synthetic Ethernet address")
		}
		copy(frame[index*6:(index+1)*6], mac)
	}
	binary.BigEndian.PutUint16(frame[12:14], protocol)
	return append(append(frame, ip...), transport...)
}

func packetChecksum(data []byte) uint16 {
	var sum uint32
	for len(data) >= 2 {
		sum += uint32(binary.BigEndian.Uint16(data[:2]))
		data = data[2:]
	}
	if len(data) != 0 {
		sum += uint32(data[0]) << 8
	}
	for sum > 0xffff {
		sum = (sum & 0xffff) + (sum >> 16)
	}
	return ^uint16(sum & 0xffff)
}

type packetEndpoint struct {
	fd  int
	mac net.HardwareAddr
}

func packetSocket(t *testing.T, name string) packetEndpoint {
	t.Helper()
	link, err := net.InterfaceByName(name)
	if err != nil {
		t.Fatal(err)
	}
	if len(link.HardwareAddr) != 6 {
		t.Fatal("raw fixture requires an Ethernet endpoint")
	}
	// AF_PACKET expects the protocol argument in network byte order.
	protocol := int(binary.NativeEndian.Uint16([]byte{0, 3}))
	fd, err := syscall.Socket(syscall.AF_PACKET, syscall.SOCK_RAW|syscall.SOCK_CLOEXEC, protocol)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := syscall.Close(fd); err != nil {
			t.Error(err)
		}
	})
	if err := syscall.Bind(fd, &syscall.SockaddrLinklayer{Ifindex: link.Index}); err != nil {
		t.Fatal(err)
	}
	if err := syscall.SetsockoptTimeval(fd, syscall.SOL_SOCKET, syscall.SO_RCVTIMEO,
		&syscall.Timeval{Usec: 20000}); err != nil {
		t.Fatal(err)
	}
	return packetEndpoint{fd: fd, mac: bytes.Clone(link.HardwareAddr)}
}

func sendPacket(ctx context.Context, t *testing.T, endpoint packetEndpoint, frame []byte) {
	t.Helper()
	if err := ctx.Err(); err != nil {
		t.Fatal(err)
	}
	if err := syscall.Sendto(endpoint.fd, frame, 0, nil); err != nil {
		t.Fatalf("isolated raw packet send failed: %v", err)
	}
}

func receivePacket(ctx context.Context, t *testing.T, endpoint packetEndpoint, sent []byte, expected bool) {
	t.Helper()
	deadline := time.Now().Add(300 * time.Millisecond)
	if expected {
		deadline = time.Now().Add(time.Second)
	}
	buffer := make([]byte, 2048)
	for time.Now().Before(deadline) {
		if err := ctx.Err(); err != nil {
			t.Fatal(err)
		}
		length, address, err := syscall.Recvfrom(endpoint.fd, buffer, 0)
		if errors.Is(err, syscall.EAGAIN) || errors.Is(err, syscall.EINTR) {
			continue
		}
		if err != nil {
			t.Fatalf("isolated raw packet receive failed: %v", err)
		}
		link, ok := address.(*syscall.SockaddrLinklayer)
		if !ok || link.Pkttype == syscall.PACKET_OUTGOING || length != len(sent) {
			continue
		}
		// Match the transport segment, including its unique payload and checksum.
		header := 34
		if binary.BigEndian.Uint16(sent[12:14]) == 0x86dd {
			header = 54
		}
		if !bytes.Equal(buffer[header:length], sent[header:]) {
			continue
		}
		if !expected {
			t.Fatal("final egress drop leaked the synthetic packet")
		}
		addressStart, hop := 26, 22
		if header == 54 {
			addressStart, hop = 22, 21
		}
		correctMAC := bytes.Equal(buffer[:6], endpoint.mac)
		correctAddresses := bytes.Equal(buffer[addressStart:header], sent[addressStart:header])
		correctHop := buffer[hop] == 63
		if !correctMAC || !correctAddresses || !correctHop {
			t.Fatal("received frame did not retain its routed IP identity and final destination MAC")
		}
		return
	}
	if expected {
		t.Fatal("synthetic routed packet was not delivered")
	}
}
