package firewall

import (
	"fmt"
	"net/netip"
)

const bootstrapReplyTag uint64 = 0xe1000000

// These paths only exempt fixed image-owned DNS/NTP traffic from cohort
// classification. The router's independent forward policy must still allow
// them. Replies must match a real conntrack reply before receiving an egress
// tag; a service port alone is never a forwarding authorization.
func (layout *guardLayout) bootstrapForward(verdict string) ([]string, [][]any) {
	lines, rules := []string{}, [][]any{}
	for _, path := range layout.bootstrapPaths {
		for _, service := range []struct {
			addresses []netip.Addr
			protocols []string
			port      uint16
		}{
			{addresses: path.DNSAddresses, protocols: []string{"tcp", "udp"}, port: 53},
			{addresses: path.NTPAddresses, protocols: []string{"udp"}, port: 123},
		} {
			for _, address := range service.addresses {
				family := "ip"
				if address.Is6() {
					family = "ip6"
				}
				for _, protocol := range service.protocols {
					for _, reply := range []bool{false, true} {
						incoming, outgoing := path.Interface, path.ServiceInterface
						field, direction, portField := "daddr", "original", "dport"
						stateText := "{ new, established }"
						state := guardMatch(map[string]any{"ct": map[string]any{"key": "state"}},
							map[string]any{"set": []string{"established", "new"}})
						if reply {
							incoming, outgoing = outgoing, incoming
							field, direction, portField = "saddr", "reply", "sport"
							stateText, state = "established", controllerCTState("established")
						}
						text := fmt.Sprintf("iifname %q oifname %q %s %s %s %s %s %d ct direction %s ct state %s",
							incoming, outgoing, family, field, address, protocol, portField, service.port, direction, stateText)
						expressions := []any{
							guardMatch(guardMeta("iifname"), incoming), guardMatch(guardMeta("oifname"), outgoing),
							guardMatch(guardPayload(family, field), address.String()),
							guardMatch(guardPayload(protocol, portField), service.port),
							guardMatch(map[string]any{"ct": map[string]any{"key": "direction"}}, direction), state,
						}
						if reply {
							mark := bootstrapReplyTag | uint64(service.port)
							text += fmt.Sprintf(" meta mark set meta mark & %s meta mark set meta mark | 0x%08x", guardMarkKeep, mark)
							expressions = append(expressions,
								guardMark(guardBinary("&", guardMeta("mark"), uint64(0x00ff0000))),
								guardMark(guardBinary("|", guardMeta("mark"), mark)))
						}
						lines = append(lines, text+" "+verdict)
						rules = append(rules, append(expressions, map[string]any{verdict: nil}))
					}
				}
			}
		}
	}
	return lines, rules
}

func (layout *guardLayout) bootstrapForwardExpressions(verdict string) [][]any {
	_, rules := layout.bootstrapForward(verdict)
	return rules
}

func (layout *guardLayout) bootstrapEgress(device string) ([]string, [][]any) {
	lines, rules := []string{}, [][]any{}
	for _, path := range layout.bootstrapPaths {
		if path.Interface != device {
			continue
		}
		for _, service := range []struct {
			protocol string
			port     uint16
		}{{protocol: "tcp", port: 53}, {protocol: "udp", port: 53}, {protocol: "udp", port: 123}} {
			mark := bootstrapReplyTag | uint64(service.port)
			lines = append(lines, fmt.Sprintf("meta mark & %s == 0x%08x %s sport %d return",
				guardMarkMask, mark, service.protocol, service.port))
			rules = append(rules, []any{
				guardMatch(guardBinary("&", guardMeta("mark"), uint64(0xff00ffff)), mark),
				guardMatch(guardPayload(service.protocol, "sport"), service.port), map[string]any{"return": nil},
			})
		}
		for _, gateway := range path.GatewayAddresses {
			if gateway.Is4() {
				// Only the router's ARP reply and DHCP server response. ARP does
				// not authorize any IP flow and DHCP never exempts other ports.
				lines = append(lines, fmt.Sprintf("arp operation reply arp saddr ip %s return", gateway))
				rules = append(rules, []any{
					guardMatch(guardPayload("arp", "operation"), "reply"),
					guardMatch(guardPayload("arp", "saddr ip"), gateway.String()), map[string]any{"return": nil},
				})
				lines = append(lines, fmt.Sprintf("ip saddr %s udp sport 67 udp dport 68 return", gateway))
				rules = append(rules, []any{
					guardMatch(guardPayload("ip", "saddr"), gateway.String()),
					guardMatch(guardPayload("udp", "sport"), 67), guardMatch(guardPayload("udp", "dport"), 68),
					map[string]any{"return": nil},
				})
				continue
			}
			for _, kind := range []string{"nd-router-advert", "nd-neighbor-solicit", "nd-neighbor-advert"} {
				lines = append(lines, fmt.Sprintf("ip6 saddr %s ip6 hoplimit 255 icmpv6 type %s icmpv6 code 0 return",
					gateway, kind))
				rules = append(rules, []any{
					guardMatch(guardPayload("ip6", "saddr"), gateway.String()),
					guardMatch(guardPayload("ip6", "hoplimit"), 255),
					guardMatch(guardPayload("icmpv6", "type"), kind), guardMatch(guardPayload("icmpv6", "code"), 0),
					map[string]any{"return": nil},
				})
			}
		}
	}
	return lines, rules
}

func bootstrapTagDrop() string { return "meta mark & 0xff000000 == 0xe1000000 drop" }

func bootstrapTagDropExpression() []any {
	return []any{
		guardMatch(guardBinary("&", guardMeta("mark"), uint64(0xff000000)), bootstrapReplyTag),
		map[string]any{"drop": nil},
	}
}
