package firewall

import (
	"fmt"
	"slices"
)

type translatedInterfacePair struct {
	tun, peer string
}

func translatedInterfacePairs(paths []deviceTranslationPath) []translatedInterfacePair {
	pairs := []translatedInterfacePair{}
	seen := map[translatedInterfacePair]bool{}
	for _, path := range paths {
		pair := translatedInterfacePair{tun: path.tunInterface, peer: path.peerInterface}
		if !seen[pair] {
			pairs = append(pairs, pair)
			seen[pair] = true
		}
	}
	return pairs
}

func (layout *guardLayout) translatedSetDefinitions(family string) []string {
	lines := []string{}
	for _, ref := range translatedGrantRefs(layout.translationPaths) {
		if ref.Family != family {
			continue
		}
		datatype := "ifname . ipv6_addr . ipv6_addr . inet_service"
		if family == "netdev" {
			address := "ipv6_addr"
			if ref.Name == "transit_request4_tcp" || ref.Name == "transit_request4_udp" {
				address = "ipv4_addr"
			}
			datatype = "ifname . " + address + " . " + address + " . inet_service"
		}
		lines = append(lines, guardSetDefinition(ref.Name, datatype))
	}
	return lines
}

func (layout *guardLayout) translatedForward(verdict string, confirmation bool) ([]string, [][]any) {
	lines, rules := []string{}, [][]any{}
	if len(layout.translationPaths) == 0 {
		return lines, rules
	}
	for _, protocol := range []string{"tcp", "udp"} {
		for _, pair := range translatedInterfacePairs(layout.translationPaths) {
			for _, isReply := range []bool{false, true} {
				incoming, source, target := "iifname", "saddr", "daddr"
				inputName, outputName := pair.tun, pair.peer
				direction, tag, tagValue := "original", translatedOriginalTag, uint64(0xc1000000)
				stateText := "{ new, established }"
				state := guardMatch(map[string]any{"ct": map[string]any{"key": "state"}},
					map[string]any{"set": []string{"established", "new"}})
				if isReply {
					incoming, source, target = "oifname", target, source
					inputName, outputName = outputName, inputName
					direction, tag, tagValue = "reply", translatedReplyTag, 0xc2000000
					stateText, state = "established", controllerCTState("established")
				}
				selector, expressions := "", []any{}
				if confirmation {
					selector = "meta mark & 0xff000000 == " + tag + " "
					expressions = append(expressions,
						guardMatch(guardBinary("&", guardMeta("mark"), uint64(0xff000000)), tagValue),
					)
				}
				selector += fmt.Sprintf("meta l4proto %s ct state %s ct direction %s "+
					"iifname %q oifname %q %s . ip6 %s . ip6 %s . ct original proto-dst @transit_from6_%s ",
					protocol, stateText, direction, inputName, outputName, incoming, source, target, protocol)
				expressions = append(expressions,
					guardMatch(guardMeta("l4proto"), protocol), state,
					guardMatch(map[string]any{"ct": map[string]any{"key": "direction"}}, direction),
					guardMatch(guardMeta("iifname"), inputName), guardMatch(guardMeta("oifname"), outputName),
					guardMatch(map[string]any{"concat": []any{
						guardMeta(incoming), guardPayload("ip6", source), guardPayload("ip6", target), guardListener(),
					}}, "@transit_from6_"+protocol),
					guardStampGoto(tag, verdict),
				)
				selector += "goto " + guardStampChain(tag, verdict)
				lines, rules = append(lines, selector), append(rules, expressions)
			}
		}
	}
	return lines, rules
}

func (layout *guardLayout) translatedEgress(device string) ([]string, [][]any) {
	lines, rules := []string{}, [][]any{}
	if len(layout.translationPaths) == 0 {
		return lines, rules
	}
	isTUN := slices.ContainsFunc(layout.translationPaths, func(path deviceTranslationPath) bool {
		return path.tunInterface == device
	})
	for _, protocol := range []string{"tcp", "udp"} {
		flows := []struct {
			name, family, source, target, tag string
			value                             uint64
		}{
			{name: "transit_request6_", family: "ip6", source: "saddr", target: "daddr",
				tag: translatedOriginalTag, value: 0xc1000000},
			{name: "transit_reply6_", family: "ip6", source: "daddr", target: "saddr",
				tag: translatedReplyTag, value: 0xc2000000},
		}
		if isTUN {
			flows = append(flows, struct {
				name, family, source, target, tag string
				value                             uint64
			}{name: "transit_request4_", family: "ip", source: "saddr", target: "daddr",
				tag: fromOriginalTag, value: 0xa1000000})
		}
		for _, flow := range flows {
			listener := "dport"
			if flow.name == "transit_reply6_" {
				listener = "sport"
			}
			lines = append(lines, fmt.Sprintf("meta l4proto %s meta mark & 0xff000000 == %s "+
				"oifname . %s %s . %s %s . %s %s @%s%s return",
				protocol, flow.tag, flow.family, flow.source, flow.family, flow.target, protocol, listener, flow.name, protocol))
			rules = append(rules, []any{
				guardMatch(guardBinary("&", guardMeta("mark"), uint64(0xff000000)), flow.value),
				guardMatch(map[string]any{"concat": []any{
					guardMeta("oifname"), guardPayload(flow.family, flow.source), guardPayload(flow.family, flow.target),
					guardPayload(protocol, listener),
				}}, "@"+flow.name+protocol), map[string]any{"return": nil},
			})
		}
	}
	if isTUN {
		lines = append(lines, "meta mark & 0xff000000 == "+fromOriginalTag+" drop")
		rules = append(rules, []any{
			guardMatch(guardBinary("&", guardMeta("mark"), uint64(0xff000000)), uint64(0xa1000000)), map[string]any{"drop": nil},
		})
	}
	return lines, rules
}

func (layout *guardLayout) translatedTagDrops() ([]string, [][]any) {
	lines, rules := []string{}, [][]any{}
	if len(layout.translationPaths) == 0 {
		return lines, rules
	}
	for index, tag := range []string{translatedOriginalTag, translatedReplyTag} {
		lines = append(lines, "meta mark & 0xff000000 == "+tag+" drop")
		rules = append(rules, []any{
			guardMatch(guardBinary("&", guardMeta("mark"), uint64(0xff000000)), uint64(0xc1000000+index*0x01000000)),
			map[string]any{"drop": nil},
		})
	}
	return lines, rules
}
