package firewall

import (
	"fmt"
	"net/netip"

	"github.com/mikenorgate/router-policy-agent/internal/policy"
)

const (
	controllerOriginalTag = "0xb1000000"
	controllerReplyTag    = "0xb2000000"
)

// A leg is immutable image-owned native geometry, not an expiring directory
// permission. Its low mark bits identify exactly one controller/interface/prefix.
type controllerLeg struct {
	sourceInterface string
	targetInterface string
	source          netip.Addr
	target          netip.Prefix
	egressSource    netip.Addr
	index           uint64
	isICMPEnabled   bool
}

func controllerLegs(baseline policy.Baseline) []controllerLeg {
	legs := []controllerLeg{}
	var index uint64
	for _, controller := range baseline.ControllerInitiators {
		for _, address := range controller.Addresses {
			for _, zone := range baseline.Zones {
				if zone.Role != policy.Untrusted {
					continue
				}
				for _, network := range zone.Networks {
					if address.Is4() != network.Addr().Is4() {
						continue
					}
					for _, name := range zone.Interfaces {
						index++
						legs = append(legs, controllerLeg{
							sourceInterface: controller.SourceInterface, targetInterface: name,
							source: address, target: network, egressSource: address, index: index,
							isICMPEnabled: controller.ICMPEnabled,
						})
					}
				}
			}
		}
	}
	for _, leg := range controllerTranslationLegs(baseline) {
		index++
		leg.index = index
		legs = append(legs, leg)
	}
	return legs
}

func (leg controllerLeg) family() string {
	if leg.source.Is4() {
		return "ip"
	}
	return "ip6"
}

func (leg controllerLeg) mark(reply bool) string {
	tag := controllerOriginalTag
	if reply {
		tag = controllerReplyTag
	}
	return fmt.Sprintf("(%s | %d)", tag, leg.index)
}

func (layout *guardLayout) controllerForwardRules(verdict string, confirmation bool) []string {
	lines := make([]string, 0, 2*len(layout.controllers))
	for _, leg := range layout.controllers {
		for _, reply := range []bool{false, true} {
			incoming, outgoing := leg.sourceInterface, leg.targetInterface
			source, target, direction, state := leg.source.String(), leg.target.String(), "original", "{ new, established }"
			if reply {
				incoming, outgoing = outgoing, incoming
				source, target, direction, state = target, source, "reply", "established"
			}
			markCheck := ""
			if confirmation {
				markCheck = "meta mark & " + guardMarkMask + " == " + leg.mark(reply) + " "
			}
			lines = append(lines, fmt.Sprintf(
				"%smeta l4proto { tcp, udp } iifname %q oifname %q %s saddr %s %s daddr %s "+
					"ct direction %s ct state %s meta mark set meta mark & %s meta mark set meta mark | %s %s",
				markCheck, incoming, outgoing, leg.family(), source, leg.family(), target,
				direction, state, guardMarkKeep, leg.mark(reply), verdict,
			))
		}
	}
	return append(lines, layout.controllerICMPForwardRules(verdict, confirmation)...)
}

func (layout *guardLayout) controllerTagDrops() []string {
	if len(layout.controllers) == 0 {
		return []string{}
	}
	return []string{
		"meta mark & 0xff000000 == " + controllerOriginalTag + " drop",
		"meta mark & 0xff000000 == " + controllerReplyTag + " drop",
	}
}

func (layout *guardLayout) controllerIdentityDrops() []string {
	lines := []string{}
	for _, leg := range layout.uniqueControllerSources() {
		for _, field := range []string{"saddr", "daddr"} {
			lines = append(lines, fmt.Sprintf("%s %s %s drop", leg.family(), field, leg.source))
		}
	}
	return lines
}

func (layout *guardLayout) uniqueControllerSources() []controllerLeg {
	seen := map[netip.Addr]bool{}
	legs := []controllerLeg{}
	for _, leg := range layout.controllers {
		if !seen[leg.source] {
			legs = append(legs, leg)
			seen[leg.source] = true
		}
	}
	for _, address := range layout.controllerAliases {
		if !seen[address] {
			legs = append(legs, controllerLeg{source: address})
			seen[address] = true
		}
	}
	return legs
}

func (layout *guardLayout) controllerIdentityExpressions() [][]any {
	rules := [][]any{}
	for _, leg := range layout.uniqueControllerSources() {
		for _, field := range []string{"saddr", "daddr"} {
			rules = append(rules, []any{
				guardMatch(guardPayload(leg.family(), field), leg.source.String()), map[string]any{"drop": nil},
			})
		}
	}
	return rules
}

func (layout *guardLayout) controllerEgressRules(device string) []string {
	lines := []string{}
	for _, leg := range layout.controllers {
		for _, reply := range []bool{false, true} {
			source, target, outgoing := leg.egressSource.String(), leg.target.String(), leg.targetInterface
			if reply {
				source, target, outgoing = target, leg.source.String(), leg.sourceInterface
			}
			if outgoing != device {
				continue
			}
			lines = append(lines, fmt.Sprintf(
				"meta mark & %s == %s meta l4proto { tcp, udp } %s saddr %s %s daddr %s return",
				guardMarkMask, leg.mark(reply), leg.family(), source, leg.family(), target,
			))
		}
	}
	return append(lines, layout.controllerICMPEgressRules(device)...)
}

func (layout *guardLayout) controllerForwardExpressions(verdict string, confirmation bool) [][]any {
	rules := make([][]any, 0, 2*len(layout.controllers))
	for _, leg := range layout.controllers {
		for _, reply := range []bool{false, true} {
			incoming, outgoing := leg.sourceInterface, leg.targetInterface
			source, target := controllerAddress(leg.source), controllerPrefix(leg.target)
			direction := "original"
			state := any(map[string]any{"set": []string{"established", "new"}})
			if reply {
				incoming, outgoing, source, target, direction = outgoing, incoming, target, source, "reply"
				state = "established"
			}
			stateMatch := guardMatch(map[string]any{"ct": map[string]any{"key": "state"}}, state)
			if reply {
				// nft lists a single conntrack-state bit as a membership match.
				stateMatch = map[string]any{"match": map[string]any{"op": "in",
					"left": map[string]any{"ct": map[string]any{"key": "state"}}, "right": state}}
			}
			expressions := []any{}
			if confirmation {
				expressions = append(expressions, controllerMarkMatch(leg, reply))
			}
			expressions = append(expressions,
				guardMatch(guardMeta("l4proto"), map[string]any{"set": []string{"tcp", "udp"}}),
				guardMatch(guardMeta("iifname"), incoming), guardMatch(guardMeta("oifname"), outgoing),
				guardMatch(guardPayload(leg.family(), "saddr"), source),
				guardMatch(guardPayload(leg.family(), "daddr"), target),
				guardMatch(map[string]any{"ct": map[string]any{"key": "direction"}}, direction),
				stateMatch,
				guardMark(guardBinary("&", guardMeta("mark"), uint64(0x00ff0000))),
				guardMark(guardBinary("|", guardMeta("mark"), controllerMark(leg, reply))), map[string]any{verdict: nil},
			)
			rules = append(rules, expressions)
		}
	}
	return append(rules, layout.controllerICMPForwardExpressions(verdict, confirmation)...)
}

func (layout *guardLayout) controllerDropExpressions() [][]any {
	rules := [][]any{}
	if len(layout.controllers) != 0 {
		for _, tag := range []uint64{0xb1000000, 0xb2000000} {
			rules = append(rules, []any{
				guardMatch(guardBinary("&", guardMeta("mark"), uint64(0xff000000)), tag),
				map[string]any{"drop": nil},
			})
		}
	}
	return rules
}

func (layout *guardLayout) controllerEgressExpressions(device string) [][]any {
	rules := [][]any{}
	for _, leg := range layout.controllers {
		for _, reply := range []bool{false, true} {
			source, target, outgoing := controllerAddress(leg.egressSource), controllerPrefix(leg.target), leg.targetInterface
			if reply {
				source, target, outgoing = target, controllerAddress(leg.source), leg.sourceInterface
			}
			if outgoing != device {
				continue
			}
			rules = append(rules, []any{
				controllerMarkMatch(leg, reply),
				guardMatch(guardMeta("l4proto"), map[string]any{"set": []string{"tcp", "udp"}}),
				guardMatch(guardPayload(leg.family(), "saddr"), source),
				guardMatch(guardPayload(leg.family(), "daddr"), target), map[string]any{"return": nil},
			})
		}
	}
	return append(rules, layout.controllerICMPEgressExpressions(device)...)
}

func controllerMark(leg controllerLeg, reply bool) uint64 {
	tag := uint64(0xb1000000)
	if reply {
		tag = 0xb2000000
	}
	// Validation caps the expanded geometry at 512 legs, before construction.
	return tag | leg.index
}

func controllerMarkMatch(leg controllerLeg, reply bool) any {
	return guardMatch(guardBinary("&", guardMeta("mark"), uint64(0xff00ffff)), controllerMark(leg, reply))
}

func controllerAddress(address netip.Addr) any { return address.String() }

func controllerPrefix(prefix netip.Prefix) any {
	return map[string]any{"prefix": map[string]any{"addr": prefix.Addr().String(), "len": prefix.Bits()}}
}
