package firewall

import "fmt"

// ICMP is an explicit root-owned option. Echo follows the exact ordinary leg;
// errors must quote its controller-originated TCP/UDP conntrack tuple. A
// userspace translator receives no authority from the previous family.
type controllerICMPFlow struct {
	isReply bool
	isError bool
}

func controllerICMPFlows() []controllerICMPFlow {
	return []controllerICMPFlow{{}, {isReply: true}, {isReply: true, isError: true}}
}

func (leg controllerLeg) icmpType(flow controllerICMPFlow) (string, string, any) {
	protocol, header, echo := "icmp", "icmp", "echo-request"
	errors := []string{"destination-unreachable", "time-exceeded", "parameter-problem"}
	if leg.source.Is6() {
		protocol, header = "ipv6-icmp", "icmpv6"
		errors = []string{"destination-unreachable", "packet-too-big", "time-exceeded", "parameter-problem"}
	}
	if flow.isReply {
		echo = "echo-reply"
	}
	if flow.isError {
		return protocol, header, map[string]any{"set": errors}
	}
	return protocol, header, echo
}

func (leg controllerLeg) icmpSelector(flow controllerICMPFlow) (string, []any) {
	protocol, header, kind := leg.icmpType(flow)
	typeText := fmt.Sprint(kind)
	if flow.isError {
		typeText = "{ destination-unreachable, time-exceeded, parameter-problem }"
		if leg.source.Is6() {
			typeText = "{ destination-unreachable, packet-too-big, time-exceeded, parameter-problem }"
		}
	}
	selector := "meta l4proto " + protocol + " " + header + " type " + typeText
	expressions := []any{
		// nft folds the redundant L4 dependency into the typed ICMP payload.
		// Its JSON listing exposes only the typed payload condition.
		guardMatch(guardPayload(header, "type"), kind),
	}
	if !flow.isError {
		selector += " " + header + " code 0"
		expressions = append(expressions, guardMatch(guardPayload(header, "code"), 0))
	}
	return selector, expressions
}

func controllerCTState(state any) any {
	return map[string]any{"match": map[string]any{"op": "in",
		"left": map[string]any{"ct": map[string]any{"key": "state"}}, "right": state}}
}

func (leg controllerLeg) icmpForwardMatch(flow controllerICMPFlow) (string, []any) {
	selector, expressions := leg.icmpSelector(flow)
	incoming, outgoing := leg.sourceInterface, leg.targetInterface
	source, target, direction := leg.source.String(), leg.target.String(), "original"
	stateText := "{ new, established }"
	state := any(map[string]any{"set": []string{"established", "new"}})
	if flow.isReply {
		incoming, outgoing = outgoing, incoming
		source, target, direction = target, source, "reply"
		stateText, state = "established", "established"
	}
	selector += fmt.Sprintf(" iifname %q oifname %q ", incoming, outgoing)
	expressions = append(expressions, guardMatch(guardMeta("iifname"), incoming), guardMatch(guardMeta("oifname"), outgoing))
	if !flow.isError {
		selector += leg.family() + " saddr " + source + " "
		value := controllerAddress(leg.source)
		if flow.isReply {
			value = controllerPrefix(leg.target)
		}
		expressions = append(expressions, guardMatch(guardPayload(leg.family(), "saddr"), value))
	}
	selector += leg.family() + " daddr " + target
	targetValue := controllerPrefix(leg.target)
	if flow.isReply {
		targetValue = controllerAddress(leg.source)
	}
	expressions = append(expressions, guardMatch(guardPayload(leg.family(), "daddr"), targetValue))
	if flow.isError {
		stateText, state = "related", "related"
		selector += " ct original " + leg.family() + " saddr " + leg.source.String() +
			" ct original " + leg.family() + " daddr " + leg.target.String() + " ct protocol { tcp, udp }"
		expressions = append(expressions,
			guardMatch(map[string]any{"ct": map[string]any{"key": leg.family() + " saddr", "dir": "original"}}, controllerAddress(leg.source)),
			guardMatch(map[string]any{"ct": map[string]any{"key": leg.family() + " daddr", "dir": "original"}}, controllerPrefix(leg.target)),
			guardMatch(map[string]any{"ct": map[string]any{"key": "protocol"}}, map[string]any{"set": []string{"tcp", "udp"}}),
		)
	}
	selector += " ct direction " + direction + " ct state " + stateText
	stateMatch := guardMatch(map[string]any{"ct": map[string]any{"key": "state"}}, state)
	if flow.isReply {
		stateMatch = controllerCTState(state)
	}
	expressions = append(expressions, guardMatch(map[string]any{"ct": map[string]any{"key": "direction"}}, direction), stateMatch)
	return selector, expressions
}

func (layout *guardLayout) controllerICMPForwardRules(verdict string, confirmation bool) []string {
	lines := []string{}
	for _, leg := range layout.controllers {
		if !leg.isICMPEnabled {
			continue
		}
		for _, flow := range controllerICMPFlows() {
			selector, _ := leg.icmpForwardMatch(flow)
			if confirmation {
				selector = "meta mark & " + guardMarkMask + " == " + leg.mark(flow.isReply) + " " + selector
			}
			lines = append(lines, selector+" meta mark set meta mark & "+guardMarkKeep+
				" meta mark set meta mark | "+leg.mark(flow.isReply)+" "+verdict)
		}
	}
	return lines
}

func (layout *guardLayout) controllerICMPForwardExpressions(verdict string, confirmation bool) [][]any {
	rules := [][]any{}
	for _, leg := range layout.controllers {
		if !leg.isICMPEnabled {
			continue
		}
		for _, flow := range controllerICMPFlows() {
			_, expressions := leg.icmpForwardMatch(flow)
			if confirmation {
				expressions = append([]any{controllerMarkMatch(leg, flow.isReply)}, expressions...)
			}
			expressions = append(expressions,
				guardMark(guardBinary("&", guardMeta("mark"), uint64(0x00ff0000))),
				guardMark(guardBinary("|", guardMeta("mark"), controllerMark(leg, flow.isReply))), map[string]any{verdict: nil},
			)
			rules = append(rules, expressions)
		}
	}
	return rules
}

func (leg controllerLeg) icmpEgressMatch(flow controllerICMPFlow) (string, []any) {
	selector, expressions := leg.icmpSelector(flow)
	source, target := controllerAddress(leg.egressSource), controllerPrefix(leg.target)
	sourceText, targetText := leg.egressSource.String(), leg.target.String()
	if flow.isReply {
		source, target = target, controllerAddress(leg.source)
		sourceText, targetText = targetText, leg.source.String()
	}
	if !flow.isError {
		selector += " " + leg.family() + " saddr " + sourceText
		expressions = append(expressions, guardMatch(guardPayload(leg.family(), "saddr"), source))
	}
	selector += " " + leg.family() + " daddr " + targetText
	expressions = append(expressions, guardMatch(guardPayload(leg.family(), "daddr"), target))
	return selector, expressions
}

func (layout *guardLayout) controllerICMPEgressRules(device string) []string {
	lines := []string{}
	for _, leg := range layout.controllers {
		if !leg.isICMPEnabled {
			continue
		}
		for _, flow := range controllerICMPFlows() {
			outgoing := leg.targetInterface
			if flow.isReply {
				outgoing = leg.sourceInterface
			}
			if outgoing != device {
				continue
			}
			selector, _ := leg.icmpEgressMatch(flow)
			lines = append(lines, "meta mark & "+guardMarkMask+" == "+leg.mark(flow.isReply)+" "+selector+" return")
		}
	}
	return lines
}

func (layout *guardLayout) controllerICMPEgressExpressions(device string) [][]any {
	rules := [][]any{}
	for _, leg := range layout.controllers {
		if !leg.isICMPEnabled {
			continue
		}
		for _, flow := range controllerICMPFlows() {
			outgoing := leg.targetInterface
			if flow.isReply {
				outgoing = leg.sourceInterface
			}
			if outgoing != device {
				continue
			}
			_, expressions := leg.icmpEgressMatch(flow)
			expressions = append([]any{controllerMarkMatch(leg, flow.isReply)}, expressions...)
			rules = append(rules, append(expressions, map[string]any{"return": nil}))
		}
	}
	return rules
}
