package firewall

import (
	"errors"
	"fmt"
	"strconv"
	"strings"
)

// guardTableSchema is derived from fixed code and the validated root layout,
// never from an observed listing or reader-supplied manifest. It describes only
// our objects; it is not an attestation of the surrounding protected chain graph.
type guardTableSchema struct {
	sets   map[string]map[string]any
	chains map[string]map[string]any
	rules  map[string][][]any
}

func (layout *guardLayout) schema(family string) (*guardTableSchema, error) {
	if layout == nil || len(layout.interfaces) == 0 {
		return nil, errors.New("firewall: missing owned guard geometry")
	}
	if family != "inet" && family != "netdev" {
		return nil, errors.New("firewall: unsupported guard family")
	}
	numbers := map[string]uint64{}
	for _, value := range []string{guardMarkKeep, fromOriginalTag, fromReplyTag, toOriginalTag, toReplyTag} {
		number, err := strconv.ParseUint(value, 0, 32)
		if err != nil {
			return nil, errors.New("firewall: invalid fixed guard mark")
		}
		numbers[value] = number
	}
	schema := &guardTableSchema{
		sets: map[string]map[string]any{}, chains: map[string]map[string]any{}, rules: map[string][][]any{},
	}
	schema.sets[cohortSet] = guardSetHeader(family, cohortSet, "ether_addr", maximumCohortSize)
	if family == "inet" {
		schema.sets[classified4Set] = guardSetHeader(family, classified4Set, "ipv4_addr", maximumTupleCount)
		schema.sets[classified6Set] = guardSetHeader(family, classified6Set, "ipv6_addr", maximumTupleCount)
	}
	for _, name := range grantSets {
		address := "ipv6_addr"
		if ipv4Set(name) {
			address = "ipv4_addr"
		}
		if family == "inet" {
			schema.sets[name] = guardLeaseHeader(family, name,
				[]string{"ifname", "ether_addr", address, address, "inet_service"})
			schema.sets[inboundSet(name)] = guardLeaseHeader(family, inboundSet(name),
				[]string{"ifname", address, address, "inet_service"})
			continue
		}
		schema.sets[egressSet(name)] = guardLeaseHeader(family, egressSet(name),
			[]string{"ifname", "ether_addr", address, address, "mark"})
	}
	for _, ref := range translatedGrantRefs(layout.translationPaths) {
		if ref.Family != family {
			continue
		}
		datatype := []string{"ifname", "ipv6_addr", "ipv6_addr", "inet_service"}
		if family == "netdev" {
			address := "ipv6_addr"
			if ref.Name == "transit_request4_tcp" || ref.Name == "transit_request4_udp" {
				address = "ipv4_addr"
			}
			datatype = []string{"ifname", address, address, "mark"}
		}
		schema.sets[ref.Name] = guardLeaseHeader(family, ref.Name, datatype)
	}
	if family == "inet" {
		schema.chains["guard_forward"] = map[string]any{
			"family": family, "table": ownedTable, "name": "guard_forward",
			"type": "filter", "hook": "forward", "prio": -150, "policy": "accept",
		}
		schema.chains["guard_confirm"] = map[string]any{
			"family": family, "table": ownedTable, "name": "guard_confirm",
			"type": "filter", "hook": "forward", "prio": 150, "policy": "accept",
		}
		schema.chains["permit_flow"] = map[string]any{"family": family, "table": ownedTable, "name": "permit_flow"}
		reset := []any{guardMark(guardBinary("&", guardMeta("mark"), numbers[guardMarkKeep]))}
		schema.rules["guard_forward"] = append([][]any{reset},
			layout.controllerForwardExpressions("return", false)...)
		_, translated := layout.translatedForward("return", false)
		schema.rules["guard_forward"] = append(schema.rules["guard_forward"], translated...)
		schema.rules["guard_forward"] = append(schema.rules["guard_forward"],
			guardForwardExpressions("return", numbers)...)
		schema.rules["guard_forward"] = append(schema.rules["guard_forward"], layout.controllerIdentityExpressions()...)
		schema.rules["guard_forward"] = append(schema.rules["guard_forward"], guardClassificationExpressions()...)
		schema.rules["guard_confirm"] = [][]any{{map[string]any{"jump": map[string]any{"target": "permit_flow"}}}}
		for _, tag := range []string{fromOriginalTag, fromReplyTag, toOriginalTag, toReplyTag} {
			schema.rules["guard_confirm"] = append(schema.rules["guard_confirm"], []any{
				guardMatch(guardBinary("&", guardMeta("mark"), uint64(0xff000000)), numbers[tag]),
				map[string]any{"drop": nil},
			})
		}
		schema.rules["guard_confirm"] = append(schema.rules["guard_confirm"], layout.controllerDropExpressions()...)
		_, drops := layout.translatedTagDrops()
		schema.rules["guard_confirm"] = append(schema.rules["guard_confirm"], drops...)
		schema.rules["guard_confirm"] = append(schema.rules["guard_confirm"], layout.controllerIdentityExpressions()...)
		schema.rules["guard_confirm"] = append(schema.rules["guard_confirm"], guardClassificationExpressions()...)
		schema.rules["permit_flow"] = layout.controllerForwardExpressions("accept", true)
		_, translated = layout.translatedForward("accept", true)
		schema.rules["permit_flow"] = append(schema.rules["permit_flow"], translated...)
		schema.rules["permit_flow"] = append(schema.rules["permit_flow"], guardForwardExpressions("accept", numbers)...)
		return schema, nil
	}
	for index, device := range layout.interfaces {
		name := fmt.Sprintf("guard_egress_%d", index)
		schema.chains[name] = map[string]any{
			"family": family, "table": ownedTable, "name": name, "dev": device,
			"type": "filter", "hook": "egress", "prio": 0, "policy": "accept",
		}
		rules := make([][]any, 0, len(grantSets)+3)
		rules = append(rules, layout.controllerEgressExpressions(device)...)
		_, translated := layout.translatedEgress(device)
		rules = append(rules, translated...)
		for _, set := range grantSets {
			_, incoming := guardTags(set)
			address, protocol := guardProtocol(set)
			key := map[string]any{"concat": []any{
				guardMeta("oifname"), guardPayload("ether", "daddr"),
				guardPayload(address, "daddr"), guardPayload(address, "saddr"),
				guardBinary("&", guardMeta("mark"), uint64(0x0000ffff)),
			}}
			rules = append(rules, []any{
				guardMatch(guardMeta("l4proto"), protocol),
				guardMatch(guardBinary("&", guardMeta("mark"), uint64(0xff000000)), numbers[incoming]),
				guardMatch(key, "@"+egressSet(set)), map[string]any{"return": nil},
			})
		}
		for _, tag := range []string{fromReplyTag, toOriginalTag} {
			rules = append(rules, []any{
				guardMatch(guardBinary("&", guardMeta("mark"), uint64(0xff000000)), numbers[tag]),
				map[string]any{"drop": nil},
			})
		}
		schema.rules[name] = append(rules,
			[]any{guardMatch(guardPayload("ether", "daddr"), "@"+cohortSet), map[string]any{"drop": nil}})
		schema.rules[name] = append(schema.rules[name], layout.controllerDropExpressions()...)
		_, drops := layout.translatedTagDrops()
		schema.rules[name] = append(schema.rules[name], drops...)
	}
	return schema, nil
}

func guardClassificationExpressions() [][]any {
	rules := [][]any{
		{guardMatch(guardPayload("ether", "saddr"), "@"+cohortSet), map[string]any{"drop": nil}},
	}
	for _, address := range []struct{ family, set string }{
		{family: "ip", set: classified4Set}, {family: "ip6", set: classified6Set},
	} {
		for _, direction := range []string{"saddr", "daddr"} {
			rules = append(rules,
				[]any{guardMatch(guardPayload(address.family, direction), "@"+address.set), map[string]any{"drop": nil}})
		}
	}
	return rules
}

func guardForwardExpressions(verdict string, numbers map[string]uint64) [][]any {
	rules := make([][]any, 0, 2*len(grantSets))
	for _, name := range grantSets {
		address, protocol := guardProtocol(name)
		outgoing, incoming := guardTags(name)
		sourceDirection, targetDirection := "reply", "original"
		if strings.HasPrefix(name, "lease_from") {
			sourceDirection, targetDirection = "original", "reply"
		}
		for _, flow := range []struct {
			direction, set, tag string
			key                 []any
		}{
			{direction: sourceDirection, set: name, tag: outgoing, key: []any{
				guardMeta("iifname"), guardPayload("ether", "saddr"),
				guardPayload(address, "saddr"), guardPayload(address, "daddr"), guardListener(),
			}},
			{direction: targetDirection, set: inboundSet(name), tag: incoming, key: []any{
				guardMeta("oifname"), guardPayload(address, "daddr"), guardPayload(address, "saddr"), guardListener(),
			}},
		} {
			rules = append(rules, []any{
				guardMatch(guardMeta("l4proto"), protocol),
				guardMatch(map[string]any{"ct": map[string]any{"key": "state"}},
					map[string]any{"set": []string{"established", "new"}}),
				guardMatch(map[string]any{"ct": map[string]any{"key": "direction"}}, flow.direction),
				guardMatch(map[string]any{"concat": flow.key}, "@"+flow.set),
				guardMark(guardBinary("|", guardBinary("&", guardMeta("mark"), numbers[guardMarkKeep]), guardListener())),
				guardMark(guardBinary("|", guardMeta("mark"), numbers[flow.tag])), map[string]any{verdict: nil},
			})
		}
	}
	return rules
}

func guardSetHeader(family, name string, datatype any, size int) map[string]any {
	return map[string]any{"family": family, "table": ownedTable, "name": name, "type": datatype, "size": size}
}

func guardLeaseHeader(family, name string, datatypes []string) map[string]any {
	header := guardSetHeader(family, name, datatypes, maximumTupleCount)
	header["flags"], header["timeout"] = []string{"timeout"}, 90
	return header
}

func guardMeta(key string) any { return map[string]any{"meta": map[string]any{"key": key}} }
func guardPayload(protocol, field string) any {
	return map[string]any{"payload": map[string]any{"protocol": protocol, "field": field}}
}
func guardListener() any {
	return map[string]any{"ct": map[string]any{"key": "proto-dst", "dir": "original"}}
}
func guardBinary(operator string, left, right any) any {
	return map[string]any{operator: []any{left, right}}
}
func guardMatch(left, right any) any {
	return map[string]any{"match": map[string]any{"op": "==", "left": left, "right": right}}
}
func guardMark(value any) any {
	return map[string]any{"mangle": map[string]any{"key": guardMeta("mark"), "value": value}}
}
