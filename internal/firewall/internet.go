package firewall

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"net/netip"
	"slices"
	"strings"

	"github.com/mikenorgate/router-policy-agent/internal/policy"
)

// Public eligibility is immutable image-owned geometry, shared by every lease.
// It is never supplied by a directory rule or added by a runtime transaction.
func (layout *guardLayout) internetPrefixSets() map[string][]netip.Prefix {
	sets := map[string][]netip.Prefix{
		"internet_allowed4": {}, "internet_allowed6": {},
		"internet_excluded4": {}, "internet_excluded6": {},
	}
	for _, source := range []struct {
		name   string
		values []netip.Prefix
	}{{name: "allowed", values: layout.internet.Allowed}, {name: "excluded", values: layout.internet.Excluded}} {
		for _, prefix := range source.values {
			family := "6"
			if prefix.Addr().Is4() {
				family = "4"
			}
			name := "internet_" + source.name + family
			sets[name] = append(sets[name], prefix)
		}
	}
	return sets
}

func (layout *guardLayout) internetSetDefinitions() []string {
	sets := layout.internetPrefixSets()
	lines := make([]string, 0, len(sets))
	for _, name := range slices.Sorted(maps.Keys(sets)) {
		typeName := "ipv6_addr"
		if strings.HasSuffix(name, "4") {
			typeName = "ipv4_addr"
		}
		values := make([]string, 0, len(sets[name]))
		for _, prefix := range sets[name] {
			values = append(values, prefix.String())
		}
		elements := ""
		if len(values) != 0 {
			elements = " elements = { " + strings.Join(values, ", ") + " };"
		}
		lines = append(lines, fmt.Sprintf("set %s { type %s; flags interval; size %d;%s }",
			name, typeName, maximumTupleCount, elements))
	}
	return lines
}

func internetWildcard(family string) string {
	if family == "ip" {
		return "0.0.0.0"
	}
	return "::"
}

func internetPredicate(name, family, direction string) string {
	if !internetSet(name) {
		return ""
	}
	suffix := "6"
	if family == "ip" {
		suffix = "4"
	}
	return fmt.Sprintf("%s %s @internet_allowed%s %s %s != @internet_excluded%s ",
		family, direction, suffix, family, direction, suffix)
}

func internetExpressions(name, family, direction string) []any {
	if !internetSet(name) {
		return []any{}
	}
	suffix := "6"
	if family == "ip" {
		suffix = "4"
	}
	return []any{
		guardMatch(guardPayload(family, direction), "@internet_allowed"+suffix),
		map[string]any{"match": map[string]any{
			"op": "!=", "left": guardPayload(family, direction), "right": "@internet_excluded" + suffix,
		}},
	}
}

func prefixValues(prefixes []netip.Prefix) []json.RawMessage {
	values := make([]json.RawMessage, 0, len(prefixes))
	for _, prefix := range prefixes {
		var value any = prefix.Addr().String()
		if !prefix.IsSingleIP() {
			value = map[string]any{"prefix": map[string]any{"addr": prefix.Addr().String(), "len": prefix.Bits()}}
		}
		encoded, _ := json.Marshal(value) // Only fixed strings, integers and maps are encoded.
		values = append(values, encoded)
	}
	return values
}

func checkInternetSet(actual []json.RawMessage, expected []netip.Prefix) error {
	if actual == nil {
		actual = []json.RawMessage{}
	}
	left, err := json.Marshal(actual)
	if err != nil {
		return errors.New("firewall: Internet geometry encoding failed")
	}
	right, err := json.Marshal(prefixValues(expected))
	if err != nil {
		return errors.New("firewall: Internet geometry encoding failed")
	}
	left, err = canonicalRulesetElements(left)
	if err != nil {
		return err
	}
	right, err = canonicalRulesetElements(right)
	if err != nil || !bytes.Equal(left, right) {
		return errors.New("firewall: immutable Internet exclusions or eligibility changed")
	}
	return nil
}

// Source-specific retained blocks cannot be folded into a shared global set.
// Check original traffic at forward and the actual recipient MAC on reply egress.
func (layout *guardLayout) internetBlockRules(egress bool) ([]string, [][]any) {
	lines, expressions := []string{}, [][]any{}
	for _, block := range layout.internet.Blocks {
		if block.SourceMAC == "" || len(block.Roles) != 0 && !slices.Contains(block.Roles, policy.Untrusted) {
			continue
		}
		for _, prefix := range block.Networks {
			family, peerField, macField := "ip6", "daddr", "saddr"
			if prefix.Addr().Is4() {
				family = "ip"
			}
			condition := "ct direction original "
			interfaces := make([]any, 0, len(layout.managedInterfaces))
			quoted := make([]string, 0, len(layout.managedInterfaces))
			for _, name := range layout.managedInterfaces {
				interfaces = append(interfaces, name)
				quoted = append(quoted, fmt.Sprintf("%q", name))
			}
			interfaceText := "{ " + strings.Join(quoted, ", ") + " }"
			var interfaceValue any = map[string]any{"set": interfaces}
			if len(interfaces) == 1 {
				interfaceText, interfaceValue = quoted[0], interfaces[0]
			}
			condition += "iifname " + interfaceText + " "
			checks := []any{
				guardMatch(map[string]any{"ct": map[string]any{"key": "direction"}}, "original"),
				guardMatch(guardMeta("iifname"), interfaceValue),
			}
			if egress {
				peerField, macField = "saddr", "daddr"
				condition = "meta mark & 0xff000000 == " + fromReplyTag + " "
				checks = []any{guardMatch(guardBinary("&", guardMeta("mark"), uint64(0xff000000)), uint64(0xa2000000))}
			}
			lines = append(lines, fmt.Sprintf("%sether %s %s %s%s %s %s drop",
				condition, macField, block.SourceMAC, internetPredicate("internet_from", family, peerField),
				family, peerField, prefix))
			checks = append(checks, guardMatch(guardPayload("ether", macField), block.SourceMAC))
			checks = append(checks, internetExpressions("internet_from", family, peerField)...)
			var target any = prefix.Addr().String()
			if !prefix.IsSingleIP() {
				target = map[string]any{"prefix": map[string]any{"addr": prefix.Addr().String(), "len": prefix.Bits()}}
			}
			checks = append(checks, guardMatch(guardPayload(family, peerField), target), map[string]any{"drop": nil})
			expressions = append(expressions, checks)
		}
	}
	return lines, expressions
}
