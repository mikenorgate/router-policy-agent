package firewall

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"

	"github.com/mikenorgate/router-policy-agent/internal/policy"
)

const (
	classified4Set  = "classified_addresses4"
	classified6Set  = "classified_addresses6"
	guardMarkMask   = "0xff00ffff"
	guardMarkKeep   = "0x00ff0000"
	fromOriginalTag = "0xa1000000"
	fromReplyTag    = "0xa2000000"
	toOriginalTag   = "0xa3000000"
	toReplyTag      = "0xa4000000"
)

// guardLayout describes image-owned objects, not reader-controlled rules. It
// supplies an early guard, a later permit chain and final destination-MAC checks.
// The image must independently qualify the protected floor, mark reservation,
// bootstrap paths, translator legs and the caller of permit_flow. This layout
// alone must not be activated as a complete router policy.
type guardLayout struct {
	interfaces        []string
	managedInterfaces []string
}

func newGuardLayout(baseline policy.Baseline) (*guardLayout, error) {
	// Decode an owned copy through the root-configuration validator. Neither
	// caller mutations nor attribute strings can choose names, hooks or marks.
	data, err := json.Marshal(baseline)
	if err != nil {
		return nil, errors.New("firewall: guard baseline encoding failed")
	}
	validated, err := policy.DecodeBaseline(data)
	if err != nil {
		return nil, err
	}
	interfaces := make([]string, 0)
	managed := make([]string, 0)
	for _, zone := range validated.Zones {
		interfaces = append(interfaces, zone.Interfaces...)
		if zone.Role == policy.Untrusted {
			managed = append(managed, zone.Interfaces...)
		}
	}
	slices.Sort(interfaces)
	slices.Sort(managed)
	return &guardLayout{interfaces: interfaces, managedInterfaces: managed}, nil
}

// program is private image-generation plumbing. No current executable or
// privileged process accepts this rule program as a runtime update.
func (layout *guardLayout) program(ctx context.Context) ([]byte, error) {
	if layout == nil || ctx == nil || len(layout.interfaces) == 0 {
		return nil, errors.New("firewall: missing guard layout or context")
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	lines := []string{"table inet " + ownedTable + " {"}
	lines = append(lines, permanentGuardSets()...)
	for _, name := range grantSets {
		addressType := "ipv6_addr"
		if ipv4Set(name) {
			addressType = "ipv4_addr"
		}
		lines = append(lines,
			guardSetDefinition(name, "ifname . ether_addr . "+addressType+" . "+addressType+" . inet_service"),
			guardSetDefinition(inboundSet(name), "ifname . "+addressType+" . "+addressType+" . inet_service"),
		)
	}
	lines = append(lines, "chain guard_forward { type filter hook forward priority -150; policy accept;",
		"meta mark set meta mark & "+guardMarkKeep)
	lines = append(lines, guardLookups("return")...)
	lines = append(lines,
		"ether saddr @"+cohortSet+" drop",
		"ip saddr @"+classified4Set+" drop", "ip daddr @"+classified4Set+" drop",
		"ip6 saddr @"+classified6Set+" drop", "ip6 daddr @"+classified6Set+" drop", "}",
		// An image-owned later chain must jump here only after all protected
		// checks, and before its ordinary application default deny. Recheck the
		// lease; a tag alone cannot authorize a later permit.
		"chain permit_flow {",
	)
	lines = append(lines, guardLookups("accept")...)
	lines = append(lines, "}", "}", "table netdev "+ownedTable+" {",
		fmt.Sprintf("set %s { type ether_addr; size %d; }", cohortSet, maximumCohortSize))
	for _, name := range grantSets {
		addressType := "ipv6_addr"
		if ipv4Set(name) {
			addressType = "ipv4_addr"
		}
		// The extracted mark has a 32-bit datatype. Its bounded numeric port
		// value is the same as the 16-bit forward/conntrack listener value.
		lines = append(lines, guardSetDefinition(egressSet(name),
			"ifname . ether_addr . "+addressType+" . "+addressType+" . mark"))
	}
	for index, name := range layout.interfaces {
		lines = append(lines, fmt.Sprintf(
			"chain guard_egress_%d { type filter hook egress device %q priority 0; policy accept;",
			index, name,
		))
		for _, set := range grantSets {
			_, incoming := guardTags(set)
			family, protocol := guardProtocol(set)
			lines = append(lines, fmt.Sprintf(
				"meta l4proto %s meta mark & 0xff000000 == %s "+
					"oifname . ether daddr . %s daddr . %s saddr . (meta mark & 0x0000ffff) @%s return",
				protocol, incoming, family, family, egressSet(set),
			))
		}
		// A projected IP permit must not transfer to an unclassified new MAC.
		// Unknown addresses on a managed MAC must not fall through either.
		lines = append(lines,
			"meta mark & 0xff000000 == "+fromReplyTag+" drop",
			"meta mark & 0xff000000 == "+toOriginalTag+" drop",
			"ether daddr @"+cohortSet+" drop", "}",
		)
	}
	lines = append(lines, "}")
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return []byte(strings.Join(lines, "\n") + "\n"), nil
}

func permanentGuardSets() []string {
	return []string{
		fmt.Sprintf("set %s { type ether_addr; size %d; }", cohortSet, maximumCohortSize),
		fmt.Sprintf("set %s { type ipv4_addr; size %d; }", classified4Set, maximumTupleCount),
		fmt.Sprintf("set %s { type ipv6_addr; size %d; }", classified6Set, maximumTupleCount),
	}
}

func guardSetDefinition(name, datatype string) string {
	return fmt.Sprintf("set %s { type %s; flags timeout; timeout 90s; size %d; }",
		name, datatype, maximumTupleCount)
}

func inboundSet(name string) string { return "inbound_" + name }
func egressSet(name string) string  { return "egress_" + name }

func guardProtocol(name string) (string, string) {
	family, protocol := "ip6", "tcp"
	if ipv4Set(name) {
		family = "ip"
	}
	if strings.HasSuffix(name, "_udp") {
		protocol = "udp"
	}
	return family, protocol
}

func guardTags(name string) (string, string) {
	if strings.HasPrefix(name, "lease_from") {
		return fromOriginalTag, fromReplyTag
	}
	return toReplyTag, toOriginalTag
}

func guardLookups(verdict string) []string {
	lines := make([]string, 0, 2*len(grantSets))
	for _, name := range grantSets {
		family, protocol := guardProtocol(name)
		outgoing, incoming := guardTags(name)
		sourceDirection, targetDirection := "reply", "original"
		if strings.HasPrefix(name, "lease_from") {
			sourceDirection, targetDirection = "original", "reply"
		}
		lines = append(lines,
			fmt.Sprintf("meta l4proto %s ct state { new, established } ct direction %s "+
				"iifname . ether saddr . %s saddr . %s daddr . ct original proto-dst @%s "+
				"meta mark set (meta mark & %s) | ct original proto-dst meta mark set meta mark | %s %s",
				protocol, sourceDirection, family, family, name, guardMarkKeep, outgoing, verdict),
			fmt.Sprintf("meta l4proto %s ct state { new, established } ct direction %s "+
				"oifname . %s daddr . %s saddr . ct original proto-dst @%s "+
				"meta mark set (meta mark & %s) | ct original proto-dst meta mark set meta mark | %s %s",
				protocol, targetDirection, family, family, inboundSet(name), guardMarkKeep, incoming, verdict),
		)
	}
	return lines
}
