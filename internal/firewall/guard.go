package firewall

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
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
// supplies early and late guards, a local permit chain and final MAC checks.
// The image must independently qualify the protected floor, mark reservation,
// bootstrap paths, translator legs and the separate router-table bridge. This layout
// alone must not be activated as a complete router policy.
type guardLayout struct {
	interfaces        []string
	managedInterfaces []string
	controllers       []controllerLeg
	controllerAliases []netip.Addr
	translationPaths  []deviceTranslationPath
	bootstrapPaths    []policy.BootstrapPath
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
	for _, controller := range validated.ControllerInitiators {
		for _, path := range controller.NAT64Paths {
			interfaces = append(interfaces, path.Interface)
		}
	}
	slices.Sort(interfaces)
	interfaces = slices.Compact(interfaces)
	slices.Sort(managed)
	return &guardLayout{
		interfaces: interfaces, managedInterfaces: managed, controllers: controllerLegs(validated),
		controllerAliases: controllerAliasIdentities(validated),
		translationPaths:  deviceTranslationPaths(validated),
		bootstrapPaths:    validated.BootstrapPaths,
	}, nil
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
	lines = append(lines, layout.translatedSetDefinitions("inet")...)
	lines = append(lines, "chain guard_forward { type filter hook forward priority -150; policy accept;",
		"meta mark set meta mark & "+guardMarkKeep)
	bootstrap, _ := layout.bootstrapForward("return")
	lines = append(lines, bootstrap...)
	lines = append(lines, layout.controllerForwardRules("return", false)...)
	translated, _ := layout.translatedForward("return", false)
	lines = append(lines, translated...)
	lines = append(lines, guardLookups("return")...)
	lines = append(lines, layout.controllerIdentityDrops()...)
	lines = append(lines, guardClassificationDrops()...)
	lines = append(lines, "}",
		// The router's separate table provisionally accepts fixed tags only
		// after its protected checks. A cross-table jump is not possible. This
		// later base chain rechecks the actual lease inside our own table.
		"chain guard_confirm { type filter hook forward priority 150; policy accept;",
		"jump permit_flow",
	)
	for _, tag := range []string{fromOriginalTag, fromReplyTag, toOriginalTag, toReplyTag} {
		// Keep the provisional tag until lookup succeeds. If another hook
		// changed the tuple to an otherwise unclassified endpoint, a stale
		// tag must still deny rather than fall through the accept policy.
		lines = append(lines, "meta mark & 0xff000000 == "+tag+" drop")
	}
	lines = append(lines, layout.controllerTagDrops()...)
	lines = append(lines, bootstrapTagDrop())
	translatedDrops, _ := layout.translatedTagDrops()
	lines = append(lines, translatedDrops...)
	lines = append(lines, layout.controllerIdentityDrops()...)
	lines = append(lines, guardClassificationDrops()...)
	lines = append(lines, "}", "chain permit_flow {")
	bootstrap, _ = layout.bootstrapForward("accept")
	lines = append(lines, bootstrap...)
	lines = append(lines, layout.controllerForwardRules("accept", true)...)
	translated, _ = layout.translatedForward("accept", true)
	lines = append(lines, translated...)
	lines = append(lines, guardLookups("accept")...)
	lines = append(lines, "}")
	lines = append(lines, guardStampProgram()...)
	lines = append(lines, "}", "table netdev "+ownedTable+" {",
		fmt.Sprintf("set %s { type ether_addr; size %d; }", cohortSet, maximumCohortSize))
	for _, name := range grantSets {
		addressType := "ipv6_addr"
		if ipv4Set(name) {
			addressType = "ipv4_addr"
		}
		// Read the listener from the direction-specific packet header. A masked
		// host-endian mark is not a safe interval concatenation on nftables 1.1.3.
		lines = append(lines, guardSetDefinition(egressSet(name),
			"ifname . ether_addr . "+addressType+" . "+addressType+" . inet_service"))
	}
	lines = append(lines, layout.translatedSetDefinitions("netdev")...)
	for index, name := range layout.interfaces {
		lines = append(lines, fmt.Sprintf(
			"chain guard_egress_%d { type filter hook egress device %q priority 0; policy accept;",
			index, name,
		))
		bootstrap, _ := layout.bootstrapEgress(name)
		lines = append(lines, bootstrap...)
		lines = append(lines, layout.controllerEgressRules(name)...)
		translated, _ = layout.translatedEgress(name)
		lines = append(lines, translated...)
		for _, set := range grantSets {
			_, incoming := guardTags(set)
			family, protocol := guardProtocol(set)
			lines = append(lines, fmt.Sprintf(
				"meta l4proto %s meta mark & 0xff000000 == %s "+
					"oifname . ether daddr . %s daddr . %s saddr . %s %s @%s return",
				protocol, incoming, family, family, protocol, guardEgressListener(set), egressSet(set),
			))
		}
		// A projected IP permit must not transfer to an unclassified new MAC.
		// Unknown addresses on a managed MAC must not fall through either.
		lines = append(lines,
			"meta mark & 0xff000000 == "+fromReplyTag+" drop",
			"meta mark & 0xff000000 == "+toOriginalTag+" drop",
			"ether daddr @"+cohortSet+" drop",
		)
		// Controller tags cannot fall through on the wrong physical egress.
		lines = append(lines, layout.controllerTagDrops()...)
		lines = append(lines, bootstrapTagDrop())
		lines = append(lines, translatedDrops...)
		lines = append(lines, "}")
	}
	lines = append(lines, "}")
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return []byte(strings.Join(lines, "\n") + "\n"), nil
}

func guardClassificationDrops() []string {
	return []string{
		"ether saddr @" + cohortSet + " drop",
		"ip saddr @" + classified4Set + " drop", "ip daddr @" + classified4Set + " drop",
		"ip6 saddr @" + classified6Set + " drop", "ip6 daddr @" + classified6Set + " drop",
	}
}

// guardBridgeRules is image-generation plumbing for the router-owned table,
// not a runtime operation. Its owner must place these provisional accepts after
// protected checks and before ordinary default deny, with guard_confirm active
// afterward. Neither these rules alone nor the early tag authorizes a packet.
func guardBridgeRules() []string {
	lines := make([]string, 0, 4)
	for _, tag := range []string{fromOriginalTag, fromReplyTag, toOriginalTag, toReplyTag} {
		lines = append(lines, "meta mark & 0xff000000 == "+tag+" accept")
	}
	return lines
}

func permanentGuardSets() []string {
	return []string{
		fmt.Sprintf("set %s { type ether_addr; size %d; }", cohortSet, maximumCohortSize),
		fmt.Sprintf("set %s { type ipv4_addr; size %d; }", classified4Set, maximumTupleCount),
		fmt.Sprintf("set %s { type ipv6_addr; size %d; }", classified6Set, maximumTupleCount),
	}
}

func guardSetDefinition(name, datatype string) string {
	return fmt.Sprintf("set %s { type %s; flags interval,timeout; timeout 90s; size %d; }",
		name, datatype, maximumTupleCount)
}

func inboundSet(name string) string { return "inbound_" + name }
func egressSet(name string) string  { return "egress_" + name }

func guardEgressListener(name string) string {
	if strings.HasPrefix(name, "lease_from") {
		return "sport"
	}
	return "dport"
}

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
				"goto %s",
				protocol, sourceDirection, family, family, name, guardStampChain(outgoing, verdict)),
			fmt.Sprintf("meta l4proto %s ct state { new, established } ct direction %s "+
				"oifname . %s daddr . %s saddr . ct original proto-dst @%s "+
				"goto %s",
				protocol, targetDirection, family, family, inboundSet(name), guardStampChain(incoming, verdict)),
		)
	}
	return lines
}
