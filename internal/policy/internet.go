package policy

import (
	"context"
	"net/netip"
	"slices"
	"time"

	"github.com/mikenorgate/router-policy-agent/internal/binding"
)

// InternetGeometry is shared router-owned Internet matching geometry. A peer
// must match Allowed and not Excluded. Blocks additionally preserve conditional
// retained destination restrictions; they cannot create any permission.
type InternetGeometry struct {
	Allowed  []netip.Prefix
	Excluded []netip.Prefix
	Blocks   []NetworkBlock
}

// InternetGeometry returns independent copies of the immutable shared geometry.
// Internet grants identify devices and port intervals, never public CIDR lists.
func (compiler *Compiler) InternetGeometry() InternetGeometry {
	if compiler == nil {
		return InternetGeometry{}
	}
	geometry := compiler.internetGeometry
	geometry.Allowed = slices.Clone(geometry.Allowed)
	geometry.Excluded = slices.Clone(geometry.Excluded)
	geometry.Blocks = slices.Clone(geometry.Blocks)
	for index := range geometry.Blocks {
		geometry.Blocks[index].Networks = slices.Clone(geometry.Blocks[index].Networks)
		geometry.Blocks[index].Roles = slices.Clone(geometry.Blocks[index].Roles)
	}
	return geometry
}

func (compiler *Compiler) calculateInternetGeometry() InternetGeometry {
	geometry := InternetGeometry{
		Allowed: prefixesOf("0.0.0.0/0", "2000::/3"), Excluded: []netip.Prefix{}, Blocks: []NetworkBlock{},
	}
	translators := []netip.Prefix{}
	for _, translator := range compiler.baseline.NAT64 {
		if translator.Scope == "global" {
			translators = append(translators, translator.Prefix)
			geometry.Allowed = append(geometry.Allowed, translator.Prefix)
		}
	}
	geometry.Excluded = internetRepresentations(compiler.nativeExcluded, translators)
	for _, block := range compiler.baseline.RetainedBlocks {
		block.Networks = internetRepresentations(block.Networks, translators)
		block.Roles = slices.Clone(block.Roles)
		appliesToUntrusted := len(block.Roles) == 0 || slices.Contains(block.Roles, Untrusted)
		if block.SourceMAC == "" && appliesToUntrusted {
			geometry.Excluded = append(geometry.Excluded, block.Networks...)
		}
		geometry.Blocks = append(geometry.Blocks, block)
	}
	geometry.Allowed = canonicalPrefixes(geometry.Allowed)
	geometry.Excluded = canonicalPrefixes(geometry.Excluded)
	return geometry
}

// Native exclusion supernets must not accidentally hide an approved translator.
// Its real IPv4 destination, not the alias's IPv6 zone, determines permission.
func internetRepresentations(networks, translators []netip.Prefix) []netip.Prefix {
	result := []netip.Prefix{}
	for _, network := range networks {
		if network.Addr().Is4() {
			result = append(result, network)
			for _, translator := range translators {
				result = append(result, netip.PrefixFrom(embed(translator, network.Addr()), 96+network.Bits()))
			}
			continue
		}
		parts := []netip.Prefix{network}
		for _, translator := range translators {
			next := []netip.Prefix{}
			for _, part := range parts {
				next = append(next, subtractPrefix(part, translator)...)
			}
			parts = next
		}
		result = append(result, parts...)
	}
	return canonicalPrefixes(result)
}

func (compiler *Compiler) compileInternetRule(
	ctx context.Context,
	device Device,
	record binding.Record,
	groupID string,
	rule Rule,
	expires time.Time,
	input Input,
) ([]Grant, string) {
	if rule.Direction != FromDevice {
		return nil, "P09_unsolicited_wan"
	}
	grants := []Grant{}
	for _, address := range record.Addresses {
		if ctx.Err() != nil {
			return nil, "compilation_canceled"
		}
		endpoint, err := resolveEndpoint(compiler.baseline, address.IP)
		if err != nil || endpoint.Real != address.IP {
			return nil, "invalid_device_alias"
		}
		ranges := compiler.internetDevicePorts(device.MAC, address.IP, rule.Protocol, portRanges(rule))
		deadline := earliest(expires, input.Bindings.ObservedAt.Add(leaseDuration(compiler.baseline)),
			record.AssociatedAt.Add(leaseDuration(compiler.baseline)),
			address.ObservedAt.Add(leaseDuration(compiler.baseline)), address.ValidUntil)
		for _, ports := range ranges {
			grants = append(grants, Grant{
				DeviceID: device.ID, MAC: device.MAC, Interface: record.Interface, VLAN: record.VLAN,
				Direction: FromDevice, Device: endpoint, Internet: true,
				Protocol: rule.Protocol, Port: ports.First, PortEnd: ports.Last,
				Contributors: []Contributor{{GroupID: groupID, RuleID: rule.ID, ExpiresAt: deadline}},
			})
		}
	}
	if len(grants) == 0 {
		return nil, "scope_has_no_permitted_flows"
	}
	return grants, ""
}

func (compiler *Compiler) internetDevicePorts(
	mac string,
	device netip.Addr,
	protocol string,
	ranges []PortRange,
) []PortRange {
	if reservedZoneHost(compiler.baseline, device) {
		return nil
	}
	for _, blocks := range [][]NetworkBlock{compiler.baseline.ProtectedNetworks, compiler.baseline.RetainedBlocks} {
		for _, block := range blocks {
			matchesRole := len(block.Roles) == 0 || slices.Contains(block.Roles, Untrusted)
			matchesMAC := block.SourceMAC == "" || block.SourceMAC == mac
			if matchesRole && matchesMAC && inPrefixes(device, block.Networks) {
				return nil
			}
		}
	}
	ranges = subtractPortRanges(ranges, PortRange{First: 53, Last: 53})
	if protocol == "udp" {
		ranges = subtractPortRanges(ranges, PortRange{First: 123, Last: 123})
	}
	for _, block := range compiler.baseline.ProtectedEndpoints {
		matchesProtocol := block.Protocol == "any" || block.Protocol == protocol
		if block.DestinationOnly || !matchesProtocol || !inPrefixes(device, block.Networks) {
			continue
		}
		if len(block.Ports) == 0 {
			return nil
		}
		for _, port := range block.Ports {
			ranges = subtractPortRanges(ranges, PortRange{First: port, Last: port})
		}
	}
	return ranges
}

func subtractPortRanges(ranges []PortRange, denied PortRange) []PortRange {
	result := make([]PortRange, 0, len(ranges))
	for _, ports := range ranges {
		first, last := max(ports.First, denied.First), min(ports.Last, denied.Last)
		if first > last {
			result = append(result, ports)
			continue
		}
		if ports.First < first {
			result = append(result, PortRange{First: ports.First, Last: first - 1})
		}
		if last < ports.Last {
			result = append(result, PortRange{First: last + 1, Last: ports.Last})
		}
	}
	return result
}
