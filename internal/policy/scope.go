package policy

import (
	"context"
	"errors"
	"net/netip"
	"slices"
	"time"

	"github.com/mikenorgate/router-policy-agent/internal/binding"
)

const maximumScopeFragments = 4096

// PeerScope is a real peer network and its installed NAT representations.
// Variants cannot create routes or translations, or change the real peer's role.
type PeerScope struct {
	Real     netip.Prefix   `json:"real"`
	Variants []netip.Prefix `json:"variants"`
}

type scopeRegion struct {
	network netip.Prefix
	ports   PortRange
}

func (compiler *Compiler) compileScopeRule(ctx context.Context, device Device, record binding.Record,
	groupID string, rule Rule, expires time.Time, input Input, edits *ledgerEdits,
) ([]Grant, string) {
	selected, code := compiler.selectScopePeers(rule, groupID, edits)
	if code != "" {
		return nil, code
	}
	grants := []Grant{}
	for _, address := range record.Addresses {
		endpoint, err := resolveEndpoint(compiler.baseline, address.IP)
		if err != nil || endpoint.Real != address.IP {
			return nil, "invalid_device_alias"
		}
		deadline := earliest(expires, input.Bindings.ObservedAt.Add(leaseDuration(compiler.baseline)),
			record.AssociatedAt.Add(leaseDuration(compiler.baseline)),
			address.ObservedAt.Add(leaseDuration(compiler.baseline)), address.ValidUntil)
		for _, network := range selected {
			for _, ports := range portRanges(rule) {
				regions, err := compiler.clipScope(ctx, network, ports, device.MAC, address.IP, rule)
				if err != nil {
					return nil, "device_quota_exceeded"
				}
				for _, region := range regions {
					scope := compiler.resolveScope(region.network)
					grants = append(grants, Grant{
						DeviceID: device.ID, MAC: device.MAC, Interface: record.Interface, VLAN: record.VLAN,
						Direction: rule.Direction, Device: endpoint, PeerScope: &scope,
						Protocol: rule.Protocol, Port: region.ports.First, PortEnd: region.ports.Last,
						Contributors: []Contributor{{GroupID: groupID, RuleID: rule.ID, ExpiresAt: deadline}},
					})
					if len(grants) > compiler.baseline.MaximumTuples || expandedTuples(grants) > compiler.baseline.MaximumTuples {
						return nil, "device_quota_exceeded"
					}
				}
			}
		}
	}
	if len(grants) == 0 {
		return nil, "scope_has_no_permitted_flows"
	}
	return grants, ""
}

func (compiler *Compiler) selectScopePeers(rule Rule, groupID string, edits *ledgerEdits) ([]netip.Prefix, string) {
	if rule.Peer.Internet {
		if rule.Direction != FromDevice {
			return nil, "P09_unsolicited_wan"
		}
		return compiler.internetNetworks(), ""
	}
	if len(rule.Peer.Zones) != 0 {
		result := []netip.Prefix{}
		for _, role := range rule.Peer.Zones {
			if role != Trusted && role != Infrastructure {
				return nil, "P07_isolated_or_router_owned_zone"
			}
			for _, zone := range compiler.baseline.Zones {
				if zone.Role == role {
					result = append(result, zone.Networks...)
				}
			}
		}
		return canonicalPrefixes(result), ""
	}
	result := []netip.Prefix{}
	for _, raw := range rule.Peer.Addresses {
		prefix, err := ParseNetwork(raw)
		if err != nil {
			return nil, "malformed_peer"
		}
		if prefix.IsSingleIP() {
			endpoint, err := resolveEndpoint(compiler.baseline, prefix.Addr())
			if err != nil || !edits.anchorPeer(groupID, rule.ID, raw, prefix.Addr(), endpoint.Real) {
				return nil, "unready_or_changed_alias"
			}
			prefix = netip.PrefixFrom(endpoint.Real, endpoint.Real.BitLen())
		} else {
			// A translator network is not an ordinary target CIDR. Exact aliases
			// can be decoded and anchored; broad alias claims cannot be anchored.
			for _, reserved := range compiler.translationNetworks() {
				if reserved.Contains(prefix.Addr()) && reserved.Bits() <= prefix.Bits() {
					return nil, "scope_alias_network_unsupported"
				}
			}
		}
		result = append(result, prefix)
	}
	return canonicalPrefixes(result), ""
}

// clipScope computes permitted flow rectangles. Whole-prefix rules are cut
// around protected hosts/ports, not authorized by checking a representative IP.
func (compiler *Compiler) clipScope(ctx context.Context, network netip.Prefix, ports PortRange,
	mac string, device netip.Addr, rule Rule,
) ([]scopeRegion, error) {
	allowed := []netip.Prefix{}
	for _, zone := range compiler.baseline.Zones {
		if zone.Role == Trusted || zone.Role == Infrastructure {
			allowed = append(allowed, zone.Networks...)
		}
	}
	if rule.Direction == FromDevice {
		allowed = append(allowed, compiler.internetNetworks()...)
	}
	allowed = canonicalPrefixes(allowed)
	regions := []scopeRegion{}
	for _, permit := range allowed {
		if intersect, ok := intersectPrefix(network, permit); ok {
			regions = append(regions, scopeRegion{network: intersect, ports: ports})
		}
	}
	deny := func(prefix netip.Prefix, deniedPorts PortRange) error {
		var err error
		regions, err = subtractRegions(ctx, regions, prefix, deniedPorts)
		return err
	}
	all := PortRange{First: 1, Last: 65535}
	for _, prefix := range compiler.nonNativeNetworks() {
		if err := deny(prefix, all); err != nil {
			return nil, err
		}
	}
	for _, reserved := range compiler.reservedZoneHosts() {
		if err := deny(reserved, all); err != nil {
			return nil, err
		}
	}
	for _, port := range []uint16{53, 123} {
		if port == 123 && rule.Protocol != "udp" {
			continue
		}
		var err error
		regions, err = denyWholeRegionPorts(ctx, regions, PortRange{First: port, Last: port})
		if err != nil {
			return nil, err
		}
	}
	for _, blocks := range [][]NetworkBlock{compiler.baseline.ProtectedNetworks, compiler.baseline.RetainedBlocks} {
		for _, block := range blocks {
			if len(block.Roles) != 0 && !slices.Contains(block.Roles, Untrusted) ||
				block.SourceMAC != "" && block.SourceMAC != mac {
				continue
			}
			if block.InternetOnly {
				// Regions are already separated at zone/Internet boundaries.
				next := []scopeRegion{}
				for _, region := range regions {
					if roleFor(compiler.baseline, region.network.Addr()) != Internet {
						next = append(next, region)
						continue
					}
					part, err := denyBlockNetworks(ctx, []scopeRegion{region}, block.Networks, device, all)
					if err != nil {
						return nil, err
					}
					next = append(next, part...)
					if len(next) > maximumScopeFragments {
						return nil, errors.New("policy: scope fragmentation quota exceeded")
					}
				}
				regions = next
				continue
			}
			var err error
			regions, err = denyBlockNetworks(ctx, regions, block.Networks, device, all)
			if err != nil {
				return nil, err
			}
		}
	}
	for _, block := range compiler.baseline.ProtectedEndpoints {
		if block.Protocol != "any" && block.Protocol != rule.Protocol {
			continue
		}
		blockedPorts := []PortRange{all}
		if len(block.Ports) != 0 {
			blockedPorts = nil
			for _, port := range block.Ports {
				blockedPorts = append(blockedPorts, PortRange{First: port, Last: port})
			}
		}
		for _, blocked := range blockedPorts {
			var err error
			if inPrefixes(device, block.Networks) && (!block.DestinationOnly || rule.Direction == ToDevice) {
				regions, err = denyWholeRegionPorts(ctx, regions, blocked)
			} else if !block.DestinationOnly || rule.Direction == FromDevice {
				for _, prefix := range block.Networks {
					if err = deny(prefix, blocked); err != nil {
						break
					}
				}
			}
			if err != nil {
				return nil, err
			}
		}
	}
	return regions, ctx.Err()
}

func denyBlockNetworks(ctx context.Context, regions []scopeRegion, networks []netip.Prefix,
	device netip.Addr, ports PortRange,
) ([]scopeRegion, error) {
	if inPrefixes(device, networks) {
		return denyWholeRegionPorts(ctx, regions, ports)
	}
	var err error
	for _, network := range networks {
		regions, err = subtractRegions(ctx, regions, network, ports)
		if err != nil {
			return nil, err
		}
	}
	return regions, nil
}

func denyWholeRegionPorts(ctx context.Context, regions []scopeRegion, ports PortRange) ([]scopeRegion, error) {
	result := []scopeRegion{}
	for _, region := range regions {
		part, err := subtractRegions(ctx, []scopeRegion{region}, region.network, ports)
		if err != nil {
			return nil, err
		}
		result = append(result, part...)
		if len(result) > maximumScopeFragments {
			return nil, errors.New("policy: scope fragmentation quota exceeded")
		}
	}
	return result, nil
}

func subtractRegions(ctx context.Context, regions []scopeRegion, network netip.Prefix, ports PortRange) ([]scopeRegion, error) {
	result := []scopeRegion{}
	for _, region := range regions {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		first, last := max(region.ports.First, ports.First), min(region.ports.Last, ports.Last)
		if !region.network.Overlaps(network) || first > last {
			result = append(result, region)
			continue
		}
		if region.ports.First < first {
			result = append(result, scopeRegion{network: region.network, ports: PortRange{First: region.ports.First, Last: first - 1}})
		}
		if last < region.ports.Last {
			result = append(result, scopeRegion{network: region.network, ports: PortRange{First: last + 1, Last: region.ports.Last}})
		}
		for _, remaining := range subtractPrefix(region.network, network) {
			result = append(result, scopeRegion{network: remaining, ports: PortRange{First: first, Last: last}})
		}
		if len(result) > maximumScopeFragments {
			return nil, errors.New("policy: scope fragmentation quota exceeded")
		}
	}
	return result, nil
}
