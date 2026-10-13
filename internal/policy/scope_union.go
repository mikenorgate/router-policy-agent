package policy

import (
	"cmp"
	"context"
	"errors"
	"net/netip"
	"slices"
)

type scopeUnionKey struct {
	deviceID  string
	mac       string
	iface     string
	vlan      uint16
	device    netip.Addr
	direction Direction
	protocol  string
}

// normalizeScopeUnion makes the real flow rectangles disjoint, retaining every
// independent contributor at intersections. Different leases must not produce
// overlapping nftables intervals or let a short-lived rule renew another rule.
// Legacy-only devices retain their unchanged exact-host representation.
func (compiler *Compiler) normalizeScopeUnion(ctx context.Context, grants []Grant) ([]Grant, error) {
	hasScope := false
	for _, grant := range grants {
		hasScope = hasScope || grant.PeerScope != nil
	}
	if !hasScope {
		return mergeGrants(grants), nil
	}
	groups := map[scopeUnionKey][]Grant{}
	for _, grant := range grants {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		if grant.PeerScope == nil {
			network := netip.PrefixFrom(grant.Peer.Real, grant.Peer.Real.BitLen())
			scope := compiler.resolveScope(network)
			grant.Peer, grant.PeerScope, grant.PortEnd = Endpoint{}, &scope, grant.Port
		}
		key := scopeUnionKey{deviceID: grant.DeviceID, mac: grant.MAC, iface: grant.Interface, vlan: grant.VLAN,
			device: grant.Device.Real, direction: grant.Direction, protocol: grant.Protocol}
		groups[key] = append(groups[key], grant)
	}
	result := make([]Grant, 0, len(grants))
	for _, group := range groups {
		combined, err := compiler.normalizeScopeGroup(ctx, group)
		if err != nil {
			return nil, err
		}
		result = append(result, combined...)
		if len(result) > compiler.baseline.MaximumTuples {
			return nil, errors.New("policy: scope union fragmentation quota exceeded")
		}
	}
	result = mergeGrants(result)
	if expandedTuples(result) > compiler.baseline.MaximumTuples {
		return nil, errors.New("policy: scope union expanded quota exceeded")
	}
	return result, ctx.Err()
}

// Sorted CIDRs form disjoint connected components: inside each component the
// first (widest) prefix contains every other prefix. Disjoint components need
// no pairwise comparisons, while overlapping geometry keeps the checked union.
func (compiler *Compiler) normalizeScopeGroup(ctx context.Context, grants []Grant) ([]Grant, error) {
	slices.SortFunc(grants, func(left, right Grant) int {
		return cmp.Or(left.PeerScope.Real.Addr().Compare(right.PeerScope.Real.Addr()),
			cmp.Compare(left.PeerScope.Real.Bits(), right.PeerScope.Real.Bits()))
	})
	result := make([]Grant, 0, len(grants))
	for first := 0; first < len(grants); {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		last := first + 1
		anchor := grants[first].PeerScope.Real
		samePrefix := true
		for last < len(grants) && anchor.Overlaps(grants[last].PeerScope.Real) {
			samePrefix = samePrefix && grants[last].PeerScope.Real == anchor
			last++
		}
		component := grants[first:last]
		combined := component[:1]
		if len(component) > 1 && samePrefix {
			var err error
			combined, err = normalizeListenerUnion(ctx, component)
			if err != nil {
				return nil, err
			}
		} else {
			for _, grant := range component[1:] {
				var err error
				combined, err = compiler.addScopeUnion(ctx, combined, grant)
				if err != nil {
					return nil, err
				}
			}
		}
		result = append(result, combined...)
		if len(result) > compiler.baseline.MaximumTuples {
			return nil, errors.New("policy: scope union fragmentation quota exceeded")
		}
		first = last
	}
	return result, ctx.Err()
}

func (compiler *Compiler) addScopeUnion(ctx context.Context, previous []Grant, added Grant) ([]Grant, error) {
	remaining := []scopeRegion{grantRegion(added)}
	result := []Grant{}
	for _, existing := range previous {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		intersection, ok := intersectPrefix(existing.PeerScope.Real, added.PeerScope.Real)
		first, last := max(existing.Port, added.Port), min(existing.PortEnd, added.PortEnd)
		if !ok || first > last {
			result = append(result, existing)
			continue
		}
		parts, err := subtractRegions(ctx, []scopeRegion{grantRegion(existing)}, added.PeerScope.Real,
			PortRange{First: added.Port, Last: added.PortEnd})
		if err != nil {
			return nil, err
		}
		for _, part := range parts {
			result = append(result, compiler.regionGrant(existing, part))
		}
		overlap := compiler.regionGrant(existing, scopeRegion{network: intersection, ports: PortRange{First: first, Last: last}})
		overlap.Contributors = append(overlap.Contributors, added.Contributors...)
		result = append(result, overlap)
		remaining, err = subtractRegions(ctx, remaining, existing.PeerScope.Real,
			PortRange{First: existing.Port, Last: existing.PortEnd})
		if err != nil {
			return nil, err
		}
		if len(result) > compiler.baseline.MaximumTuples {
			return nil, errors.New("policy: scope union fragmentation quota exceeded")
		}
	}
	for _, part := range remaining {
		result = append(result, compiler.regionGrant(added, part))
	}
	if len(result) > compiler.baseline.MaximumTuples {
		return nil, errors.New("policy: scope union fragmentation quota exceeded")
	}
	return result, nil
}

func grantRegion(grant Grant) scopeRegion {
	return scopeRegion{network: grant.PeerScope.Real, ports: PortRange{First: grant.Port, Last: grant.PortEnd}}
}

func (compiler *Compiler) regionGrant(source Grant, region scopeRegion) Grant {
	scope := compiler.resolveScope(region.network)
	source.PeerScope = &scope
	source.Port, source.PortEnd = region.ports.First, region.ports.Last
	// Avoid sharing append capacity with another rectangle's provenance.
	source.Contributors = append([]Contributor(nil), source.Contributors...)
	return source
}
