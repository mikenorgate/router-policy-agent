package policy

import (
	"cmp"
	"context"
	"errors"
	"slices"
)

// Intermediate work is bounded separately from distinct installed tuple quota.
// Independent groups may contribute the same permission without consuming it twice.
const maximumIntermediateGrants = 16384 * 16

type internetPortEvent struct {
	port  uint32
	index int
	add   bool
}

func (compiler *Compiler) normalizeGrants(ctx context.Context, grants []Grant) ([]Grant, error) {
	internet := map[scopeUnionKey][]Grant{}
	other := make([]Grant, 0, len(grants))
	for _, grant := range grants {
		if !grant.Internet {
			other = append(other, grant)
			continue
		}
		key := scopeUnionKey{deviceID: grant.DeviceID, mac: grant.MAC, iface: grant.Interface, vlan: grant.VLAN,
			device: grant.Device.Real, direction: grant.Direction, protocol: grant.Protocol}
		internet[key] = append(internet[key], grant)
	}
	result, err := compiler.normalizeScopeUnion(ctx, other)
	if err != nil {
		return nil, err
	}
	for _, group := range internet {
		normalized, err := normalizeListenerUnion(ctx, group)
		if err != nil {
			return nil, err
		}
		result = append(result, normalized...)
		if len(result) > compiler.baseline.MaximumTuples {
			return nil, errors.New("policy: Internet union quota exceeded")
		}
	}
	result = mergeGrants(result)
	if len(result) > compiler.baseline.MaximumTuples || expandedTuples(result) > compiler.baseline.MaximumTuples {
		return nil, errors.New("policy: Internet expanded quota exceeded")
	}
	return result, ctx.Err()
}

// A sweep across listener boundaries preserves contributor union without
// enumerating ports or pairwise comparisons of all grant rectangles.
func normalizeListenerUnion(ctx context.Context, grants []Grant) ([]Grant, error) {
	events := make([]internetPortEvent, 0, 2*len(grants))
	for index, grant := range grants {
		events = append(events,
			internetPortEvent{port: uint32(grant.Port), index: index, add: true},
			internetPortEvent{port: uint32(grant.PortEnd) + 1, index: index},
		)
	}
	slices.SortFunc(events, func(left, right internetPortEvent) int { return cmp.Compare(left.port, right.port) })
	active := map[int]bool{}
	result := make([]Grant, 0, len(events))
	for index := 0; index < len(events); {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		first := events[index].port
		for index < len(events) && events[index].port == first {
			event := events[index]
			if event.add {
				active[event.index] = true
			} else {
				delete(active, event.index)
			}
			index++
		}
		if index == len(events) || len(active) == 0 {
			continue
		}
		last := events[index].port - 1
		if first == 0 || first > 65535 || last > 65535 || first > last {
			return nil, errors.New("policy: listener union outside port bounds")
		}
		grant := grants[0]
		grant.Port, grant.PortEnd = uint16(first), uint16(last)
		grant.Contributors = []Contributor{}
		for activeIndex := range active {
			grant.Contributors = append(grant.Contributors, grants[activeIndex].Contributors...)
		}
		result = append(result, grant)
	}
	return mergeGrants(result), ctx.Err()
}
