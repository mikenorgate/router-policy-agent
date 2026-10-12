package policy

import (
	"cmp"
	"net/netip"
	"slices"
)

// Prefix subtraction operates on CIDRs, never on individual host addresses.
// Removing one IPv6 host from a /64 costs at most 64 fragments, not 2^64 hosts.
func subtractPrefix(source, denied netip.Prefix) []netip.Prefix {
	if !source.Overlaps(denied) {
		return []netip.Prefix{source}
	}
	if denied.Bits() <= source.Bits() {
		return nil
	}
	left, right := splitPrefix(source)
	return append(subtractPrefix(left, denied), subtractPrefix(right, denied)...)
}

func splitPrefix(prefix netip.Prefix) (netip.Prefix, netip.Prefix) {
	bits := prefix.Bits()
	address := prefix.Addr()
	if address.Is4() {
		bytes := address.As4()
		bytes[bits/8] |= 1 << (7 - bits%8)
		return netip.PrefixFrom(address, bits+1), netip.PrefixFrom(netip.AddrFrom4(bytes), bits+1)
	}
	bytes := address.As16()
	bytes[bits/8] |= 1 << (7 - bits%8)
	return netip.PrefixFrom(address, bits+1), netip.PrefixFrom(netip.AddrFrom16(bytes), bits+1)
}

func intersectPrefix(left, right netip.Prefix) (netip.Prefix, bool) {
	if !left.Overlaps(right) {
		return netip.Prefix{}, false
	}
	if left.Bits() > right.Bits() {
		return left, true
	}
	return right, true
}

func canonicalPrefixes(prefixes []netip.Prefix) []netip.Prefix {
	slices.SortFunc(prefixes, func(left, right netip.Prefix) int {
		return cmp.Or(left.Addr().Compare(right.Addr()), cmp.Compare(left.Bits(), right.Bits()))
	})
	result := make([]netip.Prefix, 0, len(prefixes))
	for _, prefix := range prefixes {
		if len(result) == 0 || !result[len(result)-1].Contains(prefix.Addr()) ||
			result[len(result)-1].Bits() > prefix.Bits() {
			result = append(result, prefix)
		}
	}
	return result
}
