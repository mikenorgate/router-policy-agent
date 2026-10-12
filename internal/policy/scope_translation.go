package policy

import (
	"encoding/binary"
	"errors"
	"net/netip"
	"slices"
)

// The Internet selector is deliberately narrower than "has a default route".
// Configured internal GUAs, translator aliases, private and special-use space
// are excluded before any representation is generated.
func (compiler *Compiler) internetNetworks() []netip.Prefix {
	return compiler.internet
}

func (compiler *Compiler) calculateInternetNetworks() ([]netip.Prefix, error) {
	networks := append(slices.Clone(compiler.global4), netip.MustParsePrefix("2000::/3"))
	excluded := compiler.nonNativeNetworks()
	excluded = append(excluded, privateIPv4...)
	excluded = append(excluded, nonGlobalIPv4...)
	excluded = append(excluded, prefixesOf("2001::/23", "2002::/16")...)
	for _, zone := range compiler.baseline.Zones {
		excluded = append(excluded, zone.Networks...)
	}
	for _, block := range compiler.baseline.ProtectedNetworks {
		excluded = append(excluded, block.Networks...)
	}
	for _, block := range compiler.baseline.ProtectedEndpoints {
		excluded = append(excluded, block.Networks...)
	}
	for _, prefix := range excluded {
		next := []netip.Prefix{}
		for _, network := range networks {
			next = append(next, subtractPrefix(network, prefix)...)
			if len(next) > maximumScopeFragments {
				return nil, errors.New("policy: internet geometry fragmentation quota exceeded")
			}
		}
		networks = next
	}
	return canonicalPrefixes(networks), nil
}

func (compiler *Compiler) publicIPv4Networks() []netip.Prefix {
	networks := prefixesOf("0.0.0.0/0")
	excluded := append(slices.Clone(privateIPv4), nonGlobalIPv4...)
	excluded = append(excluded, compiler.nonNativeNetworks()...)
	for _, prefix := range excluded {
		next := []netip.Prefix{}
		for _, network := range networks {
			next = append(next, subtractPrefix(network, prefix)...)
		}
		networks = next
	}
	return canonicalPrefixes(networks)
}

var privateIPv4 = prefixesOf("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16")

func prefixesOf(raw ...string) []netip.Prefix {
	result := make([]netip.Prefix, 0, len(raw))
	for _, value := range raw {
		result = append(result, netip.MustParsePrefix(value))
	}
	return result
}

func (compiler *Compiler) translationNetworks() []netip.Prefix {
	result := slices.Clone(compiler.baseline.NAT46Pools)
	result = append(result, wellKnownPrefix)
	for _, translator := range compiler.baseline.NAT64 {
		result = append(result, translator.Prefix)
	}
	return result
}

func (compiler *Compiler) nonNativeNetworks() []netip.Prefix {
	result := slices.Clone(nonPeerPrefixes)
	result = append(result, prefixesOf("127.0.0.0/8", "169.254.0.0/16", "224.0.0.0/4",
		"::/96", "::ffff:0:0/96", "fe80::/10", "ff00::/8")...)
	return append(result, compiler.translationNetworks()...)
}

func (compiler *Compiler) reservedZoneHosts() []netip.Prefix {
	result := []netip.Prefix{}
	for _, zone := range compiler.baseline.Zones {
		for _, prefix := range zone.Networks {
			if !prefix.Addr().Is4() || prefix.Bits() >= 31 {
				continue
			}
			result = append(result, netip.PrefixFrom(prefix.Addr(), 32))
			bytes := prefix.Addr().As4()
			value := binary.BigEndian.Uint32(bytes[:]) | (^uint32(0) >> prefix.Bits())
			binary.BigEndian.PutUint32(bytes[:], value)
			result = append(result, netip.PrefixFrom(netip.AddrFrom4(bytes), 32))
		}
	}
	return result
}

func (compiler *Compiler) resolveScope(network netip.Prefix) PeerScope {
	variants := []netip.Prefix{network}
	if network.Addr().Is4() {
		for _, translator := range compiler.baseline.NAT64 {
			eligibleNetworks := privateIPv4
			if translator.Scope == "global" {
				eligibleNetworks = compiler.global4
			}
			for _, eligibleNetwork := range eligibleNetworks {
				if intersection, ok := intersectPrefix(network, eligibleNetwork); ok {
					variants = append(variants, netip.PrefixFrom(embed(translator.Prefix, intersection.Addr()), 96+intersection.Bits()))
				}
			}
		}
	} else {
		for _, mapping := range compiler.baseline.NAT46 {
			if !mapping.Ready || !network.Contains(mapping.Target) {
				continue
			}
			endpoint, err := resolveEndpoint(compiler.baseline, mapping.Target)
			if err != nil {
				continue
			}
			for _, variant := range endpoint.Variants {
				if variant != mapping.Target {
					variants = append(variants, netip.PrefixFrom(variant, variant.BitLen()))
				}
			}
		}
	}
	return PeerScope{Real: network, Variants: canonicalPrefixes(variants)}
}
