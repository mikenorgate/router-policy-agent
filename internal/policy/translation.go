package policy

import (
	"errors"
	"net/netip"
	"slices"
)

// NAT64 declares an installed /96 translator and its eligible target class.
// Scope is global or private; unsupported/non-global targets never use the WKP.
type NAT64 struct {
	ID     string       `json:"id"`
	Prefix netip.Prefix `json:"prefix"`
	Scope  string       `json:"scope"`
}

// NAT46 declares an approved alias mapping. Reserved but unready maps grant nothing.
type NAT46 struct {
	ID     string     `json:"id"`
	Alias  netip.Addr `json:"alias"`
	Target netip.Addr `json:"target"`
	Ready  bool       `json:"ready"`
}

// Endpoint is the resolved real host and every valid available representation.
type Endpoint struct {
	Real     netip.Addr   `json:"real"`
	Variants []netip.Addr `json:"variants"`
}

var wellKnownPrefix = netip.MustParsePrefix("64:ff9b::/96")

func validateTranslators(b Baseline) error {
	if len(b.NAT64) > 4 || len(b.NAT46) > 4096 || len(b.NAT46Pools) > 32 {
		return errors.New("policy: translator catalog outside bounds")
	}
	seenPrefixes := map[netip.Prefix]bool{}
	seenIDs := map[string]bool{}
	for _, translator := range b.NAT64 {
		isPrefixValid := translator.Prefix.IsValid() && translator.Prefix.Addr().Is6() &&
			validAddress(translator.Prefix.Addr()) &&
			translator.Prefix.Bits() == 96 && translator.Prefix == translator.Prefix.Masked()
		isScopeValid := translator.Scope == "global" || translator.Scope == "private"
		if !identifier.MatchString(translator.ID) || seenIDs[translator.ID] ||
			!isPrefixValid || !isScopeValid || seenPrefixes[translator.Prefix] {
			return errors.New("policy: invalid or duplicate nat64 translator")
		}
		if translator.Prefix == wellKnownPrefix && translator.Scope != "global" {
			return errors.New("policy: well-known prefix cannot translate private targets")
		}
		seenIDs[translator.ID], seenPrefixes[translator.Prefix] = true, true
	}
	if len(b.NAT46Pools) != 0 {
		if err := validPrefixes(b.NAT46Pools); err != nil {
			return err
		}
	}
	for _, pool := range b.NAT46Pools {
		if !pool.Addr().Is4() {
			return errors.New("policy: nat46 alias pools must be ipv4")
		}
	}
	aliases := map[netip.Addr]bool{}
	for _, mapping := range b.NAT46 {
		isAddressValid := mapping.Alias.Is4() && mapping.Target.Is6() &&
			validAddress(mapping.Alias) && validAddress(mapping.Target)
		if !identifier.MatchString(mapping.ID) || seenIDs[mapping.ID] ||
			!isAddressValid || aliases[mapping.Alias] || !inPrefixes(mapping.Alias, b.NAT46Pools) {
			return errors.New("policy: invalid or duplicate nat46 mapping")
		}
		for _, translator := range b.NAT64 {
			if translator.Prefix.Contains(mapping.Target) {
				return errors.New("policy: chained translator target is unsupported")
			}
		}
		if wellKnownPrefix.Contains(mapping.Target) {
			return errors.New("policy: chained well-known target is unsupported")
		}
		seenIDs[mapping.ID], aliases[mapping.Alias] = true, true
	}
	return nil
}

// Resolve decodes recognized aliases before deriving native and NAT counterparts.
// Unknown reserved aliases and invalid private WKP encodings never fall through.
func Resolve(b Baseline, address netip.Addr) (Endpoint, error) {
	if err := validateTranslators(b); err != nil {
		return Endpoint{}, err
	}
	return resolveEndpoint(b, address)
}

func resolveEndpoint(b Baseline, address netip.Addr) (Endpoint, error) {
	if !validAddress(address) {
		return Endpoint{}, errors.New("policy: unsupported endpoint address")
	}
	realPeer, err := realAddress(b, address)
	if err != nil {
		return Endpoint{}, err
	}
	if !validAddress(realPeer) {
		return Endpoint{}, errors.New("policy: unsupported translated real peer")
	}
	variants := []netip.Addr{realPeer}
	if realPeer.Is6() {
		for _, mapping := range b.NAT46 {
			if mapping.Ready && mapping.Target == realPeer {
				variants = append(variants, mapping.Alias)
			}
		}
	}
	// Include installed NAT64 representations of native IPv4 peers and ready
	// NAT46 aliases. This is a bounded closure, not a new translation mapping.
	for _, variant := range slices.Clone(variants) {
		if !variant.Is4() {
			continue
		}
		for _, translator := range b.NAT64 {
			if eligible(translator, variant) {
				variants = append(variants, embed(translator.Prefix, variant))
			}
		}
	}
	slices.SortFunc(variants, func(left, right netip.Addr) int { return left.Compare(right) })
	return Endpoint{Real: realPeer, Variants: slices.Compact(variants)}, nil
}

func realAddress(b Baseline, address netip.Addr) (netip.Addr, error) {
	if address.Is4() {
		for _, mapping := range b.NAT46 {
			if mapping.Alias != address {
				continue
			}
			if !mapping.Ready {
				return netip.Addr{}, errors.New("policy: nat46 mapping is not ready")
			}
			return mapping.Target, nil
		}
		if inPrefixes(address, b.NAT46Pools) {
			return netip.Addr{}, errors.New("policy: unmapped reserved nat46 alias")
		}
		return address, nil
	}
	for _, translator := range b.NAT64 {
		if !translator.Prefix.Contains(address) {
			continue
		}
		decoded := decode(address)
		if !eligible(translator, decoded) {
			return netip.Addr{}, errors.New("policy: target is ineligible for nat64 prefix")
		}
		// A private NAT64 destination can itself be an approved NAT46 alias.
		// Resolve it to the real service without treating the alias as a peer.
		return realAddress(b, decoded)
	}
	if wellKnownPrefix.Contains(address) {
		return netip.Addr{}, errors.New("policy: well-known translator is not installed")
	}
	return address, nil
}

func eligible(translator NAT64, address netip.Addr) bool {
	if !address.Is4() || !validAddress(address) {
		return false
	}
	if translator.Scope == "private" {
		return address.IsPrivate()
	}
	return globalIPv4(address)
}

func globalIPv4(address netip.Addr) bool {
	if !address.Is4() || !validAddress(address) || address.IsPrivate() {
		return false
	}
	for _, prefix := range nonGlobalIPv4 {
		if prefix.Contains(address) {
			return false
		}
	}
	return true
}

var nonGlobalIPv4 = []netip.Prefix{
	netip.MustParsePrefix("100.64.0.0/10"),
	netip.MustParsePrefix("192.0.0.0/24"),
	netip.MustParsePrefix("192.88.99.0/24"),
}

func embed(prefix netip.Prefix, address netip.Addr) netip.Addr {
	result := prefix.Addr().As16()
	ipv4 := address.As4()
	copy(result[12:], ipv4[:])
	return netip.AddrFrom16(result)
}

func decode(address netip.Addr) netip.Addr {
	bytes := address.As16()
	return netip.AddrFrom4([4]byte{bytes[12], bytes[13], bytes[14], bytes[15]})
}

func inPrefixes(address netip.Addr, prefixes []netip.Prefix) bool {
	for _, prefix := range prefixes {
		if prefix.Contains(address) {
			return true
		}
	}
	return false
}

func roleFor(b Baseline, address netip.Addr) Role {
	for _, zone := range b.Zones {
		if inPrefixes(address, zone.Networks) {
			return zone.Role
		}
	}
	if address.IsPrivate() || address.Is4() && !globalIPv4(address) {
		return Unknown
	}
	return Internet
}
