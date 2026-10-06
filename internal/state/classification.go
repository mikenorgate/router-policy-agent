package state

import (
	"errors"
	"net/netip"
	"slices"

	"github.com/mikenorgate/router-policy-agent/internal/policy"
)

const maximumClassifiedAddresses = 16384

// Classification is deny-only historical identity, not current ownership or
// permission. Its addresses may remain after disconnect, expiry or IP reuse.
// Normal runtime operations may extend these sets, never retire their members.
type Classification struct {
	MACs []string
	IPv4 []string
	IPv6 []string
}

// EmptyClassification is the explicit empty startup/stop handoff. The backend
// must retain its existing classifiers even when this handoff has no additions.
func EmptyClassification() Classification {
	return Classification{MACs: []string{}, IPv4: []string{}, IPv6: []string{}}
}

// CloneClassification validates fixed kernel capacities and canonical ordering,
// then returns independently owned slices. It cannot authorize any address.
func CloneClassification(input Classification) (Classification, error) {
	validMACs := input.MACs != nil && len(input.MACs) <= maximumCohort
	validAddresses := input.IPv4 != nil && input.IPv6 != nil &&
		len(input.IPv4) <= maximumClassifiedAddresses && len(input.IPv6) <= maximumClassifiedAddresses
	if !validMACs || !validAddresses {
		return Classification{}, errors.New("state: invalid classification or capacity")
	}
	if len(input.MACs) == 0 && len(input.IPv4)+len(input.IPv6) != 0 {
		return Classification{}, errors.New("state: address classification requires a managed cohort")
	}
	for index, mac := range input.MACs {
		canonical, err := policy.CanonicalMAC(mac)
		if err != nil || canonical != mac || index > 0 && input.MACs[index-1] >= mac {
			return Classification{}, errors.New("state: cohort must be canonical, sorted and unique")
		}
	}
	for family, addresses := range [][]string{input.IPv4, input.IPv6} {
		bits := "/32"
		if family == 1 {
			bits = "/128"
		}
		for index, raw := range addresses {
			address, err := policy.ParseHost(raw + bits)
			wrongFamily := err == nil && address.Is4() != (family == 0)
			if err != nil || wrongFamily || index > 0 && addresses[index-1] >= raw {
				return Classification{}, errors.New("state: addresses must be canonical, sorted and unique")
			}
		}
	}
	return Classification{
		MACs: slices.Clone(input.MACs), IPv4: slices.Clone(input.IPv4), IPv6: slices.Clone(input.IPv6),
	}, nil
}

// Classifiers returns an owned, checked backend handoff without exposing the
// ledger, directory observation or any renewable authorization.
func Classifiers(document Document) (Classification, error) {
	owned, err := Clone(document)
	if err != nil {
		return Classification{}, err
	}
	return Classification{MACs: owned.CohortMACs, IPv4: owned.ClassifiedIPv4, IPv6: owned.ClassifiedIPv6}, nil
}

// RememberAddresses unions independently qualified device representations into
// durable deny-only history, including when policy grants none. The privileged
// caller must derive these addresses from its own compiler/binding source, not
// reader input. No ownership claim or permission is persisted by this operation.
func RememberAddresses(document Document, addresses []netip.Addr) (Document, error) {
	owned, err := Clone(document)
	if err != nil {
		return Document{}, err
	}
	if len(addresses) > 2*maximumClassifiedAddresses {
		return Document{}, errors.New("state: address observation exceeds capacity")
	}
	for _, address := range addresses {
		if address.Is4() {
			owned.ClassifiedIPv4 = append(owned.ClassifiedIPv4, address.String())
			continue
		}
		owned.ClassifiedIPv6 = append(owned.ClassifiedIPv6, address.String())
	}
	slices.Sort(owned.ClassifiedIPv4)
	slices.Sort(owned.ClassifiedIPv6)
	owned.ClassifiedIPv4 = slices.Compact(owned.ClassifiedIPv4)
	owned.ClassifiedIPv6 = slices.Compact(owned.ClassifiedIPv6)
	return Clone(owned)
}
