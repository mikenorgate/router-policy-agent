package policy

import (
	"cmp"
	"encoding/json"
	"errors"
	"net/netip"
	"slices"

	"github.com/mikenorgate/router-policy-agent/internal/strictjson"
)

func validateScopePeer(peer Peer, raw json.RawMessage) error {
	object := map[string]json.RawMessage{}
	if err := strictjson.Decode(raw, &object, AttributeLimit); err != nil {
		return err
	}
	if len(object) != 1 {
		return errors.New("policy: exactly one peer selector required")
	}
	if err := strictjson.Object(raw, nil, []string{"addresses", "zones", "internet"}, AttributeLimit); err != nil {
		return err
	}
	switch {
	case len(peer.Addresses) != 0:
		if len(peer.Addresses) > 8 {
			return errors.New("policy: peer count outside bounds")
		}
		seen := map[netip.Prefix]bool{}
		for _, value := range peer.Addresses {
			prefix, err := ParseNetwork(value)
			if err != nil || seen[prefix] {
				return errors.New("policy: invalid or duplicate peer network")
			}
			seen[prefix] = true
		}
	case len(peer.Zones) != 0:
		if len(peer.Zones) > 6 {
			return errors.New("policy: zone count outside bounds")
		}
		seen := map[Role]bool{}
		for _, role := range peer.Zones {
			if !validRole(role) || seen[role] {
				return errors.New("policy: invalid or duplicate peer zone")
			}
			seen[role] = true
		}
	case peer.Internet:
	default:
		return errors.New("policy: empty peer selector")
	}
	return nil
}

func validatePortSelection(rule Rule, object map[string]json.RawMessage) error {
	count := len(rule.DestinationPorts) + len(rule.DestinationPortRanges)
	if rule.AllDestinationPorts {
		if count != 0 || object["destination_ports"] != nil || object["destination_port_ranges"] != nil {
			return errors.New("policy: all ports cannot be combined with a port list")
		}
		return nil
	}
	if object["all_destination_ports"] != nil || count == 0 || count > 16 {
		return errors.New("policy: port selection outside bounds")
	}
	for _, key := range []string{"destination_ports", "destination_port_ranges"} {
		if value, exists := object[key]; exists {
			var values []json.RawMessage
			if err := json.Unmarshal(value, &values); err != nil || len(values) == 0 {
				return errors.New("policy: empty or invalid port list")
			}
			if key == "destination_port_ranges" {
				for _, raw := range values {
					if err := strictjson.Object(raw, []string{"first", "last"}, nil, AttributeLimit); err != nil {
						return err
					}
				}
			}
		}
	}
	ranges := portRanges(rule)
	for index, ports := range ranges {
		if ports.First == 0 || ports.First > ports.Last {
			return errors.New("policy: invalid port interval")
		}
		if index > 0 && ranges[index-1].Last >= ports.First {
			return errors.New("policy: overlapping or duplicate port interval")
		}
	}
	return nil
}

func portRanges(rule Rule) []PortRange {
	if rule.AllDestinationPorts {
		return []PortRange{{First: 1, Last: 65535}}
	}
	ranges := slices.Clone(rule.DestinationPortRanges)
	for _, port := range rule.DestinationPorts {
		ranges = append(ranges, PortRange{First: port, Last: port})
	}
	slices.SortFunc(ranges, func(left, right PortRange) int {
		return cmp.Or(cmp.Compare(left.First, right.First), cmp.Compare(left.Last, right.Last))
	})
	return ranges
}

// ParseNetwork accepts a canonical, masked IPv4/IPv6 peer CIDR. /0 is not a
// synonym for Internet; Internet is a separately floor-constrained selector.
func ParseNetwork(raw string) (netip.Prefix, error) {
	prefix, err := netip.ParsePrefix(raw)
	if err != nil || prefix.Bits() == 0 || prefix != prefix.Masked() || prefix.String() != raw ||
		prefix.Addr().Is4In6() || prefix.Addr().Zone() != "" {
		return netip.Prefix{}, errors.New("policy: invalid or noncanonical peer network")
	}
	if prefix.IsSingleIP() && !validAddress(prefix.Addr()) {
		return netip.Prefix{}, errors.New("policy: unsupported peer host")
	}
	return prefix, nil
}
