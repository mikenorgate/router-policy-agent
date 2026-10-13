package firewall

import (
	"cmp"
	"encoding/json"
	"errors"
	"net/netip"
	"slices"

	"github.com/mikenorgate/router-policy-agent/internal/policy"
	"github.com/mikenorgate/router-policy-agent/internal/strictjson"
)

// Only the peer and listener fields may contain intervals. The interface, MAC
// and bound device address remain exact in every logical authorization tuple.
func tupleHost(raw string, ipv4 bool) (netip.Addr, error) {
	address, err := netip.ParseAddr(raw)
	if err != nil || address.Is4() != ipv4 || address.String() != raw {
		return netip.Addr{}, errors.New("firewall: invalid tuple address family or encoding")
	}
	return policy.ParseHost(netip.PrefixFrom(address, address.BitLen()).String())
}

func tuplePeerScope(raw json.RawMessage, ipv4, internet bool) (netip.Addr, netip.Prefix, error) {
	var host string
	if err := json.Unmarshal(raw, &host); err == nil {
		if internet {
			return netip.Addr{}, netip.Prefix{}, errors.New("firewall: Internet tuple must use its fixed wildcard")
		}
		address, err := tupleHost(host, ipv4)
		return address, netip.Prefix{}, err
	}
	var value struct {
		Address string `json:"addr"`
		Bits    int    `json:"len"`
	}
	if err := decodeNested(raw, "prefix", &value, []string{"addr", "len"}); err != nil {
		return netip.Addr{}, netip.Prefix{}, err
	}
	address, err := netip.ParseAddr(value.Address)
	network := netip.PrefixFrom(address, value.Bits)
	if err != nil || address.Is4() != ipv4 || address.Is4In6() || address.Zone() != "" ||
		address.String() != value.Address || !network.IsValid() || network != network.Masked() ||
		value.Bits < 0 || value.Bits >= address.BitLen() || (value.Bits == 0) != internet {
		return netip.Addr{}, netip.Prefix{}, errors.New("firewall: canonical non-host peer prefix required")
	}
	return address, network, nil
}

func tuplePorts(raw json.RawMessage) (uint16, uint16, error) {
	var port uint16
	if err := json.Unmarshal(raw, &port); err == nil && port != 0 {
		return port, 0, nil
	}
	if err := strictjson.Object(raw, []string{"range"}, nil, maximumBatch); err != nil {
		return 0, 0, err
	}
	var value struct {
		Ports []uint16 `json:"range"`
	}
	if err := strictjson.Decode(raw, &value, maximumBatch); err != nil || len(value.Ports) != 2 ||
		value.Ports[0] == 0 || value.Ports[0] >= value.Ports[1] {
		return 0, 0, errors.New("firewall: bounded increasing listener range required")
	}
	return value.Ports[0], value.Ports[1], nil
}

func (key tupleKey) network() netip.Prefix {
	if key.peerNetwork.IsValid() {
		return key.peerNetwork
	}
	return netip.PrefixFrom(key.peer, key.peer.BitLen())
}

func (key tupleKey) lastPort() uint16 { return max(key.port, key.portEnd) }

func (key tupleKey) peerValue() any {
	if key.peerNetwork.IsValid() {
		return map[string]any{"prefix": map[string]any{"addr": key.peer.String(), "len": key.peerNetwork.Bits()}}
	}
	return key.peer.String()
}

func (key tupleKey) portValue() any {
	if key.portEnd > key.port {
		return map[string]any{"range": []uint16{key.port, key.portEnd}}
	}
	return key.port
}

type tupleIdentity struct {
	iface, mac string
	device     netip.Addr
}

type listenerSpan struct{ first, last uint16 }

// CIDRs are nested or disjoint. Indexing their bounded ancestor paths avoids
// pairwise rectangle comparisons (and never enumerates addresses or ports).
// This check is independent of the compiler's disjoint real-flow union.
func validateDisjointTuples(keys []tupleKey) error {
	groups := map[tupleIdentity]map[netip.Prefix][]listenerSpan{}
	for _, key := range keys {
		identity := tupleIdentity{iface: key.interfaceName, mac: key.mac, device: key.device}
		if groups[identity] == nil {
			groups[identity] = map[netip.Prefix][]listenerSpan{}
		}
		network := key.network()
		groups[identity][network] = append(groups[identity][network], listenerSpan{key.port, key.lastPort()})
	}
	for _, networks := range groups {
		for _, ports := range networks {
			slices.SortFunc(ports, func(a, b listenerSpan) int { return cmp.Compare(a.first, b.first) })
			for index := 1; index < len(ports); index++ {
				if ports[index].first <= ports[index-1].last {
					return errors.New("firewall: duplicate or overlapping leased tuple")
				}
			}
		}
		for network, ports := range networks {
			for bits := 0; bits < network.Bits(); bits++ {
				ancestors := networks[netip.PrefixFrom(network.Addr(), bits).Masked()]
				for _, port := range ports {
					index, _ := slices.BinarySearchFunc(ancestors, port.first,
						func(span listenerSpan, first uint16) int { return cmp.Compare(span.last, first) })
					if index < len(ancestors) && ancestors[index].first <= port.last {
						return errors.New("firewall: overlapping leased peer and listener intervals")
					}
				}
			}
		}
	}
	return nil
}
