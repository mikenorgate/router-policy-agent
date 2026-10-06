package policy

import (
	"net/netip"
	"slices"
)

type floorFlow struct {
	mac       string
	placement Role
	rule      Rule
	device    netip.Addr
	peer      netip.Addr
	port      uint16
}

func (compiler *Compiler) floor(flow floorFlow) string {
	mac, placement, rule, peer, port := flow.mac, flow.placement, flow.rule, flow.peer, flow.port
	peerRole := roleFor(compiler.baseline, peer)
	if placement != Untrusted || peerRole == Security {
		return "P07_security_router_owned"
	}
	if peerRole == Assessment || peerRole == Guest || peerRole == Unknown {
		return "P07_isolated_or_unclassified_peer"
	}
	if peerRole == placement {
		return "same_vlan_not_router_enforceable"
	}
	if peerRole == Internet && rule.Direction != FromDevice {
		return "P09_unsolicited_wan"
	}
	if port == 53 || rule.Protocol == "udp" && port == 123 {
		return "P06_router_dns_ntp"
	}
	for _, blocks := range [][]NetworkBlock{compiler.baseline.ProtectedNetworks, compiler.baseline.RetainedBlocks} {
		for _, block := range blocks {
			matchesRole := len(block.Roles) == 0 || slices.Contains(block.Roles, placement)
			matchesMAC := block.SourceMAC == "" || block.SourceMAC == mac
			matchesInternet := !block.InternetOnly || peerRole == Internet
			matchesNetwork := inPrefixes(peer, block.Networks) || inPrefixes(flow.device, block.Networks)
			if matchesRole && matchesMAC && matchesInternet && matchesNetwork {
				return block.ProtectionID + "_retained_network_block"
			}
		}
	}
	for _, block := range compiler.baseline.ProtectedEndpoints {
		destination := peer
		if rule.Direction == ToDevice {
			destination = flow.device
		}
		matchesProtocol := block.Protocol == "any" || block.Protocol == rule.Protocol
		matchesPort := len(block.Ports) == 0 || slices.Contains(block.Ports, port)
		matchesEndpoint := inPrefixes(destination, block.Networks)
		if !block.DestinationOnly {
			matchesEndpoint = inPrefixes(peer, block.Networks) || inPrefixes(flow.device, block.Networks)
		}
		if matchesProtocol && matchesPort && matchesEndpoint {
			return block.ProtectionID + "_protected_endpoint"
		}
	}
	return ""
}
