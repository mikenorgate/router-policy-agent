package firewall

import (
	"net/netip"
	"slices"

	"github.com/mikenorgate/router-policy-agent/internal/policy"
)

// Geometry comes only from the copied, validated root baseline. Each translated
// family gets an independent guarded leg; userspace never transports authority.
func controllerTranslationLegs(baseline policy.Baseline) []controllerLeg {
	legs := []controllerLeg{}
	for _, controller := range baseline.ControllerInitiators {
		for _, path := range controller.NAT64Paths {
			var prefix netip.Prefix
			for _, translator := range baseline.NAT64 {
				if translator.ID == path.TranslatorID {
					prefix = translator.Prefix
				}
			}
			for _, mapping := range baseline.NAT46 {
				if !mapping.Ready || !slices.Contains(path.MappingIDs, mapping.ID) {
					continue
				}
				for _, zone := range baseline.Zones {
					if zone.Role != policy.Untrusted {
						continue
					}
					for _, network := range zone.Networks {
						if !network.Addr().Is4() {
							continue
						}
						address, ipv4 := prefix.Addr().As16(), network.Addr().As4()
						copy(address[12:], ipv4[:])
						alias := netip.PrefixFrom(netip.AddrFrom16(address), 96+network.Bits())
						legs = append(legs, controllerLeg{
							sourceInterface: controller.SourceInterface, targetInterface: path.Interface,
							source: mapping.Target, target: alias, egressSource: mapping.Target,
							isICMPEnabled: controller.ICMPEnabled,
						})
						wireSource := mapping.Alias
						if path.PostroutingSource != nil {
							wireSource = *path.PostroutingSource
						}
						for _, name := range zone.Interfaces {
							legs = append(legs, controllerLeg{
								sourceInterface: path.Interface, targetInterface: name,
								source: mapping.Alias, target: network, egressSource: wireSource,
								isICMPEnabled: controller.ICMPEnabled,
							})
						}
					}
				}
			}
		}
	}
	return legs
}

func controllerAliasIdentities(baseline policy.Baseline) []netip.Addr {
	addresses := []netip.Addr{}
	for _, controller := range baseline.ControllerInitiators {
		for _, path := range controller.NAT64Paths {
			for _, mapping := range baseline.NAT46 {
				if slices.Contains(path.MappingIDs, mapping.ID) {
					// Readiness controls permits, never removal of deny identity.
					addresses = append(addresses, mapping.Alias)
				}
			}
		}
	}
	return addresses
}
