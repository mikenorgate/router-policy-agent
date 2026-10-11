package policy

import (
	"errors"
	"net/netip"
)

// BootstrapPath is image-owned link control and forced DNS/NTP geometry. It
// cannot grant application traffic or select arbitrary listener ports.
type BootstrapPath struct {
	Interface        string       `json:"interface"`
	ServiceInterface string       `json:"service_interface"`
	GatewayAddresses []netip.Addr `json:"gateway_addresses"`
	DNSAddresses     []netip.Addr `json:"dns_addresses"`
	NTPAddresses     []netip.Addr `json:"ntp_addresses"`
}

func validateBootstrapPaths(b Baseline) error {
	if len(b.BootstrapPaths) > 8 {
		return errors.New("policy: bootstrap catalog outside bounds")
	}
	seen := map[string]bool{}
	zoneInterfaces := map[string]bool{}
	for _, zone := range b.Zones {
		for _, name := range zone.Interfaces {
			zoneInterfaces[name] = true
		}
	}
	for _, path := range b.BootstrapPaths {
		invalidInterface := seen[path.Interface] || !safeInterface(path.ServiceInterface) ||
			zoneInterfaces[path.ServiceInterface]
		if invalidInterface {
			return errors.New("policy: invalid bootstrap interface")
		}
		seen[path.Interface] = true
		var networks []netip.Prefix
		for _, zone := range b.Zones {
			if zone.Role != Untrusted {
				continue
			}
			for _, name := range zone.Interfaces {
				if name == path.Interface {
					networks = zone.Networks
				}
			}
		}
		if len(networks) == 0 {
			return errors.New("policy: bootstrap client interface must be untrusted")
		}
		for _, addresses := range [][]netip.Addr{path.GatewayAddresses, path.DNSAddresses, path.NTPAddresses} {
			if len(addresses) == 0 || len(addresses) > 8 {
				return errors.New("policy: bootstrap address catalog outside bounds")
			}
			unique := map[netip.Addr]bool{}
			for _, address := range addresses {
				invalidAddress := !address.IsValid() || address.Is4In6() || address.Zone() != "" ||
					address.IsUnspecified() || address.IsMulticast() || address.IsLoopback() || unique[address]
				if invalidAddress {
					return errors.New("policy: invalid bootstrap address")
				}
				unique[address] = true
			}
		}
		for _, address := range path.GatewayAddresses {
			if !address.Is6() || !address.IsLinkLocalUnicast() {
				if !bootstrapContains(networks, address) {
					return errors.New("policy: bootstrap gateway outside its client zone")
				}
			}
		}
		for _, addresses := range [][]netip.Addr{path.DNSAddresses, path.NTPAddresses} {
			for _, address := range addresses {
				protected := false
				for _, block := range b.ProtectedNetworks {
					if block.ProtectionID == "P03" && bootstrapContains(block.Networks, address) {
						protected = true
					}
				}
				if !protected {
					return errors.New("policy: bootstrap service must belong to protected service plane")
				}
			}
		}
	}
	return nil
}

func bootstrapContains(networks []netip.Prefix, address netip.Addr) bool {
	for _, network := range networks {
		if network.Contains(address) {
			return true
		}
	}
	return false
}
