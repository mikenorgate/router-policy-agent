package policy

import (
	"encoding/json"
	"errors"
	"net/netip"
	"slices"

	"github.com/mikenorgate/router-policy-agent/internal/strictjson"
)

// ControllerInitiator supplies router-owned TCP/UDP initiation into the
// Untrusted zone, independent of directory grants. Exact addresses must belong
// to its Trusted or Infrastructure ingress. Optional private NAT64 paths need
// exact reviewed source maps. ICMP is a separate root opt-in for echo and
// correlated TCP/UDP errors; live ownership and the installed protected floor
// remain unqualified. The router's protected/source checks still apply.
type ControllerInitiator struct {
	ID              string                `json:"id"`
	SourceInterface string                `json:"source_interface"`
	Addresses       []netip.Addr          `json:"addresses"`
	NAT64Paths      []ControllerNAT64Path `json:"nat64_paths,omitempty"`
	ICMPEnabled     bool                  `json:"icmp_enabled,omitempty"`
}

func decodeControllerInitiators(data []byte) error {
	object := map[string]json.RawMessage{}
	if err := json.Unmarshal(data, &object); err != nil {
		return errors.New("policy: invalid controller baseline object")
	}
	raw, exists := object["controller_initiators"]
	if !exists {
		return nil
	}
	entries := []json.RawMessage{}
	if err := json.Unmarshal(raw, &entries); err != nil || len(entries) > 8 {
		return errors.New("policy: controller catalog outside bounds")
	}
	for _, entry := range entries {
		if err := strictjson.Object(entry, []string{"id", "source_interface", "addresses"}, []string{"nat64_paths", "icmp_enabled"}, 16384); err != nil {
			return err
		}
		if err := decodeControllerNAT64Paths(entry); err != nil {
			return err
		}
	}
	return nil
}

func validateControllerInitiators(b Baseline) error {
	if len(b.ControllerInitiators) > 8 {
		return errors.New("policy: controller catalog outside bounds")
	}
	seenIDs := make(map[string]bool, len(b.ControllerInitiators))
	seenAddresses := map[netip.Addr]bool{}
	legs := 0
	for _, controller := range b.ControllerInitiators {
		isIDValid := identifier.MatchString(controller.ID) && !seenIDs[controller.ID]
		isCapacityValid := len(controller.Addresses) > 0 && len(controller.Addresses) <= 16
		if !isIDValid || !isCapacityValid || !safeInterface(controller.SourceInterface) {
			return errors.New("policy: invalid controller identity or capacity")
		}
		seenIDs[controller.ID] = true
		var sourceZone Zone
		for _, zone := range b.Zones {
			if slices.Contains(zone.Interfaces, controller.SourceInterface) {
				sourceZone = zone
			}
		}
		if sourceZone.Role != Trusted && sourceZone.Role != Infrastructure {
			return errors.New("policy: controller ingress must be trusted or infrastructure")
		}
		for _, address := range controller.Addresses {
			addressLegs := 0
			isNativeHost := validAddress(address) && address.Zone() == "" &&
				inPrefixes(address, sourceZone.Networks) && !reservedZoneHost(b, address)
			if !isNativeHost || seenAddresses[address] {
				return errors.New("policy: invalid or duplicate exact controller host")
			}
			native, err := realAddress(b, address)
			if err != nil || native != address {
				return errors.New("policy: controller aliases are not native identities")
			}
			seenAddresses[address] = true
			for _, zone := range b.Zones {
				if zone.Role != Untrusted {
					continue
				}
				for _, network := range zone.Networks {
					if network.Addr().Is4() != address.Is4() {
						continue
					}
					for _, translator := range b.NAT64 {
						if network.Overlaps(translator.Prefix) {
							return errors.New("policy: controller target geometry includes a translator")
						}
					}
					for _, pool := range b.NAT46Pools {
						if network.Overlaps(pool) {
							return errors.New("policy: controller target geometry includes an alias pool")
						}
					}
					addressLegs += len(zone.Interfaces)
				}
			}
			if addressLegs == 0 {
				return errors.New("policy: controller host has no native untrusted targets")
			}
			legs += addressLegs
		}
	}
	translationLegs, err := validateControllerNAT64Paths(b)
	if err != nil {
		return err
	}
	legs += translationLegs
	if legs > 512 || len(b.ControllerInitiators) != 0 && legs == 0 {
		return errors.New("policy: controller native geometry outside bounds")
	}
	return nil
}
