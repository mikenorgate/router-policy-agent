package policy

import (
	"encoding/json"
	"errors"
	"net/netip"
	"slices"

	"github.com/mikenorgate/router-policy-agent/internal/strictjson"
)

// ControllerNAT64Path binds a reviewed private translator to existing exact
// NAT46 host maps for this controller. It neither installs maps nor authorizes
// a translator pool. An optional post-routing source describes NAT44 on the
// Untrusted egress; all pre-routing checks still use the exact mapped source.
type ControllerNAT64Path struct {
	TranslatorID      string      `json:"translator_id"`
	Interface         string      `json:"interface"`
	MappingIDs        []string    `json:"mapping_ids"`
	PostroutingSource *netip.Addr `json:"postrouting_source,omitempty"`
}

func decodeControllerNAT64Paths(data []byte) error {
	object := map[string]json.RawMessage{}
	if err := json.Unmarshal(data, &object); err != nil {
		return errors.New("policy: invalid controller translation object")
	}
	raw, exists := object["nat64_paths"]
	if !exists {
		return nil
	}
	entries := []json.RawMessage{}
	if err := json.Unmarshal(raw, &entries); err != nil || len(entries) > 4 {
		return errors.New("policy: controller translation paths outside bounds")
	}
	for _, entry := range entries {
		if err := strictjson.Object(entry, []string{"translator_id", "interface", "mapping_ids"},
			[]string{"postrouting_source"}, 4096); err != nil {
			return err
		}
	}
	return nil
}

func validateControllerNAT64Paths(b Baseline) (int, error) {
	interfaces, translatorInterfaces := map[string]bool{}, map[string]string{}
	for _, zone := range b.Zones {
		for _, name := range zone.Interfaces {
			interfaces[name] = true
		}
	}
	mappings := make(map[string]NAT46, len(b.NAT46))
	for _, mapping := range b.NAT46 {
		mappings[mapping.ID] = mapping
	}
	seenMappings := map[string]bool{}
	type translatedSource struct {
		translator string
		address    netip.Addr
	}
	seenSources := map[translatedSource]bool{}
	legs := 0
	for _, controller := range b.ControllerInitiators {
		if len(controller.NAT64Paths) > 4 {
			return 0, errors.New("policy: controller translation paths outside bounds")
		}
		for _, path := range controller.NAT64Paths {
			translator, err := controllerTranslator(b, path.TranslatorID)
			if err != nil {
				return 0, err
			}
			isInterfaceValid := safeInterface(path.Interface) && !interfaces[path.Interface]
			isCapacityValid := len(path.MappingIDs) > 0 && len(path.MappingIDs) <= 16
			if !isInterfaceValid || !isCapacityValid {
				return 0, errors.New("policy: invalid controller translation interface or capacity")
			}
			if previous, exists := translatorInterfaces[translator.ID]; exists && previous != path.Interface {
				return 0, errors.New("policy: controller translator interface conflicts")
			}
			for id, name := range translatorInterfaces {
				if name == path.Interface && id != translator.ID {
					return 0, errors.New("policy: controller interface represents multiple translators")
				}
			}
			translatorInterfaces[translator.ID] = path.Interface
			if err := validateControllerPostroutingSource(b, path.PostroutingSource); err != nil {
				return 0, err
			}
			for _, id := range path.MappingIDs {
				mapping, exists := mappings[id]
				isControllerMap := mapping.Target.Is6() && slices.Contains(controller.Addresses, mapping.Target)
				isAliasValid := mapping.Alias.Is4() && mapping.Alias.IsPrivate() && roleFor(b, mapping.Alias) == Unknown
				source := translatedSource{translator: translator.ID, address: mapping.Target}
				if !exists || seenMappings[id] || seenSources[source] || !isControllerMap || !isAliasValid {
					return 0, errors.New("policy: controller translation needs a unique exact owned source map")
				}
				seenMappings[id] = true
				seenSources[source] = true
				targets := 0
				for _, zone := range b.Zones {
					if zone.Role != Untrusted {
						continue
					}
					for _, network := range zone.Networks {
						if !network.Addr().Is4() {
							continue
						}
						if !privateControllerTarget(network) {
							return 0, errors.New("policy: controller private translation target outside private space")
						}
						targets += 1 + len(zone.Interfaces)
					}
				}
				if targets == 0 {
					return 0, errors.New("policy: controller translation has no eligible untrusted targets")
				}
				// Unready mappings remain deny identities and consume the same
				// capacity; they must not silently acquire a permit on readiness.
				legs += targets
			}
		}
	}
	return legs, nil
}

func controllerTranslator(b Baseline, id string) (NAT64, error) {
	for _, translator := range b.NAT64 {
		if translator.ID == id && translator.Scope == "private" && translator.Prefix != wellKnownPrefix {
			return translator, nil
		}
	}
	return NAT64{}, errors.New("policy: controller translation requires a reviewed private translator")
}

func validateControllerPostroutingSource(b Baseline, source *netip.Addr) error {
	if source == nil {
		return nil
	}
	address := *source
	isNativeHost := validAddress(address) && address.Is4() && address.Zone() == "" && !reservedZoneHost(b, address)
	if !isNativeHost || roleFor(b, address) != Untrusted || inPrefixes(address, b.NAT46Pools) {
		return errors.New("policy: controller post-routing source must be an exact native untrusted host")
	}
	return nil
}

func privateControllerTarget(prefix netip.Prefix) bool {
	for _, space := range []netip.Prefix{
		netip.MustParsePrefix("10.0.0.0/8"), netip.MustParsePrefix("172.16.0.0/12"), netip.MustParsePrefix("192.168.0.0/16"),
	} {
		if prefix.Bits() >= space.Bits() && space.Contains(prefix.Addr()) {
			return true
		}
	}
	return false
}
