package firewall

import (
	"context"
	"encoding/json"
	"errors"
	"net/netip"
	"slices"

	"github.com/mikenorgate/router-policy-agent/internal/policy"
	"github.com/mikenorgate/router-policy-agent/internal/state"
)

const (
	translatedOriginalTag = "0xc1000000"
	translatedReplyTag    = "0xc2000000"
)

// Only the reviewed controller paths currently have enough root-owned geometry
// to derive a device callback's TUN leg. General translator grants are not
// qualified. A path is not an address binding or permission by itself.
type deviceTranslationPath struct {
	deviceInterface, tunInterface, peerInterface string
	deviceNetwork, aliasNetwork                  netip.Prefix
	peer4, peer6                                 netip.Addr
	isReady                                      bool
}

func deviceTranslationPaths(baseline policy.Baseline) []deviceTranslationPath {
	paths := []deviceTranslationPath{}
	for _, controller := range baseline.ControllerInitiators {
		for _, path := range controller.NAT64Paths {
			var prefix netip.Prefix
			for _, translator := range baseline.NAT64 {
				if translator.ID == path.TranslatorID {
					prefix = translator.Prefix
				}
			}
			for _, mapping := range baseline.NAT46 {
				if !slices.Contains(path.MappingIDs, mapping.ID) {
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
						for _, name := range zone.Interfaces {
							paths = append(paths, deviceTranslationPath{
								deviceInterface: name, tunInterface: path.Interface,
								peerInterface: controller.SourceInterface, deviceNetwork: network,
								aliasNetwork: netip.PrefixFrom(embedDeviceAddress(prefix, network.Addr()), 96+network.Bits()),
								peer4:        mapping.Alias, peer6: mapping.Target, isReady: mapping.Ready,
							})
						}
					}
				}
			}
		}
	}
	return paths
}

func embedDeviceAddress(prefix netip.Prefix, address netip.Addr) netip.Addr {
	encoded, ipv4 := prefix.Addr().As16(), address.As4()
	copy(encoded[12:], ipv4[:])
	return netip.AddrFrom16(encoded)
}

func translatedGrantRefs(paths []deviceTranslationPath) []objectReference {
	refs := []objectReference{}
	if len(paths) == 0 {
		return refs
	}
	for _, protocol := range []string{"tcp", "udp"} {
		refs = append(refs, ownedRef("transit_from6_"+protocol))
		for _, name := range []string{"transit_request4_", "transit_request6_", "transit_reply6_"} {
			refs = append(refs, objectReference{Family: "netdev", Table: ownedTable, Name: name + protocol})
		}
	}
	return refs
}

// Projection consumes only the validated logical from-device IPv4 tuples. The
// physical MAC remains on the original leg; TUN authority is a separate exact,
// expiring mirror, never a fabricated Ethernet identity or pool exemption.
func projectTranslatedGrants(
	ctx context.Context,
	logical guardChanges,
	paths []deviceTranslationPath,
) ([]change, error) {
	refs := translatedGrantRefs(paths)
	values := make(map[objectReference]map[string]int, len(refs))
	for _, ref := range refs {
		values[ref] = map[string]int{}
	}
	for _, command := range logical.Commands {
		if command.Add == nil {
			continue
		}
		element := command.Add.Element
		if element.Family != "inet" || element.Name != "lease_from4_tcp" && element.Name != "lease_from4_udp" {
			continue
		}
		_, protocol := guardProtocol(element.Name)
		for _, raw := range element.Values {
			if err := ctx.Err(); err != nil {
				return nil, err
			}
			tuple, err := validateLeasedTuple(raw, true)
			if err != nil {
				return nil, err
			}
			var lease struct {
				Element struct {
					Timeout int `json:"timeout"`
				} `json:"elem"`
			}
			if err := json.Unmarshal(raw, &lease); err != nil {
				return nil, errors.New("firewall: translated source lease decoding failed")
			}
			for _, path := range paths {
				if err := ctx.Err(); err != nil {
					return nil, err
				}
				isPhysicalLeg := tuple.interfaceName == path.deviceInterface && path.deviceNetwork.Contains(tuple.device)
				if !path.isReady || !isPhysicalLeg || !tuple.network().Contains(path.peer4) {
					continue
				}
				alias := embedDeviceAddress(path.aliasNetwork, tuple.device)
				keys := map[objectReference][]any{
					ownedRef("transit_from6_" + protocol): {
						path.tunInterface, alias.String(), path.peer6.String(), tuple.portValue(),
					},
					{Family: "netdev", Table: ownedTable, Name: "transit_request4_" + protocol}: {
						path.tunInterface, tuple.device.String(), path.peer4.String(), tuple.portValue(),
					},
					{Family: "netdev", Table: ownedTable, Name: "transit_request6_" + protocol}: {
						path.peerInterface, alias.String(), path.peer6.String(), tuple.portValue(),
					},
					{Family: "netdev", Table: ownedTable, Name: "transit_reply6_" + protocol}: {
						path.tunInterface, alias.String(), path.peer6.String(), tuple.portValue(),
					},
				}
				for ref, key := range keys {
					encoded, err := json.Marshal(map[string]any{"concat": key})
					if err != nil {
						return nil, errors.New("firewall: translated tuple encoding failed")
					}
					values[ref][string(encoded)] = max(values[ref][string(encoded)], lease.Element.Timeout)
					if len(values[ref]) > maximumTupleCount {
						return nil, errors.New("firewall: translated mirror quota exceeded")
					}
				}
			}
		}
	}
	commands := make([]change, 0, 2*len(refs))
	for _, ref := range refs {
		commands = append(commands, change{Flush: &setChange{Set: ref}})
		keys := make([]string, 0, len(values[ref]))
		for key := range values[ref] {
			keys = append(keys, key)
		}
		slices.Sort(keys)
		encoded := make([]json.RawMessage, 0, len(keys))
		for _, key := range keys {
			if err := ctx.Err(); err != nil {
				return nil, err
			}
			value, err := json.Marshal(map[string]any{"elem": map[string]any{
				"val": json.RawMessage(key), "timeout": values[ref][key],
			}})
			if err != nil {
				return nil, errors.New("firewall: translated lease encoding failed")
			}
			encoded = append(encoded, value)
		}
		if len(encoded) != 0 {
			commands = append(commands, guardAdd(ref.Family, ref.Name, encoded))
		}
	}
	return commands, ctx.Err()
}

func expandMappedGuardBatch(
	ctx context.Context,
	source []byte,
	classification *state.Classification,
	paths []deviceTranslationPath,
) ([]byte, error) {
	native, err := expandGuardBatchWithClassification(ctx, source, classification)
	if err != nil || len(paths) == 0 {
		return native, err
	}
	var logical, expanded guardChanges
	if err := json.Unmarshal(source, &logical); err != nil {
		return nil, errors.New("firewall: translated logical batch decoding failed")
	}
	if err := json.Unmarshal(native, &expanded); err != nil {
		return nil, errors.New("firewall: translated native mirrors decoding failed")
	}
	translated, err := projectTranslatedGrants(ctx, logical, paths)
	if err != nil {
		return nil, err
	}
	expanded.Commands = append(expanded.Commands, translated...)
	data, err := json.Marshal(expanded)
	if err != nil || len(data) > maximumBatch {
		return nil, errors.New("firewall: translated mirror encoding or quota failed")
	}
	return data, ctx.Err()
}
