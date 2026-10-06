package policy

import (
	"encoding/json"
	"errors"
	"net"
	"net/netip"
	"slices"
	"strings"

	"github.com/mikenorgate/router-policy-agent/internal/strictjson"
)

// Baseline is router-owned configuration, never supplied by a directory group.
// The privileged applier loads its own copy independently of the reader.
type Baseline struct {
	SchemaVersion      int             `json:"schema_version"`
	Generation         string          `json:"generation"`
	Zones              []Zone          `json:"zones"`
	ProtectedNetworks  []NetworkBlock  `json:"protected_networks"`
	ProtectedEndpoints []EndpointBlock `json:"protected_endpoints"`
	RetainedBlocks     []NetworkBlock  `json:"retained_blocks"`
	NAT64              []NAT64         `json:"nat64"`
	NAT46              []NAT46         `json:"nat46"`
	NAT46Pools         []netip.Prefix  `json:"nat46_pools"`
	LeaseSeconds       int             `json:"lease_seconds"`
	RefreshSeconds     int             `json:"refresh_seconds"`
	MaximumDevices     int             `json:"maximum_devices"`
	MaximumTuples      int             `json:"maximum_tuples"`
}

// Zone supplies the reviewed role, VLAN and interface/address geometry.
type Zone struct {
	Role       Role           `json:"role"`
	VLAN       uint16         `json:"vlan"`
	Interfaces []string       `json:"interfaces"`
	Networks   []netip.Prefix `json:"networks"`
}

// NetworkBlock preserves a reviewed network/device restriction and its scope.
// Empty Roles applies to all roles; empty SourceMAC applies to all devices.
type NetworkBlock struct {
	ProtectionID string         `json:"protection_id"`
	Networks     []netip.Prefix `json:"networks"`
	Roles        []Role         `json:"roles"`
	SourceMAC    string         `json:"source_mac,omitempty"`
	InternetOnly bool           `json:"internet_only"`
}

// EndpointBlock denies protected services, not every use of their port number.
// DestinationOnly prevents treating a controller's ephemeral source as an
// attempt to access its administration listener.
type EndpointBlock struct {
	ProtectionID    string         `json:"protection_id"`
	Networks        []netip.Prefix `json:"networks"`
	Protocol        string         `json:"protocol"`
	Ports           []uint16       `json:"ports"`
	DestinationOnly bool           `json:"destination_only"`
}

// DecodeBaseline reads a bounded router-owned configuration. The applier must
// additionally check ownership and permissions before calling it.
func DecodeBaseline(data []byte) (Baseline, error) {
	required := []string{"schema_version", "generation", "zones", "protected_networks", "protected_endpoints",
		"retained_blocks", "nat64", "nat46", "nat46_pools", "lease_seconds", "refresh_seconds",
		"maximum_devices", "maximum_tuples"}
	if err := strictjson.Object(data, required, nil, 2*1024*1024); err != nil {
		return Baseline{}, err
	}
	var baseline Baseline
	if err := strictjson.Decode(data, &baseline, 2*1024*1024); err != nil {
		return Baseline{}, err
	}
	if err := validateBaseline(baseline); err != nil {
		return Baseline{}, err
	}
	return baseline, nil
}

func validateBaseline(b Baseline) error {
	if b.SchemaVersion != 1 || !identifier.MatchString(b.Generation) {
		return errors.New("policy: invalid baseline schema or generation")
	}
	isLeaseValid := b.LeaseSeconds > 0 && b.LeaseSeconds <= 90
	isRefreshValid := b.RefreshSeconds > 0 && b.RefreshSeconds < b.LeaseSeconds
	isCapacityValid := b.MaximumDevices > 0 && b.MaximumDevices <= 4096 &&
		b.MaximumTuples > 0 && b.MaximumTuples <= 16384
	if !isLeaseValid || !isRefreshValid || !isCapacityValid {
		return errors.New("policy: baseline timing or capacity outside bounds")
	}
	roles := map[Role]bool{}
	vlans := map[uint16]bool{}
	interfaces := map[string]bool{}
	for _, zone := range b.Zones {
		if !validRole(zone.Role) || roles[zone.Role] || zone.VLAN == 0 || zone.VLAN > 4094 || vlans[zone.VLAN] {
			return errors.New("policy: invalid or duplicate zone")
		}
		if len(zone.Networks) == 0 || len(zone.Interfaces) == 0 || len(zone.Interfaces) > 8 {
			return errors.New("policy: zone needs networks and interfaces")
		}
		roles[zone.Role], vlans[zone.VLAN] = true, true
		for _, name := range zone.Interfaces {
			if !safeInterface(name) || interfaces[name] {
				return errors.New("policy: invalid or duplicate zone interface")
			}
			interfaces[name] = true
		}
		if err := validPrefixes(zone.Networks); err != nil {
			return err
		}
	}
	if len(roles) != 6 {
		return errors.New("policy: all six role boundaries must be declared")
	}
	for first, zone := range b.Zones {
		for _, other := range b.Zones[first+1:] {
			for _, left := range zone.Networks {
				for _, right := range other.Networks {
					if left.Overlaps(right) {
						return errors.New("policy: conflicting zone address ownership")
					}
				}
			}
		}
	}
	if err := validateCatalogs(b); err != nil {
		return err
	}
	return validateTranslators(b)
}

func validateCatalogs(b Baseline) error {
	if len(b.ProtectedNetworks)+len(b.ProtectedEndpoints)+len(b.RetainedBlocks) > 512 {
		return errors.New("policy: protected catalog outside bounds")
	}
	if len(b.ProtectedNetworks) == 0 || len(b.ProtectedEndpoints) == 0 {
		return errors.New("policy: protected endpoint catalog must be explicit")
	}
	protections := map[string]bool{}
	for index, blocks := range [][]NetworkBlock{b.ProtectedNetworks, b.RetainedBlocks} {
		for _, block := range blocks {
			if index == 0 && (len(block.Roles) != 0 || block.SourceMAC != "" || block.InternetOnly) {
				return errors.New("policy: protected networks cannot have conditional scope")
			}
			isProtectedID := index == 0 && slices.Contains([]string{"P01", "P03"}, block.ProtectionID)
			isRetainedID := index == 1 && block.ProtectionID == "P08"
			if !isProtectedID && !isRetainedID {
				return errors.New("policy: unsupported network protection id")
			}
			if err := validPrefixes(block.Networks); err != nil {
				return err
			}
			protections[block.ProtectionID] = true
			if len(block.Roles) > 6 {
				return errors.New("policy: retained role catalog outside bounds")
			}
			for _, role := range block.Roles {
				if !validRole(role) {
					return errors.New("policy: invalid retained block role")
				}
			}
			if block.SourceMAC != "" {
				if _, err := CanonicalMAC(block.SourceMAC); err != nil {
					return err
				}
			}
		}
	}
	for _, block := range b.ProtectedEndpoints {
		if block.ProtectionID != "P02" && block.ProtectionID != "P03" {
			return errors.New("policy: unsupported endpoint protection id")
		}
		protections[block.ProtectionID] = true
		if err := validPrefixes(block.Networks); err != nil {
			return err
		}
		if block.Protocol != "tcp" && block.Protocol != "udp" && block.Protocol != "any" {
			return errors.New("policy: unsupported protected endpoint protocol")
		}
		if len(block.Ports) > 128 {
			return errors.New("policy: protected port catalog outside bounds")
		}
		for _, port := range block.Ports {
			if port == 0 {
				return errors.New("policy: invalid protected endpoint port")
			}
		}
	}
	if !protections["P01"] || !protections["P02"] || !protections["P03"] {
		return errors.New("policy: protected boundary catalog is incomplete")
	}
	return nil
}

func validPrefixes(prefixes []netip.Prefix) error {
	if len(prefixes) == 0 || len(prefixes) > 256 {
		return errors.New("policy: prefix catalog outside bounds")
	}
	for _, prefix := range prefixes {
		if !prefix.IsValid() || prefix != prefix.Masked() || prefix.Addr().Is4In6() || prefix.Bits() == 0 {
			return errors.New("policy: invalid or noncanonical prefix")
		}
	}
	return nil
}

func safeInterface(name string) bool {
	if len(name) == 0 || len(name) > 15 {
		return false
	}
	return strings.IndexFunc(name, func(value rune) bool {
		return !strings.ContainsRune("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_.:-", value)
	}) < 0
}

// CanonicalMAC rejects multicast, zero and broadcast identities and returns
// colon-separated lower-case Ethernet addresses.
func CanonicalMAC(raw string) (string, error) {
	if len(raw) == 12 && !strings.ContainsAny(raw, ":-.") {
		parts := make([]string, 0, 6)
		for index := 0; index < 12; index += 2 {
			parts = append(parts, raw[index:index+2])
		}
		raw = strings.Join(parts, ":")
	}
	mac, err := net.ParseMAC(raw)
	if err != nil || len(mac) != 6 {
		return "", errors.New("policy: invalid ethernet identity")
	}
	if mac[0]&1 != 0 || slices.Equal(mac, net.HardwareAddr{0, 0, 0, 0, 0, 0}) {
		return "", errors.New("policy: unsupported ethernet identity")
	}
	return mac.String(), nil
}

func cloneBaseline(b Baseline) (Baseline, error) {
	data, err := json.Marshal(b)
	if err != nil {
		return Baseline{}, errors.New("policy: baseline serialization failed")
	}
	var clone Baseline
	if err := json.Unmarshal(data, &clone); err != nil {
		return Baseline{}, errors.New("policy: baseline copy failed")
	}
	return clone, nil
}
