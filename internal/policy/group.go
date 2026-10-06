// Package policy compiles directory permissions against a separately owned floor.
package policy

import (
	"encoding/json"
	"errors"
	"net/netip"
	"regexp"
	"slices"
	"strings"
	"time"
	"unicode"

	"github.com/mikenorgate/router-policy-agent/internal/strictjson"
)

// Attribute is the group-only directory attribute carrying version-one policy.
const Attribute = "network_policy_v1"

// AttributeLimit is the maximum group-policy JSON size in bytes.
const AttributeLimit = 16 * 1024

var identifier = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9._:-]{0,127}$`)

// Role identifies a reviewed network zone, not an authorization privilege.
type Role string

// Reviewed roles. VLAN IDs and address allocations come from router configuration.
const (
	Trusted        Role = "trusted"
	Guest          Role = "guest"
	Untrusted      Role = "untrusted"
	Infrastructure Role = "infrastructure"
	Security       Role = "security"
	Assessment     Role = "assessment"
	Internet       Role = "internet"
	Unknown        Role = "unknown"
)

// Direction describes connection initiation, not reply permission.
type Direction string

// Supported initiation directions.
const (
	ToDevice   Direction = "to_device"
	FromDevice Direction = "from_device"
)

// Group represents an individually read group, never merged user attributes.
type Group struct {
	ID        string  `json:"id"`
	Name      string  `json:"name"`
	Policy    *string `json:"policy,omitempty"`
	IsNetwork bool    `json:"is_network"`
}

// Document is a validated placement or access attribute.
type Document struct {
	SchemaVersion int    `json:"schema_version"`
	Kind          string `json:"kind"`
	VLANRole      Role   `json:"vlan_role"`
	Temporary     bool   `json:"temporary,omitempty"`
	Rules         []Rule `json:"rules,omitempty"`
}

// Peer contains exact hosts. DNS expansion and subnet peers are not supported.
type Peer struct {
	Addresses []string `json:"addresses"`
}

// Rule defines one logical permit whose NAT variants retain scope and expiry.
type Rule struct {
	ID               string     `json:"id"`
	Direction        Direction  `json:"direction"`
	Peer             Peer       `json:"peer"`
	Protocol         string     `json:"protocol"`
	DestinationPorts []uint16   `json:"destination_ports"`
	Reason           string     `json:"reason"`
	ExpiresAt        *time.Time `json:"expires_at,omitempty"`
}

// ParseGroup validates the entire exact schema before interpreting a policy.
func ParseGroup(raw string) (Document, error) {
	data := []byte(raw)
	object := map[string]json.RawMessage{}
	if err := strictjson.Decode(data, &object, AttributeLimit); err != nil {
		return Document{}, err
	}
	var kind string
	if err := json.Unmarshal(object["kind"], &kind); err != nil {
		return Document{}, errors.New("policy: missing or invalid kind")
	}
	required := []string{"schema_version", "kind", "vlan_role"}
	switch kind {
	case "placement":
	case "access":
		required = append(required, "temporary", "rules")
	default:
		return Document{}, errors.New("policy: unsupported kind")
	}
	if err := strictjson.Object(data, required, nil, AttributeLimit); err != nil {
		return Document{}, err
	}
	var document Document
	if err := strictjson.Decode(data, &document, AttributeLimit); err != nil {
		return Document{}, err
	}
	if document.SchemaVersion != 1 || !validRole(document.VLANRole) {
		return Document{}, errors.New("policy: unsupported schema or role")
	}
	if kind == "placement" {
		return document, nil
	}
	if document.VLANRole != Untrusted {
		return Document{}, errors.New("policy: dynamic access is restricted to untrusted")
	}
	if len(document.Rules) == 0 || len(document.Rules) > 32 {
		return Document{}, errors.New("policy: rule count outside bounds")
	}
	rawRules := []json.RawMessage{}
	if err := json.Unmarshal(object["rules"], &rawRules); err != nil {
		return Document{}, errors.New("policy: invalid rule list")
	}
	seen := map[string]bool{}
	for index, rule := range document.Rules {
		if err := validateRule(rule, rawRules[index], document.Temporary); err != nil {
			return Document{}, err
		}
		if seen[rule.ID] {
			return Document{}, errors.New("policy: duplicate rule id")
		}
		seen[rule.ID] = true
	}
	return document, nil
}

func validateRule(rule Rule, raw json.RawMessage, isTemporary bool) error {
	required := []string{"id", "direction", "peer", "protocol", "destination_ports", "reason"}
	if isTemporary {
		required = append(required, "expires_at")
	}
	if err := strictjson.Object(raw, required, nil, AttributeLimit); err != nil {
		return err
	}
	object := map[string]json.RawMessage{}
	if err := strictjson.Decode(raw, &object, AttributeLimit); err != nil {
		return err
	}
	if err := strictjson.Object(object["peer"], []string{"addresses"}, nil, AttributeLimit); err != nil {
		return err
	}
	if !identifier.MatchString(rule.ID) || !validText(rule.Reason, 512) {
		return errors.New("policy: invalid rule id or reason")
	}
	if rule.Direction != ToDevice && rule.Direction != FromDevice {
		return errors.New("policy: invalid direction")
	}
	if rule.Protocol != "tcp" && rule.Protocol != "udp" {
		return errors.New("policy: unsupported protocol")
	}
	if len(rule.Peer.Addresses) == 0 || len(rule.Peer.Addresses) > 8 {
		return errors.New("policy: peer count outside bounds")
	}
	if len(rule.DestinationPorts) == 0 || len(rule.DestinationPorts) > 16 {
		return errors.New("policy: port count outside bounds")
	}
	seenPeers := map[netip.Addr]bool{}
	for _, rawPeer := range rule.Peer.Addresses {
		peer, err := ParseHost(rawPeer)
		if err != nil {
			return err
		}
		if seenPeers[peer] {
			return errors.New("policy: duplicate peer")
		}
		seenPeers[peer] = true
	}
	seenPorts := map[uint16]bool{}
	for _, port := range rule.DestinationPorts {
		if port == 0 || seenPorts[port] {
			return errors.New("policy: zero or duplicate port")
		}
		seenPorts[port] = true
	}
	if isTemporary {
		var timestamp string
		if err := json.Unmarshal(object["expires_at"], &timestamp); err != nil {
			return errors.New("policy: invalid expiry")
		}
		if !strings.HasSuffix(timestamp, "Z") || rule.ExpiresAt == nil || rule.ExpiresAt.IsZero() {
			return errors.New("policy: expiry must be an explicit utc timestamp")
		}
	}
	return nil
}

// ParseHost accepts a canonical /32 or /128 host suitable for a policy peer.
// Translator aliases must also be decoded and checked against their real peer.
func ParseHost(raw string) (netip.Addr, error) {
	prefix, err := netip.ParsePrefix(raw)
	if err != nil {
		return netip.Addr{}, errors.New("policy: invalid host prefix")
	}
	address := prefix.Addr()
	isHost := prefix.Bits() == address.BitLen()
	isCanonical := prefix.String() == raw
	if !isHost || !isCanonical || !validAddress(address) {
		return netip.Addr{}, errors.New("policy: unsupported or noncanonical host")
	}
	return address, nil
}

func validRole(role Role) bool {
	return slices.Contains([]Role{Trusted, Guest, Untrusted, Infrastructure, Security, Assessment}, role)
}

func validText(value string, maximum int) bool {
	if len(value) == 0 || len(value) > maximum || strings.TrimSpace(value) == "" {
		return false
	}
	return !strings.ContainsFunc(value, unicode.IsControl)
}

func validAddress(address netip.Addr) bool {
	if !address.IsValid() || !address.IsGlobalUnicast() || address.Is4In6() || address.Zone() != "" {
		return false
	}
	for _, prefix := range nonPeerPrefixes {
		if prefix.Contains(address) {
			return false
		}
	}
	return true
}

var nonPeerPrefixes = []netip.Prefix{
	netip.MustParsePrefix("0.0.0.0/8"),
	netip.MustParsePrefix("192.0.2.0/24"),
	netip.MustParsePrefix("198.18.0.0/15"),
	netip.MustParsePrefix("198.51.100.0/24"),
	netip.MustParsePrefix("203.0.113.0/24"),
	netip.MustParsePrefix("240.0.0.0/4"),
	netip.MustParsePrefix("2001:db8::/32"),
	netip.MustParsePrefix("3fff::/20"),
}
