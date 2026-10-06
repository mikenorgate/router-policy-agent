package firewall

import (
	"encoding/json"
	"errors"
	"net/netip"
	"regexp"

	"github.com/mikenorgate/router-policy-agent/internal/policy"
	"github.com/mikenorgate/router-policy-agent/internal/strictjson"
)

const (
	cohortSet              = "managed_macs"
	maximumElementLifetime = 87
)

var interfaceName = regexp.MustCompile(`^[a-zA-Z0-9_.:-]{1,15}$`)

// Protocol is part of the fixed object identity. Six concatenated datatype
// identifiers exceed nftables' packed type representation on the selected build.
// Five data fields plus an immutable protocol selector retain the full tuple.
var grantSets = [...]string{
	"lease_from4_tcp", "lease_from4_udp", "lease_to4_tcp", "lease_to4_udp",
	"lease_from6_tcp", "lease_from6_udp", "lease_to6_tcp", "lease_to6_udp",
}

type objectReference struct {
	Family string `json:"family"`
	Table  string `json:"table"`
	Name   string `json:"name"`
}

type elements struct {
	Family string            `json:"family"`
	Table  string            `json:"table"`
	Name   string            `json:"name"`
	Values []json.RawMessage `json:"elem"`
}

type tupleKey struct {
	interfaceName string
	mac           string
	device        netip.Addr
	peer          netip.Addr
	port          uint16
}

// validateBatch is a second privilege boundary, not just a JSON syntax check.
// Only an atomic replacement of eight fixed grant sets and an optional append
// to the permanent cohort is possible. No tables, chains, hooks, verdicts,
// maps, includes, routes, object deletion or cohort removal are admitted.
func validateBatch(data []byte) error {
	if err := strictjson.Object(
		data,
		[]string{"nftables"},
		nil,
		maximumBatch,
	); err != nil {
		return err
	}
	var batch struct {
		Commands []json.RawMessage `json:"nftables"`
	}
	if err := strictjson.Decode(data, &batch, maximumBatch); err != nil {
		return err
	}
	if len(batch.Commands) < len(grantSets) || len(batch.Commands) > 2*len(grantSets)+1 {
		return errors.New("firewall: invalid owned transaction size")
	}
	flushed, added := map[string]bool{}, map[string]bool{}
	tupleCount := 0
	for _, command := range batch.Commands {
		object := map[string]json.RawMessage{}
		if err := strictjson.Decode(command, &object, maximumBatch); err != nil || len(object) != 1 {
			return errors.New("firewall: invalid owned operation")
		}
		if raw, exists := object["flush"]; exists {
			if len(added) != 0 {
				return errors.New("firewall: flush must precede all additions")
			}
			var ref objectReference
			if err := decodeNested(
				raw,
				"set",
				&ref,
				[]string{"family", "table", "name"},
			); err != nil {
				return err
			}
			if !ownedReference(ref) || !isGrantSet(ref.Name) || flushed[ref.Name] {
				return errors.New("firewall: flush outside owned grant sets")
			}
			flushed[ref.Name] = true
			continue
		}
		raw, exists := object["add"]
		if !exists || len(flushed) != len(grantSets) {
			return errors.New("firewall: complete grant replacement required")
		}
		var values elements
		if err := decodeNested(
			raw,
			"element",
			&values,
			[]string{"family", "table", "name", "elem"},
		); err != nil {
			return err
		}
		ref := objectReference{Family: values.Family, Table: values.Table, Name: values.Name}
		if !ownedReference(ref) || added[ref.Name] || len(values.Values) == 0 {
			return errors.New("firewall: invalid owned element addition")
		}
		added[ref.Name] = true
		if ref.Name == cohortSet {
			if len(added) != 1 || len(values.Values) > 4096 {
				return errors.New("firewall: cohort must precede grants and respect quota")
			}
			if err := validateMACs(values.Values); err != nil {
				return err
			}
			continue
		}
		if !isGrantSet(ref.Name) {
			return errors.New("firewall: element outside owned sets")
		}
		tupleCount += len(values.Values)
		if tupleCount > 16384 {
			return errors.New("firewall: expanded tuple quota exceeded")
		}
		seen := map[tupleKey]bool{}
		for _, value := range values.Values {
			key, err := validateLeasedTuple(value, ipv4Set(ref.Name))
			if err != nil {
				return err
			}
			if seen[key] {
				return errors.New("firewall: duplicate leased tuple")
			}
			seen[key] = true
		}
	}
	if len(flushed) != len(grantSets) {
		return errors.New("firewall: incomplete grant replacement")
	}
	return nil
}

func decodeNested(raw json.RawMessage, key string, target any, keys []string) error {
	if err := strictjson.Object(
		raw,
		[]string{key},
		nil,
		maximumBatch,
	); err != nil {
		return err
	}
	object := map[string]json.RawMessage{}
	if err := strictjson.Decode(raw, &object, maximumBatch); err != nil {
		return err
	}
	if err := strictjson.Object(
		object[key],
		keys,
		nil,
		maximumBatch,
	); err != nil {
		return err
	}
	return strictjson.Decode(object[key], target, maximumBatch)
}

func ownedReference(ref objectReference) bool {
	return ref.Family == "inet" && ref.Table == ownedTable
}

func isGrantSet(name string) bool {
	for _, expected := range grantSets {
		if name == expected {
			return true
		}
	}
	return false
}

func ipv4Set(name string) bool {
	return name == "lease_from4_tcp" || name == "lease_from4_udp" ||
		name == "lease_to4_tcp" || name == "lease_to4_udp"
}

func validateMACs(raw []json.RawMessage) error {
	seen := map[string]bool{}
	for _, value := range raw {
		var mac string
		if err := json.Unmarshal(value, &mac); err != nil {
			return errors.New("firewall: canonical cohort MAC required")
		}
		canonical, err := policy.CanonicalMAC(mac)
		if err != nil || canonical != mac || seen[mac] {
			return errors.New("firewall: invalid or duplicate cohort MAC")
		}
		seen[mac] = true
	}
	return nil
}

func validateLeasedTuple(raw json.RawMessage, ipv4 bool) (tupleKey, error) {
	var element struct {
		Value   json.RawMessage `json:"val"`
		Timeout int             `json:"timeout"`
	}
	if err := decodeNested(
		raw,
		"elem",
		&element,
		[]string{"val", "timeout"},
	); err != nil {
		return tupleKey{}, err
	}
	// libnftables JSON uses seconds. The cap leaves room for the command's
	// execution budget, including pipe cleanup, rounded up. Rendering must also
	// subtract preparation and execution from each
	// absolute evidence deadline; this validator cannot infer those deadlines.
	if element.Timeout < 1 || element.Timeout > maximumElementLifetime {
		return tupleKey{}, errors.New("firewall: invalid bounded element lifetime")
	}
	if err := strictjson.Object(
		element.Value,
		[]string{"concat"},
		nil,
		maximumBatch,
	); err != nil {
		return tupleKey{}, err
	}
	var tuple struct {
		Values []json.RawMessage `json:"concat"`
	}
	if err := strictjson.Decode(element.Value, &tuple, maximumBatch); err != nil || len(tuple.Values) != 5 {
		return tupleKey{}, errors.New("firewall: exact five-field tuple required")
	}
	fields := make([]string, 4)
	for index := range fields {
		if err := json.Unmarshal(tuple.Values[index], &fields[index]); err != nil {
			return tupleKey{}, errors.New("firewall: invalid tuple value type")
		}
	}
	if !interfaceName.MatchString(fields[0]) {
		return tupleKey{}, errors.New("firewall: invalid tuple interface")
	}
	canonical, err := policy.CanonicalMAC(fields[1])
	if err != nil || canonical != fields[1] {
		return tupleKey{}, errors.New("firewall: invalid tuple MAC")
	}
	addresses := make([]netip.Addr, 0, 2)
	for _, rawIP := range fields[2:4] {
		address, err := netip.ParseAddr(rawIP)
		if err != nil || address.Is4() != ipv4 || address.String() != rawIP {
			return tupleKey{}, errors.New("firewall: invalid tuple address family or encoding")
		}
		prefix := "/128"
		if ipv4 {
			prefix = "/32"
		}
		if _, err := policy.ParseHost(rawIP + prefix); err != nil {
			return tupleKey{}, err
		}
		addresses = append(addresses, address)
	}
	var port uint16
	if err := json.Unmarshal(tuple.Values[4], &port); err != nil || port == 0 {
		return tupleKey{}, errors.New("firewall: exact tuple destination port required")
	}
	return tupleKey{
		interfaceName: fields[0], mac: fields[1], device: addresses[0], peer: addresses[1], port: port,
	}, nil
}
