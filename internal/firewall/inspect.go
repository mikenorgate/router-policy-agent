package firewall

import (
	"context"
	"encoding/json"
	"errors"
	"slices"

	"github.com/mikenorgate/router-policy-agent/internal/strictjson"
)

// setInventory is an observation, never an authorization or guard attestation.
// The fixed set-only table must be extended by a separately reviewed guard
// schema before packet enforcement is possible. Do not admit arbitrary rules
// merely to make a future guard table pass this verifier.
type setInventory struct {
	cohort []string
	leases int
}

type listedSet struct {
	Family   string            `json:"family"`
	Table    string            `json:"table"`
	Name     string            `json:"name"`
	Handle   uint64            `json:"handle"`
	Type     json.RawMessage   `json:"type"`
	Size     uint64            `json:"size"`
	Flags    []string          `json:"flags,omitempty"`
	Timeout  int               `json:"timeout,omitempty"`
	Elements []json.RawMessage `json:"elem,omitempty"`
}

// verifySetInventory accepts only the selected nftables listing shape. It
// rejects schema drift, ambiguous identities and unexpected table objects;
// absent, malformed or canceled observations never yield partial inventory.
// The fixed listing metadata is compatibility evidence, not release attestation.
func verifySetInventory(ctx context.Context, data []byte) (*setInventory, error) {
	if ctx == nil {
		return nil, errors.New("firewall: missing inspection context")
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if err := strictjson.Object(
		data,
		[]string{"nftables"},
		nil,
		maximumOutput,
	); err != nil {
		return nil, err
	}
	var listing struct {
		Objects []json.RawMessage `json:"nftables"`
	}
	if err := strictjson.Decode(data, &listing, maximumOutput); err != nil {
		return nil, err
	}
	// Metadata, table, permanent cohort and every distinct lease set are required.
	if len(listing.Objects) != len(grantSets)+3 {
		return nil, errors.New("firewall: owned object inventory differs")
	}
	if err := verifyListingHeader(listing.Objects[:2]); err != nil {
		return nil, err
	}
	seenNames, seenHandles := map[string]bool{}, map[uint64]bool{}
	keys := make([]tupleKey, 0)
	inventory := &setInventory{cohort: []string{}}
	for _, raw := range listing.Objects[2:] {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		set, err := decodeListedSet(raw)
		if err != nil {
			return nil, err
		}
		if seenNames[set.Name] || seenHandles[set.Handle] {
			return nil, errors.New("firewall: duplicate owned set identity")
		}
		seenNames[set.Name], seenHandles[set.Handle] = true, true
		if set.Name == cohortSet {
			if err := validateMACs(set.Elements); err != nil {
				return nil, err
			}
			for _, rawMAC := range set.Elements {
				var mac string
				if err := json.Unmarshal(rawMAC, &mac); err != nil {
					return nil, errors.New("firewall: invalid listed cohort identity")
				}
				inventory.cohort = append(inventory.cohort, mac)
			}
			continue
		}
		seenTuples := map[tupleKey]bool{}
		for _, rawElement := range set.Elements {
			if err := ctx.Err(); err != nil {
				return nil, err
			}
			key, err := verifyListedTuple(rawElement, ipv4Set(set.Name))
			if err != nil {
				return nil, err
			}
			if seenTuples[key] {
				return nil, errors.New("firewall: duplicate listed lease tuple")
			}
			seenTuples[key] = true
			keys = append(keys, key)
			if len(keys) > maximumTupleCount {
				return nil, errors.New("firewall: listed tuple quota exceeded")
			}
		}
	}
	if !seenNames[cohortSet] {
		return nil, errors.New("firewall: permanent cohort is missing")
	}
	for _, name := range grantSets {
		if !seenNames[name] {
			return nil, errors.New("firewall: owned lease set is missing")
		}
	}
	slices.Sort(inventory.cohort)
	for _, key := range keys {
		if _, classified := slices.BinarySearch(inventory.cohort, key.mac); !classified {
			return nil, errors.New("firewall: listed grant lacks permanent classification")
		}
	}
	inventory.leases = len(keys)
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return inventory, nil
}

func verifyListingHeader(objects []json.RawMessage) error {
	return verifyOwnedListingHeader(objects, "inet")
}

func verifyOwnedListingHeader(objects []json.RawMessage, family string) error {
	var metadata struct {
		Version     string `json:"version"`
		ReleaseName string `json:"release_name"`
		Schema      int    `json:"json_schema_version"`
	}
	if err := decodeNested(
		objects[0],
		"metainfo",
		&metadata,
		[]string{"version", "release_name", "json_schema_version"},
	); err != nil {
		return err
	}
	validLibrary := metadata.Version == "1.1.3" && metadata.ReleaseName == "Commodore Bullmoose #4"
	if !validLibrary || metadata.Schema != 1 {
		return errors.New("firewall: unsupported listing format")
	}
	var table struct {
		Family string `json:"family"`
		Name   string `json:"name"`
		Handle uint64 `json:"handle"`
	}
	if err := decodeNested(
		objects[1],
		"table",
		&table,
		[]string{"family", "name", "handle"},
	); err != nil {
		return err
	}
	if table.Family != family || table.Name != ownedTable || table.Handle == 0 {
		return errors.New("firewall: owned table identity differs")
	}
	return nil
}

func decodeListedSet(raw json.RawMessage) (listedSet, error) {
	var set listedSet
	if err := strictjson.Object(
		raw,
		[]string{"set"},
		nil,
		maximumOutput,
	); err != nil {
		return set, err
	}
	object := map[string]json.RawMessage{}
	if err := strictjson.Decode(raw, &object, maximumOutput); err != nil {
		return set, err
	}
	required := []string{"family", "table", "name", "handle", "type", "size"}
	optional := []string{"elem"}
	// Only lease sets may carry timeouts. Permanent classification cannot expire.
	var identity struct {
		Name string `json:"name"`
	}
	if err := json.Unmarshal(object["set"], &identity); err != nil {
		return set, errors.New("firewall: invalid listed set identity")
	}
	if isGrantSet(identity.Name) {
		required = append(required, "flags", "timeout")
	}
	if err := strictjson.Object(
		object["set"],
		required,
		optional,
		maximumOutput,
	); err != nil {
		return set, err
	}
	if err := strictjson.Decode(object["set"], &set, maximumOutput); err != nil {
		return set, err
	}
	ref := objectReference{Family: set.Family, Table: set.Table, Name: set.Name}
	if !ownedReference(ref) || set.Handle == 0 {
		return set, errors.New("firewall: listed set is outside ownership")
	}
	if set.Name == cohortSet {
		var datatype string
		if err := json.Unmarshal(set.Type, &datatype); err != nil || datatype != "ether_addr" {
			return set, errors.New("firewall: permanent cohort datatype differs")
		}
		if set.Size != maximumCohortSize || len(set.Elements) > maximumCohortSize {
			return set, errors.New("firewall: permanent cohort capacity differs")
		}
		return set, nil
	}
	if !isGrantSet(set.Name) {
		return set, errors.New("firewall: unexpected listed set")
	}
	addressType := "ipv6_addr"
	if ipv4Set(set.Name) {
		addressType = "ipv4_addr"
	}
	var datatypes []string
	if err := json.Unmarshal(set.Type, &datatypes); err != nil ||
		!slices.Equal(datatypes, []string{"ifname", "ether_addr", addressType, addressType, "inet_service"}) {
		return set, errors.New("firewall: lease tuple datatype differs")
	}
	validTimeout := slices.Equal(set.Flags, []string{"timeout"}) && set.Timeout == 90
	validCapacity := set.Size == maximumTupleCount && len(set.Elements) <= maximumTupleCount
	if !validTimeout || !validCapacity {
		return set, errors.New("firewall: lease set bounds or flags differ")
	}
	return set, nil
}

func verifyListedTuple(raw json.RawMessage, ipv4 bool) (tupleKey, error) {
	var element struct {
		Value   json.RawMessage `json:"val"`
		Timeout int             `json:"timeout"`
		Expires uint64          `json:"expires"`
	}
	if err := decodeNested(
		raw,
		"elem",
		&element,
		[]string{"val", "timeout", "expires"},
	); err != nil {
		return tupleKey{}, err
	}
	if element.Timeout < 1 || element.Timeout > maximumElementLifetime {
		return tupleKey{}, errors.New("firewall: listed lease lifetime outside bounds")
	}
	if element.Expires > uint64(element.Timeout) {
		return tupleKey{}, errors.New("firewall: listed lease expiry exceeds its lifetime")
	}
	return validateTuple(element.Value, ipv4)
}

// checkReplacement requires a verified inventory and a separately validated
// fixed transaction. Every leased identity must already be classified or be
// included in the same atomic append. No tuple in the listing is authorization.
func (inventory *setInventory) checkReplacement(ctx context.Context, data []byte) error {
	if inventory == nil || ctx == nil {
		return errors.New("firewall: missing verified replacement dependencies")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := validateBatch(data); err != nil {
		return err
	}
	var batch struct {
		Commands []change `json:"nftables"`
	}
	if err := strictjson.Decode(data, &batch, maximumBatch); err != nil {
		return err
	}
	cohort := make(map[string]bool, len(inventory.cohort))
	for _, mac := range inventory.cohort {
		cohort[mac] = true
	}
	for _, command := range batch.Commands {
		if command.Add == nil || command.Add.Element.Name != cohortSet {
			continue
		}
		for _, raw := range command.Add.Element.Values {
			var mac string
			if err := json.Unmarshal(raw, &mac); err != nil {
				return errors.New("firewall: invalid cohort addition")
			}
			cohort[mac] = true
		}
	}
	if len(cohort) > maximumCohortSize {
		return errors.New("firewall: replacement exceeds permanent cohort capacity")
	}
	for _, command := range batch.Commands {
		if err := ctx.Err(); err != nil {
			return err
		}
		if command.Add == nil || command.Add.Element.Name == cohortSet {
			continue
		}
		for _, raw := range command.Add.Element.Values {
			if err := ctx.Err(); err != nil {
				return err
			}
			key, err := validateLeasedTuple(raw, ipv4Set(command.Add.Element.Name))
			if err != nil {
				return err
			}
			if !cohort[key.mac] {
				return errors.New("firewall: replacement grant lacks permanent classification")
			}
		}
	}
	return ctx.Err()
}
