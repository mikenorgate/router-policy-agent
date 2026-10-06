package firewall

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"slices"

	"github.com/mikenorgate/router-policy-agent/internal/state"
	"github.com/mikenorgate/router-policy-agent/internal/strictjson"
)

// preparedGuardBatch preserves the original renderer's preparation/age fence.
// The current set-only executor deliberately does not admit this new schema.
// Guarded inventory verification and writer fencing are required before wiring.
type preparedGuardBatch struct {
	batch          preparedBatch
	classification *state.Classification
}

type guardChanges struct {
	Commands []change `json:"nftables"`
}

type guardProjection struct {
	value   json.RawMessage
	timeout int
}

// prepareGuards derives all physical mirrors from a validated logical batch.
// No variant is discarded; this is not proof of translated packet correlation.
// Cohort and observed addresses remain permanent when leased grants are flushed.
func prepareGuards(ctx context.Context, source *preparedBatch) (*preparedGuardBatch, error) {
	return prepareGuardsWithClassification(ctx, source, nil)
}

func prepareGuardsWithClassification(
	ctx context.Context,
	source *preparedBatch,
	classification *state.Classification,
) (*preparedGuardBatch, error) {
	if ctx == nil || source == nil {
		return nil, errors.New("firewall: missing guarded transaction or context")
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if err := validateBatch(source.data); err != nil {
		return nil, err
	}
	var owned *state.Classification
	if classification != nil {
		value, err := state.CloneClassification(*classification)
		if err != nil {
			return nil, errors.New("firewall: invalid historical classification")
		}
		owned = &value
	}
	data, err := expandGuardBatchWithClassification(ctx, source.data, owned)
	if err != nil {
		return nil, err
	}
	prepared := *source
	prepared.data = data
	return &preparedGuardBatch{batch: prepared, classification: owned}, nil
}

func expandGuardBatch(ctx context.Context, source []byte) ([]byte, error) {
	return expandGuardBatchWithClassification(ctx, source, nil)
}

func expandGuardBatchWithClassification(
	ctx context.Context,
	source []byte,
	classification *state.Classification,
) ([]byte, error) {
	if ctx == nil {
		return nil, errors.New("firewall: missing guard expansion context")
	}
	if err := validateBatch(source); err != nil {
		return nil, err
	}
	var original guardChanges
	if err := json.Unmarshal(source, &original); err != nil {
		return nil, errors.New("firewall: invalid logical guard input")
	}
	if classification != nil {
		var err error
		original, err = classifyGuardChanges(ctx, original, *classification)
		if err != nil {
			return nil, err
		}
	}
	commands := make([]change, 0, 6*len(grantSets)+4)
	for _, name := range grantSets {
		for _, ref := range guardLeaseRefs(name) {
			commands = append(commands, change{Flush: &setChange{Set: ref}})
		}
	}
	addresses := map[string]map[string]bool{classified4Set: {}, classified6Set: {}}
	if classification != nil {
		for index, name := range []string{classified4Set, classified6Set} {
			values := classification.IPv4
			if index == 1 {
				values = classification.IPv6
			}
			for _, value := range values {
				if err := ctx.Err(); err != nil {
					return nil, err
				}
				encoded, err := json.Marshal(value)
				if err != nil {
					return nil, errors.New("firewall: historical address encoding failed")
				}
				addresses[name][string(encoded)] = true
			}
		}
	}
	leases := make([]change, 0)
	for _, command := range original.Commands {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		if command.Add == nil {
			continue
		}
		values := command.Add.Element
		if values.Name == cohortSet {
			commands = append(commands, command, guardAdd("netdev", cohortSet, values.Values))
			continue
		}
		projections := map[string]guardProjection{}
		for _, raw := range values.Values {
			if err := ctx.Err(); err != nil {
				return nil, err
			}
			tuple, err := validateLeasedTuple(raw, ipv4Set(values.Name))
			if err != nil {
				return nil, err
			}
			var element struct {
				Element struct {
					Timeout int `json:"timeout"`
					Value   struct {
						Concat []json.RawMessage `json:"concat"`
					} `json:"val"`
				} `json:"elem"`
			}
			if err := json.Unmarshal(raw, &element); err != nil {
				return nil, errors.New("firewall: guarded element decoding failed")
			}
			// Deduplicate decoded typed values, not their JSON spelling. Escaped
			// strings or whitespace must not create duplicate kernel projections.
			projection := []any{tuple.interfaceName, tuple.device.String(), tuple.peer.String(), tuple.port}
			key, err := json.Marshal(projection)
			if err != nil {
				return nil, errors.New("firewall: guard projection encoding failed")
			}
			projected, err := json.Marshal(map[string]any{"elem": map[string]any{
				"timeout": element.Element.Timeout, "val": map[string]any{"concat": projection},
			}})
			if err != nil {
				return nil, errors.New("firewall: guarded lease encoding failed")
			}
			if old, exists := projections[string(key)]; exists && old.timeout >= element.Element.Timeout {
				continue
			}
			projections[string(key)] = guardProjection{value: projected, timeout: element.Element.Timeout}
			set := classified6Set
			if ipv4Set(values.Name) {
				set = classified4Set
			}
			address, err := json.Marshal(tuple.device.String())
			if err != nil {
				return nil, errors.New("firewall: classified address encoding failed")
			}
			addresses[set][string(address)] = true
		}
		keys := make([]string, 0, len(projections))
		for key := range projections {
			keys = append(keys, key)
		}
		slices.Sort(keys)
		projected := make([]json.RawMessage, 0, len(keys))
		for _, key := range keys {
			projected = append(projected, projections[key].value)
		}
		leases = append(leases, command,
			guardAdd("inet", inboundSet(values.Name), projected),
			guardAdd("netdev", egressSet(values.Name), values.Values))
	}
	for _, name := range []string{classified4Set, classified6Set} {
		keys := make([]string, 0, len(addresses[name]))
		for key := range addresses[name] {
			keys = append(keys, key)
		}
		slices.Sort(keys)
		values := make([]json.RawMessage, 0, len(keys))
		for _, key := range keys {
			values = append(values, json.RawMessage(key))
		}
		if len(values) != 0 {
			commands = append(commands, guardAdd("inet", name, values))
		}
	}
	commands = append(commands, leases...)
	data, err := json.Marshal(struct {
		Commands []change `json:"nftables"`
	}{Commands: commands})
	if err != nil || len(data) > maximumBatch {
		return nil, errors.New("firewall: guarded transaction encoding or quota failed")
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return data, nil
}

// validateGuardBatch reconstructs the only permitted mirrors from the logical
// full tuples. Extra operations, permanent-set removal, missing/mismatched
// mirrors, altered timeouts and arbitrary object changes cannot be admitted.
func validateGuardBatch(ctx context.Context, data []byte) error {
	return validateGuardBatchWithClassification(ctx, data, nil)
}

func validateGuardBatchWithClassification(
	ctx context.Context,
	data []byte,
	classification *state.Classification,
) error {
	if ctx == nil {
		return errors.New("firewall: missing guard validation context")
	}
	decoded, err := decodeGuardChanges(data)
	if err != nil {
		return err
	}
	logical := make([]change, 0)
	for _, command := range decoded.Commands {
		if command.Flush != nil && ownedReference(command.Flush.Set) && isGrantSet(command.Flush.Set.Name) {
			logical = append(logical, command)
		}
		if command.Add != nil {
			ref := command.Add.Element
			if ref.Family == "inet" && ref.Table == ownedTable && (isGrantSet(ref.Name) || ref.Name == cohortSet) {
				logical = append(logical, command)
			}
		}
	}
	source, err := json.Marshal(struct {
		Commands []change `json:"nftables"`
	}{Commands: logical})
	if err != nil {
		return errors.New("firewall: guard reconstruction failed")
	}
	if err := validateBatch(source); err != nil {
		return err
	}
	expected, err := expandGuardBatchWithClassification(ctx, source, classification)
	if err != nil {
		return err
	}
	canonical, err := canonicalGuardJSON(data)
	if err != nil {
		return err
	}
	expectedCanonical, err := canonicalGuardJSON(expected)
	if err != nil || !bytes.Equal(canonical, expectedCanonical) {
		return errors.New("firewall: guard mirrors or permanent classification differ")
	}
	return nil
}

// Compare semantic JSON, including RawMessage elements: ordering a tuple's
// object keys differently cannot change its scope or create a different mirror.
// UseNumber keeps numeric input exact, without a float conversion.
func canonicalGuardJSON(data []byte) ([]byte, error) {
	var value any
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.UseNumber()
	if err := decoder.Decode(&value); err != nil {
		return nil, errors.New("firewall: guard normalization failed")
	}
	canonical, err := json.Marshal(value)
	if err != nil {
		return nil, errors.New("firewall: guard normalized encoding failed")
	}
	return canonical, nil
}

func guardLeaseRefs(name string) []objectReference {
	return []objectReference{ownedRef(name), ownedRef(inboundSet(name)),
		{Family: "netdev", Table: ownedTable, Name: egressSet(name)}}
}

func guardAdd(family, name string, values []json.RawMessage) change {
	return change{Add: &elementChange{Element: elements{
		Family: family, Table: ownedTable, Name: name, Values: values,
	}}}
}

func decodeGuardChanges(data []byte) (guardChanges, error) {
	if err := strictjson.Object(data, []string{"nftables"}, nil, maximumBatch); err != nil {
		return guardChanges{}, err
	}
	var raw struct {
		Commands []json.RawMessage `json:"nftables"`
	}
	if err := strictjson.Decode(data, &raw, maximumBatch); err != nil {
		return guardChanges{}, err
	}
	if len(raw.Commands) < 3*len(grantSets) || len(raw.Commands) > 6*len(grantSets)+4 {
		return guardChanges{}, errors.New("firewall: guarded transaction size invalid")
	}
	decoded := guardChanges{Commands: make([]change, 0, len(raw.Commands))}
	for _, command := range raw.Commands {
		if err := strictjson.Object(command, nil, []string{"flush", "add"}, maximumBatch); err != nil {
			return guardChanges{}, err
		}
		object := map[string]json.RawMessage{}
		if err := strictjson.Decode(command, &object, maximumBatch); err != nil || len(object) != 1 {
			return guardChanges{}, errors.New("firewall: exact guarded operation required")
		}
		if value, exists := object["flush"]; exists {
			var ref objectReference
			if err := decodeNested(value, "set", &ref, []string{"family", "table", "name"}); err != nil {
				return guardChanges{}, err
			}
			decoded.Commands = append(decoded.Commands, change{Flush: &setChange{Set: ref}})
			continue
		}
		var value elements
		if err := decodeNested(object["add"], "element", &value, []string{"family", "table", "name", "elem"}); err != nil {
			return guardChanges{}, err
		}
		decoded.Commands = append(decoded.Commands, change{Add: &elementChange{Element: value}})
	}
	return decoded, nil
}
