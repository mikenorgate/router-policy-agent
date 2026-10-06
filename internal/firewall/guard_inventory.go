package firewall

import (
	"context"
	"encoding/json"
	"errors"
	"net/netip"
	"slices"

	"github.com/mikenorgate/router-policy-agent/internal/state"
)

func (inventory *guardInventory) checkMirrors(
	ctx context.Context,
	inet, netdev *guardTableObservation,
) error {
	logical := guardChanges{Commands: make([]change, 0, 2*len(grantSets)+1)}
	for _, name := range grantSets {
		logical.Commands = append(logical.Commands, change{Flush: &setChange{Set: ownedRef(name)}})
	}
	if cohort := inet.sets[cohortSet].Elements; len(cohort) != 0 {
		logical.Commands = append(logical.Commands, guardAdd("inet", cohortSet, cohort))
	}
	for _, name := range grantSets {
		values, err := listedGuardLeases(ctx, inet.sets[name].Elements)
		if err != nil {
			return err
		}
		inventory.leases += len(values)
		if len(values) != 0 {
			logical.Commands = append(logical.Commands, guardAdd("inet", name, values))
		}
	}
	source, err := json.Marshal(logical)
	if err != nil {
		return errors.New("firewall: guarded observation reconstruction failed")
	}
	if err := (&setInventory{cohort: inventory.cohort}).checkReplacement(ctx, source); err != nil {
		return err
	}
	if err := inventory.checkInterfaces(ctx, logical.Commands); err != nil {
		return err
	}
	expanded, err := expandGuardBatch(ctx, source)
	if err != nil {
		return err
	}
	expected, err := decodeGuardChanges(expanded)
	if err != nil {
		return err
	}
	wanted := map[objectReference][]json.RawMessage{}
	for _, command := range expected.Commands {
		if command.Add != nil {
			value := command.Add.Element
			wanted[objectReference{Family: value.Family, Table: value.Table, Name: value.Name}] = value.Values
		}
	}
	for _, name := range grantSets {
		for _, ref := range guardLeaseRefs(name) {
			observation := inet
			if ref.Family == "netdev" {
				observation = netdev
			}
			actual, err := listedGuardLeases(ctx, observation.sets[ref.Name].Elements)
			if err != nil {
				return err
			}
			if err := sameGuardElements(ctx, actual, wanted[ref]); err != nil {
				return err
			}
		}
	}
	return inventory.checkAddressAdditions(ctx, wanted, false)
}

// Kernel expiry counters are observations, not refreshed lease deadlines.
// Listings of different tables need not have equal remaining seconds. Require
// identical tuple/timeout mirrors; an expiry-boundary mismatch fails closed and
// can be retried without treating either observation as new authorization.
func listedGuardLeases(ctx context.Context, elements []json.RawMessage) ([]json.RawMessage, error) {
	values := make([]json.RawMessage, 0, len(elements))
	for _, raw := range elements {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		var element struct {
			Value   json.RawMessage `json:"val"`
			Timeout int             `json:"timeout"`
			Expires uint64          `json:"expires"`
		}
		if err := decodeNested(raw, "elem", &element, []string{"val", "timeout", "expires"}); err != nil {
			return nil, err
		}
		if element.Timeout < 1 || element.Timeout > maximumElementLifetime {
			return nil, errors.New("firewall: invalid guarded lease observation")
		}
		if element.Expires > uint64(element.Timeout) {
			return nil, errors.New("firewall: invalid guarded lease observation")
		}
		value, err := json.Marshal(map[string]any{"elem": map[string]any{
			"val": element.Value, "timeout": element.Timeout,
		}})
		if err != nil {
			return nil, errors.New("firewall: guarded lease observation encoding failed")
		}
		values = append(values, value)
	}
	return values, nil
}

func sameGuardElements(ctx context.Context, actual, expected []json.RawMessage) error {
	if len(actual) != len(expected) {
		return errors.New("firewall: guarded lease mirrors differ")
	}
	normalized := make([][]string, 0, 2)
	for _, elements := range [][]json.RawMessage{actual, expected} {
		values := make([]string, 0, len(elements))
		for _, raw := range elements {
			if err := ctx.Err(); err != nil {
				return err
			}
			value, err := canonicalGuardJSON(raw)
			if err != nil {
				return err
			}
			values = append(values, string(value))
		}
		slices.Sort(values)
		normalized = append(normalized, values)
	}
	if !slices.Equal(normalized[0], normalized[1]) {
		return errors.New("firewall: guarded lease mirrors differ")
	}
	return nil
}

func (inventory *guardInventory) checkInterfaces(ctx context.Context, commands []change) error {
	for _, command := range commands {
		if command.Add == nil || !isGrantSet(command.Add.Element.Name) || command.Add.Element.Family != "inet" {
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
			if _, exists := slices.BinarySearch(inventory.managedInterfaces, key.interfaceName); !exists {
				return errors.New("firewall: guarded lease outside managed interfaces")
			}
		}
	}
	return ctx.Err()
}

func (inventory *guardInventory) checkReplacement(ctx context.Context, data []byte) error {
	return inventory.checkGuardReplacement(ctx, data, nil)
}

// checkPreparedReplacement accepts historical additions only against the
// owned, validated state retained by preparation. The raw set-only path still
// cannot admit them, and this inspection is not a privileged writer fence.
func (inventory *guardInventory) checkPreparedReplacement(ctx context.Context, prepared *preparedGuardBatch) error {
	if prepared == nil {
		return errors.New("firewall: missing prepared guarded replacement")
	}
	return inventory.checkGuardReplacement(ctx, prepared.batch.data, prepared.classification)
}

func (inventory *guardInventory) checkGuardReplacement(
	ctx context.Context,
	data []byte,
	classification *state.Classification,
) error {
	if inventory == nil || ctx == nil {
		return errors.New("firewall: missing guarded replacement dependencies")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := validateGuardBatchWithClassification(ctx, data, classification); err != nil {
		return err
	}
	guarded, err := decodeGuardChanges(data)
	if err != nil {
		return err
	}
	logical := guardChanges{Commands: make([]change, 0)}
	additions := map[objectReference][]json.RawMessage{}
	for _, command := range guarded.Commands {
		if command.Flush != nil && ownedReference(command.Flush.Set) && isGrantSet(command.Flush.Set.Name) {
			logical.Commands = append(logical.Commands, command)
		}
		if command.Add != nil {
			value := command.Add.Element
			ref := objectReference{Family: value.Family, Table: value.Table, Name: value.Name}
			additions[ref] = value.Values
			if ownedReference(ref) && (isGrantSet(ref.Name) || ref.Name == cohortSet) {
				logical.Commands = append(logical.Commands, command)
			}
		}
	}
	source, err := json.Marshal(logical)
	if err != nil {
		return errors.New("firewall: guarded replacement reconstruction failed")
	}
	if err := (&setInventory{cohort: inventory.cohort}).checkReplacement(ctx, source); err != nil {
		return err
	}
	if err := inventory.checkInterfaces(ctx, logical.Commands); err != nil {
		return err
	}
	return inventory.checkAddressAdditions(ctx, additions, true)
}

func (inventory *guardInventory) checkAddressAdditions(
	ctx context.Context,
	additions map[objectReference][]json.RawMessage,
	canAppend bool,
) error {
	for _, family := range []struct {
		name      string
		ipv4      bool
		addresses []netip.Addr
	}{
		{name: classified4Set, ipv4: true, addresses: inventory.addresses4},
		{name: classified6Set, addresses: inventory.addresses6},
	} {
		seen := make(map[netip.Addr]bool, len(family.addresses))
		for _, address := range family.addresses {
			seen[address] = true
		}
		addresses, err := listedGuardAddresses(ctx, additions[ownedRef(family.name)], family.ipv4)
		if err != nil {
			return err
		}
		for _, address := range addresses {
			if !canAppend && !seen[address] {
				return errors.New("firewall: guarded lease lacks permanent address classification")
			}
			seen[address] = true
		}
		if len(seen) > maximumTupleCount {
			return errors.New("firewall: permanent address capacity exceeded")
		}
	}
	return ctx.Err()
}
