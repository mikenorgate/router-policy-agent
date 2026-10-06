package firewall

import (
	"context"
	"encoding/json"
	"errors"
	"slices"

	"github.com/mikenorgate/router-policy-agent/internal/state"
)

// prepareClassifiedGuards restores helper-owned historical classifiers as part
// of the fixed mirror replacement. History cannot create a lease: every logical
// lease still comes from the original renderer and keeps its preparation fence.
// Reader input and kernel listings are not authority for this state handoff.
func prepareClassifiedGuards(
	ctx context.Context,
	source *preparedBatch,
	classification state.Classification,
) (*preparedGuardBatch, error) {
	return prepareGuardsWithClassification(ctx, source, &classification)
}

// prepareGuardSeal clears every owned lease mirror and appends saved deny-only
// classifiers, even with no grants. It never flushes classification, changes
// rules, or invents an authorization clock. Execution requires fixed guard
// inspection and shared writer fencing, not an unchanged external floor.
// Production use still needs independent protection and boot qualification.
func prepareGuardSeal(ctx context.Context, classification state.Classification) (*preparedGuardBatch, error) {
	if ctx == nil {
		return nil, errors.New("firewall: missing sealing context")
	}
	commands := make([]change, 0, len(grantSets))
	for _, name := range grantSets {
		commands = append(commands, change{Flush: &setChange{Set: ownedRef(name)}})
	}
	data, err := json.Marshal(guardChanges{Commands: commands})
	if err != nil {
		return nil, errors.New("firewall: sealing transaction encoding failed")
	}
	return prepareClassifiedGuards(ctx, &preparedBatch{data: data}, classification)
}

// classifyGuardChanges requires all leased MAC/address identities to have been
// saved first. It adds the whole historical MAC cohort, not just the renderer's
// delta; duplicate kernel additions are idempotent and never remove history.
func classifyGuardChanges(
	ctx context.Context,
	logical guardChanges,
	classification state.Classification,
) (guardChanges, error) {
	if ctx == nil {
		return guardChanges{}, errors.New("firewall: missing historical classification context")
	}
	if err := ctx.Err(); err != nil {
		return guardChanges{}, err
	}
	owned, err := state.CloneClassification(classification)
	if err != nil {
		return guardChanges{}, errors.New("firewall: invalid historical classification")
	}
	flushes, leases := make([]change, 0, len(grantSets)), make([]change, 0, len(grantSets))
	for _, command := range logical.Commands {
		if err := ctx.Err(); err != nil {
			return guardChanges{}, err
		}
		if command.Flush != nil {
			flushes = append(flushes, command)
			continue
		}
		if command.Add == nil {
			return guardChanges{}, errors.New("firewall: missing historical classification operation")
		}
		value := command.Add.Element
		if value.Name == cohortSet {
			for _, raw := range value.Values {
				if err := ctx.Err(); err != nil {
					return guardChanges{}, err
				}
				var mac string
				if err := json.Unmarshal(raw, &mac); err != nil {
					return guardChanges{}, errors.New("firewall: invalid historical cohort delta")
				}
				if _, exists := slices.BinarySearch(owned.MACs, mac); !exists {
					return guardChanges{}, errors.New("firewall: cohort delta is absent from saved classification")
				}
			}
			continue
		}
		for _, raw := range value.Values {
			if err := ctx.Err(); err != nil {
				return guardChanges{}, err
			}
			tuple, err := validateLeasedTuple(raw, ipv4Set(value.Name))
			if err != nil {
				return guardChanges{}, err
			}
			addresses := owned.IPv6
			if tuple.device.Is4() {
				addresses = owned.IPv4
			}
			_, managedMAC := slices.BinarySearch(owned.MACs, tuple.mac)
			_, managedAddress := slices.BinarySearch(addresses, tuple.device.String())
			if !managedMAC || !managedAddress {
				return guardChanges{}, errors.New("firewall: leased identity is absent from saved classification")
			}
		}
		leases = append(leases, command)
	}
	if len(owned.MACs) != 0 {
		values := make([]json.RawMessage, 0, len(owned.MACs))
		for _, mac := range owned.MACs {
			if err := ctx.Err(); err != nil {
				return guardChanges{}, err
			}
			encoded, err := json.Marshal(mac)
			if err != nil {
				return guardChanges{}, errors.New("firewall: historical cohort encoding failed")
			}
			values = append(values, encoded)
		}
		flushes = append(flushes, guardAdd("inet", cohortSet, values))
	}
	return guardChanges{Commands: append(flushes, leases...)}, ctx.Err()
}

func validatePreparedGuardBatch(ctx context.Context, prepared *preparedGuardBatch) error {
	if prepared == nil {
		return errors.New("firewall: missing prepared guarded transaction")
	}
	return validateGuardBatchWithClassification(ctx, prepared.batch.data, prepared.classification)
}

// Sealing has no authorization clock and cannot contain any leased addition.
// Only fixed mirror flushes and permanent deny-only additions are admitted.
func validateGuardSeal(ctx context.Context, prepared *preparedGuardBatch) error {
	if err := validatePreparedGuardBatch(ctx, prepared); err != nil {
		return err
	}
	batch := prepared.batch
	if !batch.preparedAt.IsZero() || !batch.startBefore.IsZero() || !batch.startedAt.IsZero() {
		return errors.New("firewall: sealing cannot carry authorization preparation")
	}
	commands, err := decodeGuardChanges(batch.data)
	if err != nil {
		return err
	}
	for _, command := range commands.Commands {
		if err := ctx.Err(); err != nil {
			return err
		}
		if command.Add == nil {
			continue
		}
		name := command.Add.Element.Name
		if name != cohortSet && name != classified4Set && name != classified6Set {
			return errors.New("firewall: sealing cannot add a lease")
		}
	}
	return ctx.Err()
}
