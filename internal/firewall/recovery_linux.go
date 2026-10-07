package firewall

import (
	"context"
	"errors"
	"time"

	"github.com/mikenorgate/router-policy-agent/internal/state"
)

// Recover revokes only the existing agent-owned application leases and restores
// validated deny-only history. It requires root, checked private configuration,
// an exclusive persistent-state lock and the existing guard schema. A running
// helper must be stopped separately; Recover never stops it or changes sockets.
// It cannot restore grants, reset state, repair baseline rules, change routes or
// flush conntrack. Success verifies sealing, not the external protected floor.
func Recover(ctx context.Context, directory string) (result error) {
	config, err := loadHelperConfig(ctx, directory)
	if err != nil {
		return err
	}
	resources, err := openConfiguredOwner(ctx, config)
	if err != nil {
		return err
	}
	history := state.EmptyClassification()
	defer func() {
		// No service was constructed, so no writer can race these resources.
		// Cancellation or a failed inspection must not skip the bounded final
		// revocation attempt. Closing happens only after that attempt returns.
		if result != nil {
			sealErr := func() error {
				revocation, cancel := context.WithTimeout(context.WithoutCancel(ctx), 2*time.Second)
				defer cancel()
				return resources.backend.seal(revocation, history)
			}()
			result = errors.Join(result, sealErr)
		}
		cleanup, cancel := context.WithTimeout(context.WithoutCancel(ctx), 2*time.Second)
		defer cancel()
		result = errors.Join(result, resources.close(cleanup))
		if result != nil {
			result = profileFailure("recovery incomplete", result)
		}
	}()
	// Withdraw current leases before attempting to read durable history. Even
	// missing/corrupt history must not prevent sealing valid existing guards;
	// it still makes recovery unsuccessful and is never repaired or reset.
	if err := resources.backend.seal(ctx, history); err != nil {
		return err
	}
	document, err := resources.store.Load(ctx)
	if err != nil {
		return err
	}
	saved, err := state.Classifiers(document)
	if err != nil {
		return err
	}
	history = saved
	return resources.backend.seal(ctx, history)
}
