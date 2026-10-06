package firewall

import (
	"context"
	"errors"
	"os"
)

// transition is an owning-writer operation, never a reader/helper request. It
// closes readiness durably before revocation, changes owned state only after
// revocation, and publishes a new vector only after matching audit observations.
// It never creates missing state or restores permits. Publication/post-fence
// failures can be indeterminate: callers must keep permits sealed and re-audit,
// not assume metadata or externally changed state rolled back.
func (g *generationGate) transition(
	ctx context.Context,
	previous writerGeneration,
	target generationTarget,
	steps transitionSteps,
) (writerGeneration, error) {
	if !previous.Ready {
		return writerGeneration{}, errors.New("firewall: normal transition requires ready state")
	}
	return g.change(
		ctx,
		previous,
		target,
		steps,
	)
}

// recoverTransition is a separate, explicit owning-writer recovery path. A
// closed record never reopens just because it can be parsed. Recovery repeats
// revocation, the idempotent owned update and an actual independent audit, with
// new sequences. An older ready vector cannot be restored through this path.
func (g *generationGate) recoverTransition(
	ctx context.Context,
	previous writerGeneration,
	target generationTarget,
	steps transitionSteps,
) (writerGeneration, error) {
	if previous.Ready {
		return writerGeneration{}, errors.New("firewall: recovery requires closed state")
	}
	return g.change(
		ctx,
		previous,
		target,
		steps,
	)
}

func (g *generationGate) change(
	ctx context.Context,
	previous writerGeneration,
	target generationTarget,
	steps transitionSteps,
) (writerGeneration, error) {
	missingGate := g == nil || g.fence == nil
	if missingGate || ctx == nil {
		return writerGeneration{}, errors.New("firewall: missing writer transition dependencies")
	}
	prepared, err := prepareGenerationTransition(previous, target, steps)
	if err != nil {
		return writerGeneration{}, err
	}
	err = g.fence.With(ctx, func(bounded context.Context, root *os.Root) error {
		if err := checkTransitionRecord(bounded, root, prepared.previous); err != nil {
			return err
		}
		if err := writeWriterGeneration(bounded, root, prepared.pending); err != nil {
			return err
		}
		if err := prepared.run(bounded, root); err != nil {
			return err
		}
		return writeWriterGeneration(bounded, root, prepared.ready)
	})
	if err != nil {
		return writerGeneration{}, err
	}
	return prepared.ready, nil
}

func checkTransitionRecord(ctx context.Context, root *os.Root, expected writerGeneration) error {
	actual, err := readWriterGeneration(ctx, root)
	if err != nil {
		return err
	}
	if actual != expected {
		return errors.New("firewall: writer transition record differs")
	}
	return nil
}

func (t generationTransition) run(ctx context.Context, root *os.Root) error {
	if err := t.steps.revoke(ctx); err != nil {
		return err
	}
	if err := checkTransitionRecord(ctx, root, t.pending); err != nil {
		return err
	}
	if err := t.steps.update(ctx); err != nil {
		return err
	}
	if err := checkTransitionRecord(ctx, root, t.pending); err != nil {
		return err
	}
	observed, err := t.steps.audit(ctx)
	if err != nil {
		return err
	}
	if err := observed.validate(); err != nil {
		return err
	}
	want := generationTarget{FloorHash: t.ready.FloorHash, MappingHash: t.ready.MappingHash}
	if observed != want {
		return errors.New("firewall: writer transition audit differs")
	}
	return checkTransitionRecord(ctx, root, t.pending)
}
