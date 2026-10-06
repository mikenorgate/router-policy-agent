package firewall

import (
	"context"
	"errors"
	"math"
)

// generationTarget contains only hashes of owner-reviewed state. It is not a
// map request, a directory policy, or proof that the named state is installed.
type generationTarget struct {
	FloorHash   string
	MappingHash string
}

func (g generationTarget) validate() error {
	if !generationHash(g.FloorHash) || !generationHash(g.MappingHash) {
		return errors.New("firewall: invalid generation target")
	}
	return nil
}

// transitionSteps must come from the owning privileged writer and independent
// auditor, never from IPC. Revoke withdraws old application permits and affected
// owned counterparts without removing classification or unrelated state.
// Update cannot grant application permission. Audit must observe actual paths,
// not echo the requested hashes. All steps must honor their inherited context.
// These hooks are not wired to production writers or a qualified auditor yet.
type transitionSteps struct {
	revoke func(context.Context) error
	update func(context.Context) error
	audit  func(context.Context) (generationTarget, error)
}

func (s transitionSteps) validate() error {
	hasMutationSteps := s.revoke != nil && s.update != nil
	if !hasMutationSteps || s.audit == nil {
		return errors.New("firewall: missing writer transition steps")
	}
	return nil
}

type generationTransition struct {
	previous writerGeneration
	pending  writerGeneration
	ready    writerGeneration
	steps    transitionSteps
}

func prepareGenerationTransition(
	previous writerGeneration,
	target generationTarget,
	steps transitionSteps,
) (generationTransition, error) {
	if err := previous.validate(); err != nil {
		return generationTransition{}, err
	}
	if err := target.validate(); err != nil {
		return generationTransition{}, err
	}
	if err := steps.validate(); err != nil {
		return generationTransition{}, err
	}
	// Reserve both increments before any write or callback. Neither closure nor
	// reopening may wrap, reuse a sequence, or reset it to recover capacity.
	if previous.Sequence > math.MaxUint64-2 {
		return generationTransition{}, errors.New("firewall: writer generation sequence exhausted")
	}
	pending := previous
	pending.Sequence++
	pending.Ready = false
	ready := writerGeneration{
		SchemaVersion: 1, Sequence: previous.Sequence + 2,
		FloorHash: target.FloorHash, MappingHash: target.MappingHash, Ready: true,
	}
	return generationTransition{previous: previous, pending: pending, ready: ready, steps: steps}, nil
}
