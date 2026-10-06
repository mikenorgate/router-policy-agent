package firewall

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"math"
	"testing"
)

func transitionTargetFixture() generationTarget {
	value := writerGenerationFixture()
	mapping := sha256.Sum256([]byte("synthetic-next-translator-mappings"))
	return generationTarget{FloorHash: value.FloorHash, MappingHash: hex.EncodeToString(mapping[:])}
}

func transitionStepsFixture() transitionSteps {
	return transitionSteps{
		revoke: func(context.Context) error { return nil },
		update: func(context.Context) error { return nil },
		audit:  func(context.Context) (generationTarget, error) { return transitionTargetFixture(), nil },
	}
}

func TestPrepareGenerationTransitionReservesDistinctMonotonicVectors(t *testing.T) {
	t.Parallel()
	previous := writerGenerationFixture()
	target := transitionTargetFixture()
	prepared, err := prepareGenerationTransition(previous, target, transitionStepsFixture())
	if err != nil {
		t.Fatal(err)
	}
	lostOwningState := prepared.previous != previous
	invalidReadiness := prepared.pending.Ready || !prepared.ready.Ready
	if lostOwningState || invalidReadiness {
		t.Fatal("preparation lost the owning state or readiness ordering")
	}
	if prepared.pending.Sequence != previous.Sequence+1 || prepared.ready.Sequence != previous.Sequence+2 {
		t.Fatal("closure and reopening did not receive distinct increasing sequences")
	}
	if prepared.pending.FloorHash != previous.FloorHash || prepared.pending.MappingHash != previous.MappingHash {
		t.Fatal("closure claimed new hashes before the owning update")
	}
	if prepared.ready.FloorHash != target.FloorHash || prepared.ready.MappingHash != target.MappingHash {
		t.Fatal("ready vector lost the owner-reviewed target")
	}
}

func TestPrepareGenerationTransitionRejectsInvalidStateAndSteps(t *testing.T) {
	t.Parallel()
	for _, name := range []string{
		"invalid previous", "invalid target", "missing revoke", "missing update", "missing audit", "maximum", "one slot",
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			previous, target, steps := writerGenerationFixture(), transitionTargetFixture(), transitionStepsFixture()
			switch name {
			case "invalid previous":
				previous.Sequence = 0
			case "invalid target":
				target.FloorHash = "invalid"
			case "missing revoke":
				steps.revoke = nil
			case "missing update":
				steps.update = nil
			case "missing audit":
				steps.audit = nil
			case "maximum":
				previous.Sequence = math.MaxUint64
			case "one slot":
				previous.Sequence = math.MaxUint64 - 1
			}
			if _, err := prepareGenerationTransition(previous, target, steps); err == nil {
				t.Fatal("invalid or overflowing transition was prepared")
			}
		})
	}
}

func FuzzGenerationTransition(f *testing.F) {
	target := transitionTargetFixture()
	f.Add(
		uint64(1),
		true,
		target.FloorHash,
		target.MappingHash,
	)
	f.Add(
		uint64(math.MaxUint64),
		false,
		target.FloorHash,
		target.MappingHash,
	)
	f.Fuzz(func(t *testing.T, sequence uint64, ready bool, floor, mapping string) {
		previous := writerGenerationFixture()
		previous.Sequence, previous.Ready = sequence, ready
		candidate := generationTarget{FloorHash: floor, MappingHash: mapping}
		prepared, err := prepareGenerationTransition(previous, candidate, transitionStepsFixture())
		if err != nil {
			isZero := prepared.previous == (writerGeneration{}) && prepared.pending == (writerGeneration{})
			if !isZero || prepared.ready != (writerGeneration{}) {
				t.Fatal("invalid transition produced partial generation state")
			}
			return
		}
		if prepared.pending.Sequence <= sequence || prepared.ready.Sequence <= prepared.pending.Sequence {
			t.Fatal("accepted transition overflowed or reused a sequence")
		}
		invalidReadiness := prepared.pending.Ready || !prepared.ready.Ready
		if invalidReadiness || prepared.previous != previous {
			t.Fatal("accepted transition lost its owning state or readiness ordering")
		}
		if prepared.ready.FloorHash != floor || prepared.ready.MappingHash != mapping {
			t.Fatal("accepted transition widened or changed its reviewed target")
		}
	})
}
