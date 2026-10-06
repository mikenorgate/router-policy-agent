//go:build integration && linux

package firewall

import (
	"context"
	"errors"
	"math"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"
)

func readGenerationFixture(t *testing.T, root *os.Root) writerGeneration {
	t.Helper()
	value, err := readWriterGeneration(t.Context(), root)
	if err != nil {
		t.Fatal(err)
	}
	return value
}

func assertNoTemporaryGenerations(t *testing.T, path string) {
	t.Helper()
	entries, err := os.ReadDir(path)
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		if strings.HasPrefix(entry.Name(), ".generation-") {
			t.Fatal("publication leaked an owner-only temporary file")
		}
	}
}

func TestGenerationTransitionDurableClosurePrecedesRevokeUpdateAndAudit(t *testing.T) {
	t.Parallel()
	gate, root, path := generationGateFixture(t)
	previous, target := writerGenerationFixture(), transitionTargetFixture()
	observer, err := openGenerationGate(t.Context(), path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.WithoutCancel(t.Context()), 3*time.Second)
		defer cancel()
		if err := observer.close(ctx); err != nil {
			t.Error(err)
		}
	})
	steps := []string{}
	checkClosed := func(ctx context.Context) error {
		actual := readGenerationFixture(t, root)
		want := previous
		want.Sequence++
		want.Ready = false
		if actual != want {
			return errors.New("synthetic update ran without its exact closed generation")
		}
		short, cancel := context.WithTimeout(ctx, 20*time.Millisecond)
		defer cancel()
		called := false
		err := observer.with(short, previous, func(context.Context) error { called = true; return nil })
		if !errors.Is(err, context.DeadlineExceeded) || called {
			return errors.New("synthetic observer bypassed the owning transition fence")
		}
		return nil
	}
	operations := transitionSteps{
		revoke: func(ctx context.Context) error { steps = append(steps, "revoke"); return checkClosed(ctx) },
		update: func(ctx context.Context) error {
			if !slices.Equal(steps, []string{"revoke"}) {
				return errors.New("synthetic update preceded revocation")
			}
			steps = append(steps, "update")
			return checkClosed(ctx)
		},
		audit: func(ctx context.Context) (generationTarget, error) {
			steps = append(steps, "audit")
			return target, checkClosed(ctx)
		},
	}
	ready, err := gate.transition(
		t.Context(),
		previous,
		target,
		operations,
	)
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(steps, []string{"revoke", "update", "audit"}) || ready.Sequence != previous.Sequence+2 {
		t.Fatal("transition lost its ordering or sequence")
	}
	if actual := readGenerationFixture(t, root); actual != ready {
		t.Fatal("successful transition did not publish its exact ready vector")
	}
	if err := observer.with(t.Context(), previous, func(context.Context) error { return nil }); err == nil {
		t.Fatal("old authorization generation survived the owning transition")
	}
	if err := observer.with(t.Context(), ready, func(context.Context) error { return nil }); err != nil {
		t.Fatal("new audited generation was not available after the writer released")
	}
	assertNoTemporaryGenerations(t, path)
}

func TestGenerationTransitionFailureStopsLaterStagesAndRetainsClosure(t *testing.T) {
	t.Parallel()
	for _, failure := range []string{
		"revoke", "update", "audit", "wrong floor", "wrong mapping", "invalid audit", "cancel revoke", "cancel update",
	} {
		t.Run(failure, func(t *testing.T) {
			t.Parallel()
			gate, root, path := generationGateFixture(t)
			previous, target := writerGenerationFixture(), transitionTargetFixture()
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			marker := errors.New("synthetic owning writer failure")
			stages := []string{}
			step := func(name string) error {
				stages = append(stages, name)
				if failure == "cancel "+name {
					cancel()
				}
				if failure == name {
					return marker
				}
				return nil
			}
			operations := transitionSteps{
				revoke: func(context.Context) error { return step("revoke") },
				update: func(context.Context) error { return step("update") },
				audit: func(context.Context) (generationTarget, error) {
					observed := target
					switch failure {
					case "wrong floor":
						observed.FloorHash = target.MappingHash
					case "wrong mapping":
						observed.MappingHash = target.FloorHash
					case "invalid audit":
						observed.FloorHash = "invalid"
					}
					return observed, step("audit")
				},
			}
			ready, err := gate.transition(
				ctx,
				previous,
				target,
				operations,
			)
			if err == nil || ready != (writerGeneration{}) {
				t.Fatal("failed transition returned successful coordination state")
			}
			wanted := []string{"revoke", "update", "audit"}
			switch failure {
			case "revoke", "cancel revoke":
				wanted = wanted[:1]
			case "update", "cancel update":
				wanted = wanted[:2]
			}
			if !slices.Equal(stages, wanted) {
				t.Fatal("failed owning step reached a later transition stage")
			}
			if failure == "revoke" || failure == "update" || failure == "audit" {
				if !errors.Is(err, marker) {
					t.Fatal("owning callback failure was lost")
				}
			}
			pending := readGenerationFixture(t, root)
			if pending.Ready || pending.Sequence != previous.Sequence+1 {
				t.Fatal("ordinary failure reopened readiness or reset the sequence")
			}
			assertNoTemporaryGenerations(t, path)
		})
	}
}

func TestGenerationTransitionRequiresExplicitFreshRecoveryAfterRestart(t *testing.T) {
	t.Parallel()
	gate, root, path := generationGateFixture(t)
	previous, target, operations := writerGenerationFixture(), transitionTargetFixture(), transitionStepsFixture()
	operations.update = func(context.Context) error { return errors.New("synthetic interrupted update") }
	_, err := gate.transition(
		t.Context(),
		previous,
		target,
		operations,
	)
	if err == nil {
		t.Fatal("interrupted transition succeeded")
	}
	pending := readGenerationFixture(t, root)
	if err := gate.close(t.Context()); err != nil {
		t.Fatal(err)
	}
	restarted, err := openGenerationGate(t.Context(), path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.WithoutCancel(t.Context()), 3*time.Second)
		defer cancel()
		if err := restarted.close(ctx); err != nil {
			t.Error(err)
		}
	})
	called := false
	if err := restarted.with(t.Context(), previous, func(context.Context) error { called = true; return nil }); err == nil || called {
		t.Fatal("restart restored old readiness")
	}
	_, err = restarted.transition(
		t.Context(),
		pending,
		target,
		transitionStepsFixture(),
	)
	if err == nil {
		t.Fatal("normal transition silently recovered closed state")
	}
	stages := []string{}
	operations = transitionSteps{
		revoke: func(context.Context) error { stages = append(stages, "revoke"); return nil },
		update: func(context.Context) error { stages = append(stages, "update"); return nil },
		audit: func(context.Context) (generationTarget, error) {
			stages = append(stages, "audit")
			return target, nil
		},
	}
	ready, err := restarted.recoverTransition(
		t.Context(),
		pending,
		target,
		operations,
	)
	if err != nil {
		t.Fatal(err)
	}
	if ready.Sequence != pending.Sequence+2 || !slices.Equal(stages, []string{"revoke", "update", "audit"}) {
		t.Fatal("explicit recovery did not requalify through fresh increasing stages")
	}
	_, err = restarted.recoverTransition(
		t.Context(),
		previous,
		target,
		operations,
	)
	if err == nil {
		t.Fatal("recovery accepted an old ready vector")
	}
}

func TestGenerationTransitionRejectsMissingStaleAndExhaustedStateBeforeCallbacks(t *testing.T) {
	t.Parallel()
	for _, name := range []string{"missing", "malformed", "stale", "exhausted", "canceled", "nil context", "nil gate"} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			gate, root, path := generationGateFixture(t)
			previous, target := writerGenerationFixture(), transitionTargetFixture()
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			switch name {
			case "missing":
				if err := root.Remove(writerGenerationFile); err != nil {
					t.Fatal(err)
				}
			case "malformed":
				if err := root.WriteFile(writerGenerationFile, []byte(`{"ready":true}`), 0o600); err != nil {
					t.Fatal(err)
				}
			case "stale":
				previous.Sequence++
			case "exhausted":
				previous.Sequence = math.MaxUint64
			case "canceled":
				cancel()
			case "nil context":
				ctx = nil // Invalid input must reject, not become a background request.
			case "nil gate":
				gate = nil
			}
			called := false
			operations := transitionSteps{
				revoke: func(context.Context) error { called = true; return nil },
				update: func(context.Context) error { called = true; return nil },
				audit:  func(context.Context) (generationTarget, error) { called = true; return target, nil },
			}
			ready, err := gate.transition(
				ctx,
				previous,
				target,
				operations,
			)
			unsafeSuccess := err == nil || ready != (writerGeneration{})
			if unsafeSuccess || called {
				t.Fatal("unsafe transition reached an owning callback or returned a ready vector")
			}
			assertNoTemporaryGenerations(t, path)
		})
	}
}

func TestGenerationPublicationRejectsInvalidAndFailedReplacement(t *testing.T) {
	t.Parallel()
	_, root, path := generationGateFixture(t)
	previous := writerGenerationFixture()
	if err := writeWriterGeneration(t.Context(), root, writerGeneration{}); err == nil {
		t.Fatal("invalid state was published")
	}
	if actual := readGenerationFixture(t, root); actual != previous {
		t.Fatal("invalid publication changed existing state")
	}
	if err := root.Rename(writerGenerationFile, "original.json"); err != nil {
		t.Fatal(err)
	}
	if err := root.Mkdir(writerGenerationFile, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := writeWriterGeneration(t.Context(), root, previous); err == nil {
		t.Fatal("failed fixed-name replacement succeeded")
	}
	assertNoTemporaryGenerations(t, path)
}

func TestGenerationTransitionRejectsRecordDriftBetweenEveryStage(t *testing.T) {
	t.Parallel()
	for _, stage := range []string{"revoke", "update", "audit"} {
		t.Run(stage, func(t *testing.T) {
			t.Parallel()
			gate, root, path := generationGateFixture(t)
			previous, target := writerGenerationFixture(), transitionTargetFixture()
			foreign := previous
			foreign.Sequence += 7
			foreign.Ready = false
			stages := []string{}
			step := func(name string) {
				stages = append(stages, name)
				if name == stage {
					// Deliberately violate the cooperative-writer contract. The
					// coordinator must detect this, not overwrite the new record.
					writeGenerationFixture(t, root, foreign)
				}
			}
			operations := transitionSteps{
				revoke: func(context.Context) error { step("revoke"); return nil },
				update: func(context.Context) error { step("update"); return nil },
				audit: func(context.Context) (generationTarget, error) {
					step("audit")
					return target, nil
				},
			}
			ready, err := gate.transition(
				t.Context(),
				previous,
				target,
				operations,
			)
			if err == nil || ready != (writerGeneration{}) {
				t.Fatal("record drift returned a successful coordination vector")
			}
			want := []string{"revoke", "update", "audit"}
			switch stage {
			case "revoke":
				want = want[:1]
			case "update":
				want = want[:2]
			}
			if !slices.Equal(stages, want) {
				t.Fatal("record drift reached a later owning stage")
			}
			if actual := readGenerationFixture(t, root); actual != foreign {
				t.Fatal("record drift was overwritten with the coordinator's target")
			}
			assertNoTemporaryGenerations(t, path)
		})
	}
}

func TestGenerationTransitionReportsFenceFailureAfterVisiblePublication(t *testing.T) {
	t.Parallel()
	gate, root, path := generationGateFixture(t)
	previous, target := writerGenerationFixture(), transitionTargetFixture()
	moved := filepath.Join(t.TempDir(), "moved-coordination")
	operations := transitionStepsFixture()
	operations.audit = func(context.Context) (generationTarget, error) {
		// The pinned descriptor remains usable, but its configured path now
		// names another directory. Only the final fence check observes this.
		if err := os.Rename(path, moved); err != nil {
			return generationTarget{}, err
		}
		if err := os.Mkdir(path, 0o700); err != nil {
			return generationTarget{}, err
		}
		return target, nil
	}
	ready, err := gate.transition(
		t.Context(),
		previous,
		target,
		operations,
	)
	if err == nil || ready != (writerGeneration{}) {
		t.Fatal("post-publication fence failure returned a successful vector")
	}
	actual := readGenerationFixture(t, root)
	want := writerGeneration{
		SchemaVersion: 1, Sequence: previous.Sequence + 2,
		FloorHash: target.FloorHash, MappingHash: target.MappingHash, Ready: true,
	}
	if actual != want {
		t.Fatal("fixture did not exercise the visible-publication failure boundary")
	}
	called := false
	err = gate.with(t.Context(), actual, func(context.Context) error { called = true; return nil })
	if err == nil || called {
		t.Fatal("replaced fence permitted a callback despite its invalid identity")
	}
	assertNoTemporaryGenerations(t, moved)
}
