package agent

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"slices"
	"testing"
	"testing/synctest"
	"time"

	"github.com/mikenorgate/router-policy-agent/internal/binding"
	"github.com/mikenorgate/router-policy-agent/internal/ipc"
	"github.com/mikenorgate/router-policy-agent/internal/policy"
	"github.com/mikenorgate/router-policy-agent/internal/state"
)

var errFixture = errors.New("synthetic backend failure")

type fixture struct {
	baseline   policy.Baseline
	directory  policy.DirectorySnapshot
	bindings   binding.Snapshot
	now        time.Time
	clockSetAt time.Time
	events     []string
	store      memoryState
	firewall   memoryFirewall
}

func newFixture(t *testing.T) *fixture {
	t.Helper()
	f := &fixture{}
	baseline, err := os.ReadFile("../../examples/baseline.json")
	if err != nil {
		t.Fatal(err)
	}
	f.baseline, err = policy.DecodeBaseline(baseline)
	if err != nil {
		t.Fatal(err)
	}
	directory, err := os.ReadFile("../../examples/directory.json")
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(directory, &f.directory); err != nil {
		t.Fatal(err)
	}
	bindings, err := os.ReadFile("../../examples/bindings.json")
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(bindings, &f.bindings); err != nil {
		t.Fatal(err)
	}
	f.now = f.directory.ObservedAt
	f.clockSetAt = time.Now()
	f.store = memoryState{document: state.Initial(), events: &f.events}
	f.firewall.events = &f.events
	return f
}

func (f *fixture) options(mode Mode) Options {
	options := Options{Mode: mode,
		State: Persistence{Load: f.store.load, Save: f.store.save}, Clock: f.utc,
		Bindings: func(ctx context.Context) (binding.Snapshot, error) {
			f.events = append(f.events, "bindings")
			return f.bindings, ctx.Err()
		},
	}
	if mode == Enforce {
		options.Firewall = Enforcement{Seal: f.firewall.seal, Apply: f.firewall.apply}
	}
	return options
}

func (f *fixture) engine(t *testing.T, options Options) *Engine {
	t.Helper()
	engine, err := New(f.baseline, options)
	if err != nil {
		t.Fatal(err)
	}
	if err := engine.Start(t.Context()); err != nil {
		t.Fatal(err)
	}
	if f.store.document.LastDirectoryObservedAt.IsZero() {
		// A real collector obtains initial ownership evidence after helper
		// startup. Keep normal tests on a running clock, not frozen UTC that
		// can trigger the rollback guard when a loaded test runner pauses.
		observed := f.utc()
		f.directory.ObservedAt = observed
		f.bindings.ObservedAt = observed
		for recordIndex := range f.bindings.Records {
			record := &f.bindings.Records[recordIndex]
			record.AssociatedAt = observed
			for addressIndex := range record.Addresses {
				record.Addresses[addressIndex].ObservedAt = observed
			}
		}
	}
	return engine
}

func (f *fixture) utc() time.Time {
	if f.now.IsZero() {
		return time.Time{}
	}
	return f.now.Add(time.Since(f.clockSetAt))
}

func (f *fixture) setUTC(now time.Time) {
	f.now, f.clockSetAt = now, time.Now()
}

type memoryState struct {
	document        state.Document
	events          *[]string
	loadError       error
	saves           int
	failSave        int
	advanceThenFail bool
}

func (store *memoryState) load(ctx context.Context) (state.Document, error) {
	*store.events = append(*store.events, "load")
	if err := errors.Join(ctx.Err(), store.loadError); err != nil {
		return state.Document{}, err
	}
	return state.Clone(store.document)
}

func (store *memoryState) save(ctx context.Context, next state.Document) error {
	*store.events = append(*store.events, "save")
	store.saves++
	if err := errors.Join(ctx.Err(), state.CheckTransition(store.document, next)); err != nil {
		return err
	}
	if store.saves == store.failSave && !store.advanceThenFail {
		return errFixture
	}
	owned, err := state.Clone(next)
	if err != nil {
		return err
	}
	store.document = owned
	if store.saves == store.failSave {
		return errFixture
	}
	return nil
}

type memoryFirewall struct {
	events     *[]string
	cohort     []string
	active     []policy.Grant
	candidates []policy.Candidate
	sealError  error
	applyError error
}

func (firewall *memoryFirewall) seal(ctx context.Context, cohort []string) error {
	*firewall.events = append(*firewall.events, "seal")
	if err := errors.Join(ctx.Err(), firewall.sealError); err != nil {
		return err
	}
	firewall.active = nil
	firewall.cohort = append(firewall.cohort, cohort...)
	slices.Sort(firewall.cohort)
	firewall.cohort = slices.Compact(firewall.cohort)
	return nil
}

func (firewall *memoryFirewall) apply(ctx context.Context, candidate policy.Candidate, cohort []string) error {
	*firewall.events = append(*firewall.events, "apply")
	firewall.candidates = append(firewall.candidates, candidate)
	if err := ctx.Err(); err != nil {
		return err
	}
	// Also simulate an error after a backend has partially changed its objects:
	// the engine's error path must remove permits rather than trust that failure.
	firewall.active = candidate.Grants
	firewall.cohort = slices.Clone(cohort)
	return firewall.applyError
}

func TestHelperTransactionOrdering(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	engine := f.engine(t, f.options(Enforce))
	receipt, err := engine.Process(t.Context(), f.directory)
	if err != nil || receipt.Status != ipc.StatusApplied || receipt.GrantCount != 1 || receipt.DenialCount != 0 {
		t.Fatalf("helper transaction failed: %+v, %v", receipt, err)
	}
	want := []string{"seal", "load", "seal", "load", "save", "bindings", "save", "apply"}
	if !slices.Equal(f.events, want) || len(f.store.document.CohortMACs) != 1 || len(f.firewall.active) != 1 {
		t.Fatalf("unsafe transaction ordering: %v", f.events)
	}
	if err := engine.Stop(t.Context()); err != nil || len(f.firewall.active) != 0 || len(f.firewall.cohort) != 1 {
		t.Fatalf("stop erased guards or left permits: %v", err)
	}
	if _, err := engine.Process(t.Context(), f.directory); err == nil {
		t.Fatal("processed request after stop")
	}
	if err := engine.Start(t.Context()); err != nil || len(f.firewall.active) != 0 || len(f.firewall.cohort) != 1 {
		t.Fatalf("restart restored permits or lost cohort: %v", err)
	}
}

func TestShadowDoesNotMutateFirewall(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	engine := f.engine(t, f.options(Shadow))
	receipt, err := engine.Process(t.Context(), f.directory)
	if err != nil || receipt.Status != ipc.StatusShadow || receipt.GrantCount != 1 || len(f.firewall.candidates) != 0 {
		t.Fatalf("shadow mutated firewall or implied apply: %+v, %v", receipt, err)
	}
	if err := engine.Stop(t.Context()); err != nil || slices.Contains(f.events, "seal") || slices.Contains(f.events, "apply") {
		t.Fatalf("shadow performed firewall operations: %v, %v", f.events, err)
	}
}

func TestBindingFailurePersistsNewerDenialAndBlocksReplay(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	options := f.options(Enforce)
	var sourceError error
	options.Bindings = func(ctx context.Context) (binding.Snapshot, error) {
		return f.bindings, errors.Join(ctx.Err(), sourceError)
	}
	engine := f.engine(t, options)
	if _, err := engine.Process(t.Context(), f.directory); err != nil {
		t.Fatal(err)
	}
	older := f.directory
	// Clone the device slice so changing the new observation cannot change the
	// old allow that is replayed below.
	f.directory.Devices = slices.Clone(f.directory.Devices)
	f.directory.Devices[0].Active = false
	f.setUTC(f.now.Add(time.Second))
	f.directory.ObservedAt = f.now
	sourceError = errFixture
	if _, err := engine.Process(t.Context(), f.directory); !errors.Is(err, errFixture) || len(f.firewall.active) != 0 {
		t.Fatalf("binding failure retained authorization: %v", err)
	}
	if !f.store.document.LastDirectoryObservedAt.Equal(f.now) || len(f.store.document.CohortMACs) != 1 {
		t.Fatal("binding failure lost directory watermark or classification")
	}
	sourceError = nil
	if _, err := engine.Process(t.Context(), older); err == nil || len(f.firewall.active) != 0 {
		t.Fatalf("replayed older allow after newer denial: %v", err)
	}
	receipt, err := engine.Process(t.Context(), f.directory)
	if err != nil || receipt.GrantCount != 0 || receipt.DenialCount != 1 || len(f.firewall.active) != 0 {
		t.Fatalf("inactive device regained authorization: %+v, %v", receipt, err)
	}
}

func TestFailureCannotAuthorize(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name   string
		mutate func(*fixture)
	}{
		{name: "load", mutate: func(f *fixture) { f.store.loadError = errFixture }},
		{name: "observation save", mutate: func(f *fixture) { f.store.failSave = 1 }},
		{name: "anchor save", mutate: func(f *fixture) { f.store.failSave = 2 }},
		{name: "save advanced before sync error", mutate: func(f *fixture) {
			f.store.failSave, f.store.advanceThenFail = 2, true
		}},
		{name: "apply", mutate: func(f *fixture) { f.firewall.applyError = errFixture }},
		{name: "incomplete bindings", mutate: func(f *fixture) { f.bindings.Complete = false }},
		{name: "incomplete directory", mutate: func(f *fixture) { f.directory.Complete = false }},
		{name: "corrupt state", mutate: func(f *fixture) { f.store.document.SchemaVersion = 99 }},
		{name: "unsafe clock", mutate: func(f *fixture) { f.setUTC(time.Time{}) }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			f := newFixture(t)
			engine := f.engine(t, f.options(Enforce))
			test.mutate(f)
			receipt, err := engine.Process(t.Context(), f.directory)
			if err == nil || receipt.Status != "" || len(f.firewall.active) != 0 || f.events[len(f.events)-1] != "seal" {
				t.Fatalf("failure returned authorization or missed cleanup: %+v, %v, %v", receipt, err, f.events)
			}
		})
	}
}

func TestCancellationRemovesPermitsWithIndependentDeadline(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	options := f.options(Enforce)
	options.Bindings = func(context.Context) (binding.Snapshot, error) {
		cancel()
		return binding.Snapshot{}, context.Canceled
	}
	engine := f.engine(t, options)
	f.firewall.active = []policy.Grant{{MAC: f.directory.Devices[0].MAC}}
	if _, err := engine.Process(ctx, f.directory); !errors.Is(err, context.Canceled) || len(f.firewall.active) != 0 {
		t.Fatalf("canceled request skipped closed cleanup: %v", err)
	}
}

func TestFailedSealRequiresRestart(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	engine := f.engine(t, f.options(Enforce))
	f.firewall.applyError, f.firewall.sealError = errFixture, errFixture
	if _, err := engine.Process(t.Context(), f.directory); !errors.Is(err, errFixture) {
		t.Fatal("backend failure was hidden")
	}
	f.firewall.applyError, f.firewall.sealError = nil, nil
	if _, err := engine.Process(t.Context(), f.directory); err == nil {
		t.Fatal("applied again without successful closed startup")
	}
	if err := engine.Start(t.Context()); err != nil || len(f.firewall.active) != 0 {
		t.Fatalf("restart did not first remove partial permits: %v", err)
	}
}

func TestCancellationAfterPartialApplyRemovesPermits(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	options := f.options(Enforce)
	apply := options.Firewall.Apply
	options.Firewall.Apply = func(ctx context.Context, candidate policy.Candidate, cohort []string) error {
		err := apply(ctx, candidate, cohort)
		cancel()
		return err
	}
	engine := f.engine(t, options)
	if _, err := engine.Process(ctx, f.directory); !errors.Is(err, context.Canceled) || len(f.firewall.active) != 0 {
		t.Fatalf("cancellation after apply left permits: %v", err)
	}
}

func TestStartupDoesNotInitializeMissingOrUnsafeState(t *testing.T) {
	t.Parallel()
	for _, startupError := range []error{state.ErrUninitialized, errFixture} {
		f := newFixture(t)
		f.store.loadError = startupError
		f.firewall.active = []policy.Grant{{MAC: f.directory.Devices[0].MAC}}
		engine, err := New(f.baseline, f.options(Enforce))
		if err != nil {
			t.Fatal(err)
		}
		if err := engine.Start(t.Context()); !errors.Is(err, startupError) || len(f.firewall.active) != 0 || f.store.saves != 0 {
			t.Fatalf("unsafe startup authorized or initialized state: %v", err)
		}
		if _, err := engine.Process(t.Context(), f.directory); err == nil {
			t.Fatal("processed before successful startup")
		}
	}
}

func TestClockChangeAndExpiryBeforeApply(t *testing.T) {
	t.Parallel()
	for _, delta := range []time.Duration{-time.Second, 91 * time.Second} {
		f := newFixture(t)
		options := f.options(Enforce)
		originalSave := options.State.Save
		options.State.Save = func(ctx context.Context, document state.Document) error {
			err := originalSave(ctx, document)
			if f.store.saves == 2 {
				f.setUTC(f.now.Add(delta))
			}
			return err
		}
		engine := f.engine(t, options)
		if _, err := engine.Process(t.Context(), f.directory); err == nil || len(f.firewall.candidates) != 0 {
			t.Fatalf("unsafe application clock/expiry accepted: delta=%v, error=%v", delta, err)
		}
	}
}

func TestConstructorRejectsUnsafeDependencies(t *testing.T) {
	t.Parallel()
	mutations := []func(*Options){
		func(o *Options) { o.Mode = "" },
		func(o *Options) { o.State.Load = nil },
		func(o *Options) { o.State.Save = nil },
		func(o *Options) { o.Bindings = nil },
		func(o *Options) { o.Clock = nil },
		func(o *Options) { o.Firewall.Seal = nil },
		func(o *Options) { o.Firewall.Apply = nil },
		func(o *Options) { o.Mode = Shadow },
	}
	for _, mutate := range mutations {
		f := newFixture(t)
		options := f.options(Enforce)
		mutate(&options)
		if _, err := New(f.baseline, options); err == nil {
			t.Fatal("accepted unsafe helper wiring")
		}
	}
	f := newFixture(t)
	f.baseline.SchemaVersion = 99
	if _, err := New(f.baseline, f.options(Enforce)); err == nil {
		t.Fatal("accepted invalid baseline")
	}
	var engine *Engine
	if err := engine.Start(t.Context()); err == nil {
		t.Fatal("accepted nil engine")
	}
	f = newFixture(t)
	engine = f.engine(t, f.options(Shadow))
	//nolint:staticcheck // A nil context must fail closed at this public boundary.
	if err := engine.Start(nil); err == nil {
		t.Fatal("accepted nil context")
	}
}

func TestRepeatingSnapshotCannotRenewItsLease(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	engine := f.engine(t, f.options(Enforce))
	if _, err := engine.Process(t.Context(), f.directory); err != nil {
		t.Fatal(err)
	}
	firstExpiry := f.firewall.candidates[0].Grants[0].ExpiresAt()
	f.setUTC(f.now.Add(30 * time.Second))
	f.bindings.ObservedAt = f.now
	f.bindings.Records[0].AssociatedAt = f.now
	f.bindings.Records[0].Addresses[0].ObservedAt = f.now
	if _, err := engine.Process(t.Context(), f.directory); err != nil ||
		!f.firewall.candidates[1].Grants[0].ExpiresAt().Equal(firstExpiry) {
		t.Fatalf("identical directory snapshot renewed its lease: %v", err)
	}
	f.setUTC(firstExpiry)
	if _, err := engine.Process(t.Context(), f.directory); err == nil || len(f.firewall.active) != 0 {
		t.Fatalf("expired directory restored permission: %v", err)
	}
}

func TestClockRollbackCannotRejuvenateEvidence(t *testing.T) {
	t.Parallel()
	synctest.Test(t, func(t *testing.T) {
		f := newFixture(t)
		engine := f.engine(t, f.options(Enforce))
		if _, err := engine.Process(t.Context(), f.directory); err != nil {
			t.Fatal(err)
		}
		// Two minutes really elapse, but UTC advances only 45 seconds after a
		// backward adjustment. It still exceeds the durable validation time.
		time.Sleep(120 * time.Second)
		f.setUTC(f.now.Add(45 * time.Second))
		receipt, err := engine.Process(t.Context(), f.directory)
		if err == nil || receipt.Status != "" || len(f.firewall.active) != 0 || len(f.firewall.candidates) != 1 {
			t.Fatalf("old evidence regained a lease after clock rollback: %+v, %v", receipt, err)
		}
	})
}

func TestRestartRequiresFreshEvidence(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name        string
		directory   bool
		snapshot    bool
		association bool
		address     bool
		wantErr     bool
	}{
		{name: "directory predates startup", wantErr: true},
		{name: "binding snapshot predates startup", directory: true, wantErr: true},
		{name: "association predates startup", directory: true, snapshot: true, wantErr: true},
		{name: "address predates startup", directory: true, snapshot: true, association: true, wantErr: true},
		{name: "all evidence refreshed", directory: true, snapshot: true, association: true, address: true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			synctest.Test(t, func(t *testing.T) {
				f := newFixture(t)
				engine := f.engine(t, f.options(Enforce))
				if _, err := engine.Process(t.Context(), f.directory); err != nil {
					t.Fatal(err)
				}
				if err := engine.Stop(t.Context()); err != nil {
					t.Fatal(err)
				}
				time.Sleep(5 * time.Second)
				f.setUTC(f.now.Add(5 * time.Second))
				engine = f.engine(t, f.options(Enforce))
				if test.directory {
					f.directory.ObservedAt = f.now
				}
				if test.snapshot {
					f.bindings.ObservedAt = f.now
				}
				if test.association {
					f.bindings.Records[0].AssociatedAt = f.now
				}
				if test.address {
					f.bindings.Records[0].Addresses[0].ObservedAt = f.now
				}
				receipt, err := engine.Process(t.Context(), f.directory)
				if (err != nil) != test.wantErr || test.wantErr && (receipt.Status != "" || len(f.firewall.active) != 0) {
					t.Fatalf("restart evidence gate failed: %+v, %v", receipt, err)
				}
				if !test.wantErr && (receipt.GrantCount != 1 || len(f.firewall.active) != 1) {
					t.Fatal("fresh observations could not authorize after restart")
				}
			})
		})
	}
}

func TestRestartRejectsPersistedSnapshotAtStartupTime(t *testing.T) {
	t.Parallel()
	synctest.Test(t, func(t *testing.T) {
		f := newFixture(t)
		engine := f.engine(t, f.options(Enforce))
		if _, err := engine.Process(t.Context(), f.directory); err != nil {
			t.Fatal(err)
		}
		if err := engine.Stop(t.Context()); err != nil {
			t.Fatal(err)
		}
		engine = f.engine(t, f.options(Enforce))
		if _, err := engine.Process(t.Context(), f.directory); err == nil || len(f.firewall.active) != 0 {
			t.Fatal("restart reused the persisted observation at an equal startup timestamp")
		}
	})
}

func TestSmallClockLagDoesNotExtendLeaseOrAdmitFutureEvidence(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name   string
		mutate func(*fixture)
	}{
		{name: "existing observation"},
		{name: "future directory", mutate: func(f *fixture) {
			f.directory.ObservedAt = f.now.Add(50 * time.Millisecond)
		}},
		{name: "future binding snapshot", mutate: func(f *fixture) {
			f.bindings.ObservedAt = f.now.Add(50 * time.Millisecond)
		}},
		{name: "future association", mutate: func(f *fixture) {
			f.bindings.Records[0].AssociatedAt = f.now.Add(50 * time.Millisecond)
		}},
		{name: "future address", mutate: func(f *fixture) {
			f.bindings.Records[0].Addresses[0].ObservedAt = f.now.Add(50 * time.Millisecond)
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			synctest.Test(t, func(t *testing.T) {
				f := newFixture(t)
				engine := f.engine(t, f.options(Enforce))
				if _, err := engine.Process(t.Context(), f.directory); err != nil {
					t.Fatal(err)
				}
				deadline := f.firewall.active[0].ExpiresAt()
				time.Sleep(30 * time.Second)
				f.setUTC(f.now.Add(30*time.Second - 100*time.Millisecond))
				f.bindings.ObservedAt = f.now
				f.bindings.Records[0].AssociatedAt = f.now
				f.bindings.Records[0].Addresses[0].ObservedAt = f.now
				if test.mutate != nil {
					test.mutate(f)
				}
				receipt, err := engine.Process(t.Context(), f.directory)
				if test.mutate != nil {
					if err == nil || receipt.Status != "" || len(f.firewall.active) != 0 {
						t.Fatal("monotonic clock clamp admitted future evidence")
					}
					return
				}
				if err != nil || receipt.GrantCount != 1 || !f.firewall.active[0].ExpiresAt().Equal(deadline) ||
					!receipt.CompiledAt.Equal(f.now.Add(100*time.Millisecond)) {
					t.Fatalf("clock sampling lag extended a lease or understated age: %+v, %v", receipt, err)
				}
			})
		})
	}
}

func TestClockRecoveryRequiresNewEvidence(t *testing.T) {
	t.Parallel()
	synctest.Test(t, func(t *testing.T) {
		f := newFixture(t)
		engine := f.engine(t, f.options(Enforce))
		if _, err := engine.Process(t.Context(), f.directory); err != nil {
			t.Fatal(err)
		}
		time.Sleep(120 * time.Second)
		f.setUTC(f.now.Add(45 * time.Second))
		if _, err := engine.Process(t.Context(), f.directory); err == nil {
			t.Fatal("clock rollback was accepted")
		}
		f.setUTC(f.now.Add(75 * time.Second))
		if _, err := engine.Process(t.Context(), f.directory); err == nil || len(f.firewall.active) != 0 {
			t.Fatal("clock recovery refreshed old directory or binding evidence")
		}
		f.directory.ObservedAt = f.now
		f.bindings.ObservedAt = f.now
		f.bindings.Records[0].AssociatedAt = f.now
		f.bindings.Records[0].Addresses[0].ObservedAt = f.now
		if receipt, err := engine.Process(t.Context(), f.directory); err != nil || receipt.GrantCount != 1 {
			t.Fatalf("clock recovery could not accept new evidence: %+v, %v", receipt, err)
		}
	})
}

func TestHelperSerializesRequestsAndCancelsWaitingCaller(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	options := f.options(Enforce)
	entered, release := make(chan struct{}, 1), make(chan struct{})
	options.Bindings = func(ctx context.Context) (binding.Snapshot, error) {
		entered <- struct{}{}
		select {
		case <-release:
			return f.bindings, nil
		case <-ctx.Done():
			return binding.Snapshot{}, ctx.Err()
		}
	}
	engine := f.engine(t, options)
	first, cancelFirst := context.WithTimeout(t.Context(), 2*time.Second)
	defer cancelFirst()
	finished := make(chan error, 1)
	go func() {
		_, err := engine.Process(first, f.directory)
		finished <- err
	}()
	select {
	case <-entered:
	case <-first.Done():
		t.Fatal("first transaction did not reach binding collection")
	}
	waiting, cancelWaiting := context.WithTimeout(t.Context(), 20*time.Millisecond)
	defer cancelWaiting()
	_, waitingError := engine.Process(waiting, f.directory)
	close(release)
	firstError := <-finished
	if !errors.Is(waitingError, context.DeadlineExceeded) || firstError != nil || len(f.firewall.candidates) != 1 {
		t.Fatalf("transactions overlapped or waiter did not cancel: %v, %v", waitingError, firstError)
	}
}
