package firewall

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"syscall"
	"testing"
	"time"

	"github.com/mikenorgate/router-policy-agent/internal/hostfs"
	"github.com/mikenorgate/router-policy-agent/internal/policy"
	"github.com/mikenorgate/router-policy-agent/internal/state"
)

func backendOptionsFixture(t testing.TB) backendOptions {
	t.Helper()
	data := routerProfileFixture(t)
	profile, err := decodePinnedProfile(t.Context(), data, routerProfileDigest(data))
	if err != nil {
		t.Fatal(err)
	}
	expected := writerGenerationFixture()
	expected.FloorHash = profile.ruleset.digest
	return backendOptions{
		profile: profile, executor: &process{gate: make(chan struct{}, 1)},
		generation: &generationGate{fence: &hostfs.Fence{}}, expected: expected, clock: time.Now,
	}
}

func TestGuardedBackendRequiresPairedTrustedDependencies(t *testing.T) {
	t.Parallel()
	for _, test := range []struct {
		name   string
		change func(*backendOptions)
	}{
		{name: "profile", change: func(o *backendOptions) { o.profile = nil }},
		{name: "executor", change: func(o *backendOptions) { o.executor = nil }},
		{name: "executor gate", change: func(o *backendOptions) { o.executor.gate = nil }},
		{name: "writer gate", change: func(o *backendOptions) { o.generation = nil }},
		{name: "writer fence", change: func(o *backendOptions) { o.generation.fence = nil }},
		{name: "clock", change: func(o *backendOptions) { o.clock = nil }},
		{name: "profile pin", change: func(o *backendOptions) { o.profile.digest = "invalid" }},
		{name: "renderer", change: func(o *backendOptions) { o.profile.renderer = nil }},
		{name: "compiler", change: func(o *backendOptions) { o.profile.renderer.compiler = nil }},
		{name: "guard layout", change: func(o *backendOptions) { o.profile.layout = nil }},
		{name: "reviewed contract", change: func(o *backendOptions) { o.profile.ruleset = nil }},
		{name: "contract digest", change: func(o *backendOptions) { o.profile.ruleset.digest = "invalid" }},
		{name: "closed expectation", change: func(o *backendOptions) { o.expected.Ready = false }},
		{name: "floor mismatch", change: func(o *backendOptions) { o.expected.FloorHash = o.profile.digest }},
		{name: "invalid mapping pin", change: func(o *backendOptions) { o.expected.MappingHash = "invalid" }},
		{name: "missing sequence", change: func(o *backendOptions) { o.expected.Sequence = 0 }},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			options := backendOptionsFixture(t)
			test.change(&options)
			if backend, err := newGuardedBackend(options); err == nil || backend != nil {
				t.Fatal("incomplete trusted dependencies constructed a guarded backend")
			}
		})
	}
	options := backendOptionsFixture(t)
	backend, err := newGuardedBackend(options)
	if err != nil {
		t.Fatal(err)
	}
	options.expected.Sequence++
	options.clock = nil
	if backend.options.expected.Sequence != writerGenerationFixture().Sequence || backend.options.clock == nil {
		t.Fatal("backend retained mutable options storage")
	}
	for _, backend := range []*guardedBackend{nil, {}} {
		if err := backend.apply(t.Context(), policy.Authorization{}, state.EmptyClassification()); err == nil {
			t.Fatal("zero backend accepted application")
		}
		if err := backend.seal(t.Context(), state.EmptyClassification()); err == nil {
			t.Fatal("zero backend accepted sealing")
		}
	}
}

func TestGuardSealCannotAddOrRenewAuthorization(t *testing.T) {
	t.Parallel()
	sealed, err := prepareGuardSeal(t.Context(), guardClassificationFixture())
	if err != nil || validateGuardSeal(t.Context(), sealed) != nil {
		t.Fatalf("deny-only sealing was rejected: %v", err)
	}
	renderer, input, _, _ := renderFixture(t)
	logical, err := renderer.prepare(t.Context(), input)
	if err != nil {
		t.Fatal(err)
	}
	active, err := prepareClassifiedGuards(t.Context(), logical, guardClassificationFixture())
	if err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		name   string
		change func() *preparedGuardBatch
	}{
		{name: "lease and clock", change: func() *preparedGuardBatch { return active }},
		{name: "lease without clock", change: func() *preparedGuardBatch {
			value := *active
			value.batch.preparedAt, value.batch.startBefore, value.batch.startedAt = time.Time{}, time.Time{}, time.Time{}
			return &value
		}},
		{name: "clock without lease", change: func() *preparedGuardBatch {
			value := *sealed
			value.batch.startedAt = time.Now()
			return &value
		}},
		{name: "missing preparation", change: func() *preparedGuardBatch { return nil }},
	} {
		t.Run(test.name, func(t *testing.T) {
			if err := validateGuardSeal(t.Context(), test.change()); err == nil {
				t.Fatal("sealing admitted authorization or its renewal clock")
			}
		})
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if err := validateGuardSeal(ctx, sealed); !errors.Is(err, context.Canceled) {
		t.Fatal("sealing validation ignored cancellation")
	}
}

func TestGuardedBackendFailureKeepsOriginalAndCleanupErrors(t *testing.T) {
	t.Parallel()
	for _, name := range []string{"missing generation", "invalid classification", "canceled request"} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			path := t.TempDir()
			if err := os.Chmod(path, 0o700); err != nil { // #nosec G302 -- Owner-only fixture directory.
				t.Fatal(err)
			}
			info, err := os.Stat(path)
			if err != nil {
				t.Fatal(err)
			}
			owner, ok := info.Sys().(*syscall.Stat_t)
			if !ok {
				t.Fatal("fixture directory has no checked Linux owner")
			}
			// Test-only current-user fence; no generation record or executable
			// exists. This cannot produce a privileged application or receipt.
			fence, err := hostfs.OpenFence(t.Context(), hostfs.DirectoryOptions{
				Path: path, OwnerUID: owner.Uid, Private: true,
			})
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() {
				cleanup, cancel := context.WithTimeout(context.WithoutCancel(t.Context()), 2*time.Second)
				defer cancel()
				if err := fence.Close(cleanup); err != nil {
					t.Error(err)
				}
			})
			options := backendOptionsFixture(t)
			options.generation = &generationGate{fence: fence}
			backend, err := newGuardedBackend(options)
			if err != nil {
				t.Fatal(err)
			}
			ctx, history := t.Context(), state.EmptyClassification()
			switch name {
			case "invalid classification":
				history = state.Classification{}
			case "canceled request":
				canceled, cancel := context.WithCancel(ctx)
				cancel()
				ctx = canceled
			}
			err = backend.apply(ctx, policy.Authorization{}, history)
			joined, ok := err.(interface{ Unwrap() []error })
			if !ok || len(joined.Unwrap()) != 2 || !errors.Is(err, os.ErrClosed) {
				t.Fatal("failed application discarded the independent cleanup failure")
			}
			if name == "canceled request" && !errors.Is(err, context.Canceled) {
				t.Fatal("cleanup erased the original cancellation")
			}
			if len(options.executor.gate) != 0 {
				t.Fatal("failed cleanup left the executor gate held")
			}
		})
	}
}

func TestGuardedOperationRejectsUntrustedPreparationWithoutStartingChild(t *testing.T) {
	t.Parallel()
	renderer, input, _, _ := renderFixture(t)
	logical, err := renderer.prepare(t.Context(), input)
	if err != nil {
		t.Fatal(err)
	}
	active, err := prepareClassifiedGuards(t.Context(), logical, guardClassificationFixture())
	if err != nil {
		t.Fatal(err)
	}
	for _, input := range []commandInput{
		{op: applyGuarded},
		{op: sealGuarded},
		{op: applyGuarded, payload: clearBatch(t), guarded: active},
		{op: sealGuarded, prepared: logical, guarded: active},
		{op: inspectOwned, guarded: active},
		{op: sealGuarded, guarded: active},
		{op: applyGuarded, guarded: &preparedGuardBatch{}},
	} {
		// No executable exists: every case must reject at its input boundary,
		// not reach command execution and hide that failure as an nft error.
		_, err := (&process{}).run(t.Context(), input)
		if err == nil || err.Error() == "firewall: nftables operation failed" {
			t.Fatal("invalid guarded input escaped its pre-execution boundary")
		}
	}
}

func TestSealingInspectionRetainsClassificationDespiteLeaseAndFloorDrift(t *testing.T) {
	t.Parallel()
	layout, original := fullRulesetFixture(t)
	for _, test := range []struct {
		name   string
		change func([]byte) []byte
	}{
		{name: "floor drift", change: func(data []byte) []byte {
			return bytes.ReplaceAll(data, []byte(`"10.240.2.254"`), []byte(`"10.240.2.253"`))
		}},
		{name: "unequal lease mirrors", change: func(data []byte) []byte {
			return changeSealingSet(t, data, sealingSetChange{family: "netdev", name: "egress_lease_to6_tcp", elements: []any{}})
		}},
		{name: "different permanent cohorts", change: func(data []byte) []byte {
			return changeSealingSet(t, data, sealingSetChange{
				family: "netdev", name: cohortSet, elements: []any{"02:00:00:00:00:02"},
			})
		}},
		{name: "malformed lease content", change: func(data []byte) []byte {
			return changeSealingSet(t, data, sealingSetChange{
				family: "inet", name: "lease_to6_tcp", elements: []any{"not-a-permit"},
			})
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			data := test.change(bytes.Clone(original))
			if bytes.Equal(original, data) {
				t.Fatal("sealing test did not change its fixture")
			}
			if _, err := reviewedRulesetFixture(t).inspect(t.Context(), layout, data); err == nil {
				t.Fatal("application inspection admitted drift")
			}
			inventory, retained, err := inspectSealingGuards(t.Context(), layout, data)
			if err != nil || len(retained.MACs) == 0 || len(retained.IPv6) == 0 || inventory.leases == 0 {
				t.Fatalf("revocation was disabled by inconsistent grants or external drift: %v", err)
			}
			if test.name == "different permanent cohorts" && len(retained.MACs) != 2 {
				t.Fatal("sealing dropped a permanent cohort mirror instead of retaining both")
			}
		})
	}
	changed := bytes.ReplaceAll(original, []byte(`"prio":150`), []byte(`"prio":149`))
	if bytes.Equal(changed, original) {
		t.Fatal("guard drift test did not change the confirmation hook")
	}
	if _, _, err := inspectSealingGuards(t.Context(), layout, changed); err == nil {
		t.Fatal("sealing accepted changed code-owned guard objects")
	}
	if _, _, err := inspectSealingGuards(t.Context(), layout, []byte(`{"nftables":[]}`)); err == nil {
		t.Fatal("missing guards could bootstrap themselves from a live listing")
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if _, _, err := inspectSealingGuards(ctx, layout, original); !errors.Is(err, context.Canceled) {
		t.Fatal("sealing inspection ignored cancellation")
	}
}

type sealingSetChange struct {
	family, name string
	elements     []any
}

func changeSealingSet(t testing.TB, data []byte, change sealingSetChange) []byte {
	t.Helper()
	var listing struct {
		Objects []map[string]map[string]any `json:"nftables"`
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.UseNumber()
	if err := decoder.Decode(&listing); err != nil {
		t.Fatal(err)
	}
	changed := false
	for _, object := range listing.Objects {
		set := object["set"]
		if set["family"] == change.family && set["table"] == ownedTable && set["name"] == change.name {
			set["elem"] = change.elements
			changed = true
		}
	}
	if !changed {
		t.Fatal("synthetic sealing set missing")
	}
	encoded, err := json.Marshal(listing)
	if err != nil {
		t.Fatal(err)
	}
	return encoded
}
