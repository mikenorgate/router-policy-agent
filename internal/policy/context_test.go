package policy

import (
	"context"
	"errors"
	"fmt"
	"sync/atomic"
	"testing"
	"time"
)

func TestCompileContextCancellation(t *testing.T) {
	t.Parallel()
	compiler, input := testCompiler(t, testBaseline()), testInput(t)
	probe := &cancelAtCheck{Context: t.Context()}
	if _, err := compiler.CompileContext(probe, input); err != nil {
		t.Fatal(err)
	}
	for position := int64(1); position <= probe.calls.Load(); position++ {
		t.Run(fmt.Sprintf("check-%d", position), func(t *testing.T) {
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			checked := &cancelAtCheck{Context: ctx, at: position, cancel: cancel}
			candidate, err := compiler.CompileContext(checked, input)
			if !errors.Is(err, context.Canceled) || len(candidate.Grants) != 0 {
				t.Fatalf("canceled compilation returned candidate: %+v, %v", candidate, err)
			}
			if len(input.Ledger.FirstSeen) != 0 || len(input.Ledger.AliasPeers) != 0 {
				t.Fatal("canceled compilation mutated caller ledger")
			}
		})
	}
	//nolint:staticcheck // A nil context must fail closed at this public boundary.
	if _, err := compiler.CompileContext(nil, input); err == nil {
		t.Fatal("accepted nil context")
	}
}

// cancelAtCheck uses a real cancellable parent and changes only when the test
// triggers it, making cancellation at each compiler checkpoint deterministic.
type cancelAtCheck struct {
	context.Context //nolint:containedctx // This test-only decorator implements context.Context.
	calls           atomic.Int64
	at              int64
	cancel          context.CancelFunc
}

func (ctx *cancelAtCheck) Err() error {
	if count := ctx.calls.Add(1); ctx.at != 0 && count == ctx.at {
		ctx.cancel()
	}
	return ctx.Context.Err()
}

func TestObserveDirectoryRetainsClassificationWithoutStartingDeadlines(t *testing.T) {
	t.Parallel()
	input := testInput(t)
	rule := testRule()
	expires := testNow.Add(time.Hour)
	rule.ExpiresAt = &expires
	input.Directory.Groups[1] = accessGroup(t, "access", true, rule)
	compiler := testCompiler(t, testBaseline())
	ledger, err := compiler.ObserveDirectory(t.Context(), input.Directory, testNow, input.Ledger)
	if err != nil {
		t.Fatal(err)
	}
	if !ledger.NetworkGroups["access"] || !ledger.LastValidated.Equal(testNow) || len(ledger.FirstSeen) != 0 {
		t.Fatalf("observation changed deadlines or lost classification: %+v", ledger)
	}
	if len(input.Ledger.NetworkGroups) != 0 {
		t.Fatal("observation mutated caller ledger")
	}
	input.Directory.Groups[1].Policy = nil
	input.Directory.Groups[1].IsNetwork = false
	input.Ledger = ledger
	candidate, err := compiler.CompileContext(t.Context(), input)
	if err != nil || len(candidate.Grants) != 0 || len(candidate.Denials) != 1 ||
		candidate.Denials[0].Code != "missing_network_attribute" {
		t.Fatalf("observation classification was lost: %+v, %v", candidate, err)
	}
}

func TestDeniedDeviceRollsBackOnlyItsNewAnchors(t *testing.T) {
	t.Parallel()
	input := testInput(t)
	allowed, forbidden := testRule(), testRule()
	allowed.Peer.Addresses = []string{"fdca:1a2b:64::af0:a/128"}
	expires := testNow.Add(time.Hour)
	allowed.ExpiresAt = &expires
	forbidden.ID = "forbidden"
	forbidden.Peer.Addresses = []string{"fdca:1a2b:4::10/128"}
	forbidden.ExpiresAt = &expires
	input.Directory.Groups[1] = accessGroup(t, "access", true, allowed, forbidden)
	candidate, err := testCompiler(t, testBaseline()).CompileContext(t.Context(), input)
	if err != nil || len(candidate.Grants) != 0 || len(candidate.Denials) != 1 {
		t.Fatalf("expected denied device: %+v, %v", candidate, err)
	}
	if len(candidate.Ledger.FirstSeen) != 0 || len(candidate.Ledger.AliasPeers) != 0 ||
		!candidate.Ledger.NetworkGroups["access"] {
		t.Fatalf("denied device retained new anchors or lost classification: %+v", candidate.Ledger)
	}
	input.Ledger = candidate.Ledger
	input.Ledger.FirstSeen["access/device-api"] = testNow.Add(-time.Minute)
	input.Ledger.AliasPeers["access/device-api/fdca:1a2b:64::af0:a/128"] =
		input.Bindings.Records[0].Addresses[0].IP // Deliberately mismatched prior ownership.
	candidate, err = testCompiler(t, testBaseline()).CompileContext(t.Context(), input)
	if err != nil || len(candidate.Grants) != 0 || len(candidate.Ledger.FirstSeen) != 1 || len(candidate.Ledger.AliasPeers) != 1 {
		t.Fatalf("rollback erased an existing anchor: %+v, %v", candidate, err)
	}
}

func TestCompileAtCohortAndLedgerCapacity(t *testing.T) {
	t.Parallel()
	input := testInput(t)
	input.Ledger.LastValidated = testNow
	input.Ledger.FirstSeen = make(map[string]time.Time, maximumLedgerEntries-2)
	for index := range maximumLedgerEntries - 2 {
		input.Ledger.FirstSeen[fmt.Sprintf("retired-%d/rule", index)] = testNow
	}
	input.Directory.Devices = make([]Device, 4096)
	for index := range input.Directory.Devices {
		input.Directory.Devices[index] = Device{ID: fmt.Sprintf("synthetic-%d", index),
			MAC: fmt.Sprintf("02:00:00:00:%02x:%02x", index>>8, index&255), Active: false, GroupIDs: []string{}}
	}
	input.Bindings.Records = nil
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()
	candidate, err := testCompiler(t, testBaseline()).CompileContext(ctx, input)
	if err != nil || len(candidate.Denials) != 4096 || len(candidate.Grants) != 0 ||
		ledgerSize(candidate.Ledger) != maximumLedgerEntries {
		t.Fatalf("bounded-capacity compilation failed: denials=%d, ledger=%d, error=%v",
			len(candidate.Denials), ledgerSize(candidate.Ledger), err)
	}
}
