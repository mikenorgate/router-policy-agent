package reader

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"reflect"
	"strings"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"

	"github.com/mikenorgate/router-policy-agent/internal/ipc"
	"github.com/mikenorgate/router-policy-agent/internal/policy"
)

func testSnapshot(at time.Time) policy.DirectorySnapshot {
	return policy.DirectorySnapshot{ObservedAt: at, Complete: true,
		Groups: []policy.Group{}, Devices: []policy.Device{}}
}

func testReceipt(status ipc.Status) ipc.Receipt {
	return ipc.Receipt{SchemaVersion: 1, Status: status, BaselineHash: strings.Repeat("a", 64),
		CompiledAt: time.Now().UTC(), GrantCount: 2, DenialCount: 1}
}

func TestLoopAlwaysRecollectsAndNeverReplaysFailedSubmission(t *testing.T) {
	t.Parallel()
	synctest.Test(t, func(t *testing.T) {
		ctx, cancel := context.WithCancel(t.Context())
		defer cancel()
		var diagnostics bytes.Buffer
		var collections, submissions atomic.Int64
		observations := []time.Time{}
		collect := func(context.Context) (policy.DirectorySnapshot, error) {
			count := collections.Add(1)
			snapshot := testSnapshot(time.Now().UTC())
			if count == 2 {
				// Even a populated partial result alongside an error is discarded.
				return snapshot, errors.New("synthetic-private-directory-diagnostic")
			}
			observations = append(observations, snapshot.ObservedAt)
			return snapshot, nil
		}
		submit := func(_ context.Context, snapshot policy.DirectorySnapshot) (ipc.Receipt, error) {
			count := submissions.Add(1)
			if !reflect.DeepEqual(snapshot, testSnapshot(observations[count-1])) {
				t.Error("snapshot changed between collection and submission")
			}
			if count == 1 {
				return testReceipt(ipc.StatusApplied), errors.New("synthetic-private-lost-receipt")
			}
			return testReceipt(ipc.StatusApplied), nil
		}
		done := make(chan error, 1)
		go func() { done <- runLoop(ctx, collect, submit, &diagnostics) }()
		synctest.Wait()
		if collections.Load() != 1 || submissions.Load() != 1 {
			t.Fatal("startup did not make exactly one collection and submission")
		}
		time.Sleep(refreshInterval)
		synctest.Wait()
		if collections.Load() != 2 || submissions.Load() != 1 {
			t.Fatal("failed collection submitted or lost receipt retried")
		}
		time.Sleep(refreshInterval)
		synctest.Wait()
		if collections.Load() != 3 || submissions.Load() != 2 {
			t.Fatal("recovery did not submit a newly collected observation")
		}
		cancel()
		if err := <-done; !errors.Is(err, context.Canceled) {
			t.Fatal("reader cancellation did not join its loop")
		}
		if !observations[1].After(observations[0]) {
			t.Fatal("recovered observation was not fresh")
		}
		decoder := json.NewDecoder(&diagnostics)
		for _, outcome := range []string{"submission_failed", "collection_failed", "applied"} {
			var result attempt
			if err := decoder.Decode(&result); err != nil || result.Outcome != outcome {
				t.Fatal("unexpected diagnostic outcome")
			}
		}
		var extra attempt
		if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
			t.Fatal("extra poll or unbounded diagnostic payload")
		}
	})
}

func TestCycleSharesDeadlineAndPreservesObservationAge(t *testing.T) {
	t.Parallel()
	synctest.Test(t, func(t *testing.T) {
		started := time.Now()
		var observedDeadline time.Time
		original := testSnapshot(started.UTC())
		collect := func(ctx context.Context) (policy.DirectorySnapshot, error) {
			deadline, ok := ctx.Deadline()
			if !ok {
				t.Error("collection has no deadline")
			}
			observedDeadline = deadline
			time.Sleep(9 * time.Second)
			return original, nil
		}
		submit := func(ctx context.Context, snapshot policy.DirectorySnapshot) (ipc.Receipt, error) {
			deadline, ok := ctx.Deadline()
			if !deadline.Equal(observedDeadline) || !ok || deadline.Sub(started) != cycleTimeout ||
				!reflect.DeepEqual(snapshot, original) {
				t.Error("submission renewed the collection budget or observation timestamp")
			}
			<-ctx.Done()
			return testReceipt(ipc.StatusApplied), nil
		}
		result, err := runCycle(t.Context(), collect, submit)
		if err != nil || result.Outcome != "submission_failed" || result.GrantCount != 0 ||
			time.Since(started) != cycleTimeout {
			t.Fatal("late submission was logged as applied or exceeded its shared deadline")
		}
	})
}

func TestCycleDoesNotSubmitAfterCollectionDeadline(t *testing.T) {
	t.Parallel()
	synctest.Test(t, func(t *testing.T) {
		collect := func(ctx context.Context) (policy.DirectorySnapshot, error) {
			<-ctx.Done()
			return testSnapshot(time.Now().UTC()), nil
		}
		submit := func(context.Context, policy.DirectorySnapshot) (ipc.Receipt, error) {
			t.Error("expired collection reached helper")
			return testReceipt(ipc.StatusApplied), nil
		}
		result, err := runCycle(t.Context(), collect, submit)
		if err != nil || result.Outcome != "collection_failed" {
			t.Fatal("collection timeout was not a failed attempt")
		}
	})
}

func TestCycleReportsOnlyFixedOutcomes(t *testing.T) {
	t.Parallel()
	for _, test := range []struct {
		name, outcome string
		receipt       ipc.Receipt
		err           error
	}{
		{name: "shadow is not applied", outcome: "shadow", receipt: testReceipt(ipc.StatusShadow)},
		{name: "applied", outcome: "applied", receipt: testReceipt(ipc.StatusApplied)},
		{name: "rejection", outcome: "rejected", err: errors.Join(ipc.ErrRejected, errors.New("synthetic-private-error"))},
		{name: "submission failure", outcome: "submission_failed", err: errors.New("synthetic-private-error")},
		{name: "unknown status", outcome: "submission_failed", receipt: ipc.Receipt{Status: "synthetic-private-status"}},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			collect := func(context.Context) (policy.DirectorySnapshot, error) { return testSnapshot(time.Now().UTC()), nil }
			submit := func(context.Context, policy.DirectorySnapshot) (ipc.Receipt, error) { return test.receipt, test.err }
			result, err := runCycle(t.Context(), collect, submit)
			if err != nil || result.Outcome != test.outcome {
				t.Fatal("incorrect cycle outcome")
			}
			data, err := json.Marshal(result)
			if err != nil || bytes.Contains(data, []byte("synthetic-private")) {
				t.Fatal("upstream details escaped to diagnostics")
			}
		})
	}
}

func TestLoopCancellationJoinsActiveOperation(t *testing.T) {
	t.Parallel()
	for _, stage := range []string{"collection", "submission"} {
		t.Run(stage, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				ctx, cancel := context.WithCancel(t.Context())
				defer cancel()
				var diagnostics bytes.Buffer
				var joined bool
				collect := func(ctx context.Context) (policy.DirectorySnapshot, error) {
					if stage == "collection" {
						<-ctx.Done()
						joined = true
						return policy.DirectorySnapshot{}, ctx.Err()
					}
					return testSnapshot(time.Now().UTC()), nil
				}
				submit := func(ctx context.Context, _ policy.DirectorySnapshot) (ipc.Receipt, error) {
					<-ctx.Done()
					joined = true
					return ipc.Receipt{}, ctx.Err()
				}
				done := make(chan error, 1)
				go func() { done <- runLoop(ctx, collect, submit, &diagnostics) }()
				synctest.Wait()
				cancel()
				if err := <-done; !errors.Is(err, context.Canceled) || !joined || diagnostics.Len() != 0 {
					t.Fatal("cancellation returned before active work stopped or emitted a success")
				}
			})
		})
	}
}

type failedWriter struct{}

func (failedWriter) Write([]byte) (int, error) {
	return 0, errors.New("synthetic-private-output-error")
}

func TestLoopRejectsInvalidDependenciesAndOutputFailure(t *testing.T) {
	t.Parallel()
	collect := func(context.Context) (policy.DirectorySnapshot, error) { return testSnapshot(time.Now().UTC()), nil }
	submit := func(context.Context, policy.DirectorySnapshot) (ipc.Receipt, error) {
		return testReceipt(ipc.StatusShadow), nil
	}
	for _, test := range []struct {
		name        string
		hasContext  bool
		collect     collectFunc
		submit      submitFunc
		diagnostics io.Writer
	}{
		{name: "missing context", collect: collect, submit: submit, diagnostics: io.Discard},
		{name: "missing collector", hasContext: true, submit: submit, diagnostics: io.Discard},
		{name: "missing submitter", hasContext: true, collect: collect, diagnostics: io.Discard},
		{name: "missing diagnostics", hasContext: true, collect: collect, submit: submit},
		{name: "failed diagnostics", hasContext: true, collect: collect, submit: submit, diagnostics: failedWriter{}},
	} {
		t.Run(test.name, func(t *testing.T) {
			var ctx context.Context
			if test.hasContext {
				ctx = t.Context()
			}
			if err := runLoop(ctx, test.collect, test.submit, test.diagnostics); !errors.Is(err, errRuntime) {
				t.Fatal("invalid dependency or diagnostic failure ignored")
			}
		})
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if err := runLoop(ctx, collect, submit, io.Discard); !errors.Is(err, context.Canceled) {
		t.Fatal("already-canceled loop started work")
	}
}
