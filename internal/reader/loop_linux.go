// Package reader runs fresh directory collections through the local helper boundary.
// It neither obtains network bindings nor chooses privileged enforcement inputs.
package reader

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"time"

	"github.com/mikenorgate/router-policy-agent/internal/ipc"
	"github.com/mikenorgate/router-policy-agent/internal/policy"
)

const refreshInterval = 30 * time.Second
const cycleTimeout = 10 * time.Second

var errRuntime = errors.New("reader: runtime unavailable")

type collectFunc func(context.Context) (policy.DirectorySnapshot, error)
type submitFunc func(context.Context, policy.DirectorySnapshot) (ipc.Receipt, error)

// attempt contains only locally selected outcomes and bounded receipt counts.
// Upstream errors, identities and policy contents never enter the log sink.
type attempt struct {
	SchemaVersion int    `json:"schema_version"`
	Outcome       string `json:"outcome"`
	GrantCount    int    `json:"grant_count"`
	DenialCount   int    `json:"denial_count"`
}

// runLoop is synchronous: a poll cannot overlap another poll or queue a snapshot.
// A failed submission is never retried; the next poll starts a new collection.
// Dependencies must honor their context and join their own I/O before returning.
func runLoop(ctx context.Context, collect collectFunc, submit submitFunc, diagnostics io.Writer) error {
	if ctx == nil || collect == nil || submit == nil || diagnostics == nil {
		return errRuntime
	}
	timer := time.NewTimer(0)
	defer timer.Stop()
	encoder := json.NewEncoder(diagnostics)
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-timer.C:
		}
		if err := ctx.Err(); err != nil {
			return err
		}
		started := time.Now()
		result, err := runCycle(ctx, collect, submit)
		if err != nil {
			return err
		}
		if err := encoder.Encode(result); err != nil {
			return errRuntime
		}
		// Schedule from the start, not the end, of this bounded attempt. If an
		// attempt overruns, skip missed polls rather than sending a catch-up burst.
		wait := refreshInterval - time.Since(started)
		if wait <= 0 {
			wait = refreshInterval
		}
		timer.Reset(wait)
	}
}

func runCycle(ctx context.Context, collect collectFunc, submit submitFunc) (attempt, error) {
	bounded, cancel := context.WithTimeout(ctx, cycleTimeout)
	defer cancel()
	result := attempt{SchemaVersion: 1, Outcome: "collection_failed"}
	snapshot, err := collect(bounded)
	if ctx.Err() != nil {
		return attempt{}, ctx.Err()
	}
	if err != nil || bounded.Err() != nil {
		return result, nil
	}
	// Keep the collector's observation time intact. The helper independently
	// checks completeness, freshness, replay, bindings and its protected floor.
	receipt, err := submit(bounded, snapshot)
	if ctx.Err() != nil {
		return attempt{}, ctx.Err()
	}
	result.Outcome = "submission_failed"
	if bounded.Err() != nil {
		return result, nil
	}
	if errors.Is(err, ipc.ErrRejected) {
		result.Outcome = "rejected"
		return result, nil
	}
	if err != nil {
		return result, nil
	}
	switch receipt.Status {
	case ipc.StatusShadow:
		result.Outcome = "shadow"
	case ipc.StatusApplied:
		result.Outcome = "applied"
	default:
		return result, nil
	}
	result.GrantCount, result.DenialCount = receipt.GrantCount, receipt.DenialCount
	return result, nil
}
