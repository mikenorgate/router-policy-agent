//go:build integration && linux

package firewall

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"
)

func TestMain(main *testing.M) {
	if os.Args[0] == "nft" {
		os.Exit(runProcessFixture())
	}
	os.Exit(main.Run())
}

// runProcessFixture is a self-executed synthetic ELF, not an nftables backend.
// It proves descriptor execution, fixed arguments, environment isolation,
// cancellation and bounded/redacted output without a network capability.
func runProcessFixture() int {
	name, err := os.Readlink("/proc/self/exe")
	if err != nil {
		return 1
	}
	switch {
	case strings.HasSuffix(name, "nft-error"):
		if _, err := fmt.Fprint(os.Stderr, "synthetic-confidential-diagnostic"); err != nil {
			return 1
		}
		return 42
	case strings.HasSuffix(name, "nft-sleep"):
		time.Sleep(10 * time.Second)
	case strings.HasSuffix(name, "nft-output"):
		block := []byte(strings.Repeat("x", 64<<10))
		for range 300 {
			if _, err := os.Stdout.Write(block); err != nil {
				return 1
			}
		}
		return 0
	case strings.HasSuffix(name, "nft-inventory"):
		if err := json.NewEncoder(os.Stdout).Encode(map[string]any{"nftables": listingFixtureObjects()}); err != nil {
			return 1
		}
		return 0
	}
	data, err := io.ReadAll(io.LimitReader(os.Stdin, maximumBatch+1))
	if err != nil {
		return 1
	}
	result := struct {
		Arguments []string `json:"arguments"`
		Env       []string `json:"env"`
		Bytes     int      `json:"bytes"`
	}{Arguments: os.Args[1:], Env: os.Environ(), Bytes: len(data)}
	if err := json.NewEncoder(os.Stdout).Encode(result); err != nil {
		return 1
	}
	return 0
}

func processFixture(t *testing.T, name string) (*process, string) {
	t.Helper()
	if os.Geteuid() != 0 {
		t.Skip("root-owned executable fixture runs in the isolated root CI job")
	}
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	// #nosec G304 -- The source is this test's own os.Executable result.
	source, err := os.Open(executable)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), name)
	// #nosec G304 G302 -- Fresh test directory, exclusive executable fixture.
	target, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o755)
	if err != nil {
		t.Fatal(errors.Join(err, source.Close()))
	}
	_, copyError := io.Copy(target, source)
	if err := errors.Join(copyError, target.Close(), source.Close()); err != nil {
		t.Fatal(err)
	}
	process, err := openProcess(t.Context(), path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if process.executable != nil {
			if err := process.close(); err != nil {
				t.Error(err)
			}
		}
	})
	return process, path
}

func TestProcessPinsExecutableAndRestrictsArguments(t *testing.T) {
	t.Parallel()
	process, path := processFixture(t, "nft-fixture")
	// Replace only this freshly created fixture after opening it. A pathname
	// execution would now fail or run a script; the pinned ELF must still run.
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	// #nosec G306 -- Deliberately invalid replacement in a fresh test directory.
	if err := os.WriteFile(path, []byte("#!/bin/sh\nexit 99\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		name      string
		op        operation
		payload   []byte
		arguments []string
	}{
		{name: "inspect", op: inspectOwned, arguments: []string{"--json", "list", "table", "inet", ownedTable}},
		{name: "inspect final egress", op: inspectGuardEgress, arguments: []string{"--json", "list", "table", "netdev", ownedTable}},
		{name: "inspect complete ruleset", op: inspectWholeRuleset, arguments: []string{"--json", "list", "ruleset"}},
		{name: "apply", op: applyOwned, payload: clearBatch(t), arguments: []string{"--json", "--file", "-"}},
	} {
		t.Run(test.name, func(t *testing.T) {
			data, err := process.execute(t.Context(), test.op, test.payload)
			if err != nil {
				t.Fatal(err)
			}
			var observed struct {
				Arguments []string `json:"arguments"`
				Env       []string `json:"env"`
				Bytes     int      `json:"bytes"`
			}
			if err := json.Unmarshal(data, &observed); err != nil {
				t.Fatal(err)
			}
			if !slices.Equal(observed.Arguments, test.arguments) || observed.Bytes != len(test.payload) ||
				!slices.Equal(observed.Env, []string{"LC_ALL=C", "PATH=/usr/sbin:/usr/bin"}) {
				t.Fatalf("unexpected privilege boundary: %+v", observed)
			}
		})
	}
	if _, err := process.execute(t.Context(), operation(99), nil); err == nil {
		t.Fatal("accepted unknown operation")
	}
	if _, err := process.execute(t.Context(), inspectOwned, clearBatch(t)); err == nil {
		t.Fatal("inspection accepted a program")
	}
	if _, err := process.execute(t.Context(), inspectGuardEgress, clearBatch(t)); err == nil {
		t.Fatal("egress inspection accepted a program")
	}
	if _, err := process.execute(t.Context(), inspectWholeRuleset, clearBatch(t)); err == nil {
		t.Fatal("complete inspection accepted a program")
	}
	arbitrary := []byte(`{"nftables":[{"flush":{"ruleset":null}}]}`)
	if _, err := process.execute(t.Context(), applyOwned, arbitrary); err == nil {
		t.Fatal("accepted an arbitrary program")
	}
	for _, operation := range []operation{applyGuarded, sealGuarded} {
		for _, payload := range [][]byte{nil, clearBatch(t), arbitrary} {
			if _, err := process.execute(t.Context(), operation, payload); err == nil {
				t.Fatal("raw executor bypassed trusted guarded preparation")
			}
		}
	}
	if err := process.close(); err != nil {
		t.Fatal(err)
	}
	if _, err := process.execute(t.Context(), inspectOwned, nil); !errors.Is(err, os.ErrClosed) {
		t.Fatalf("used a closed executor: %v", err)
	}
}

func TestProcessFailureAndCancellation(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name string
		file string
	}{
		{name: "diagnostic redaction", file: "nft-error"},
		{name: "output quota", file: "nft-output"},
		{name: "deadline", file: "nft-sleep"},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			process, _ := processFixture(t, test.file)
			ctx, cancel := context.WithTimeout(t.Context(), 100*time.Millisecond)
			defer cancel()
			if test.file != "nft-sleep" {
				ctx = t.Context()
			}
			data, err := process.execute(ctx, inspectOwned, nil)
			if err == nil || len(data) != 0 || strings.Contains(err.Error(), "synthetic-confidential-diagnostic") {
				t.Fatalf("failed command leaked a response or diagnostic: %v", err)
			}
			if test.file == "nft-sleep" && !errors.Is(err, context.DeadlineExceeded) {
				t.Fatalf("deadline was not propagated: %v", err)
			}
		})
	}
}

func TestProcessGuardInspectionDoesNotTrustOtherObjects(t *testing.T) {
	t.Parallel()
	layout, _ := guardListingFixture(t, false)
	for _, name := range []string{"nft-fixture", "nft-inventory"} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			process, _ := processFixture(t, name)
			if inventory, err := process.inspectGuards(t.Context(), layout); err == nil || inventory != nil {
				t.Fatal("unverified or set-only observations became guarded inventory")
			}
			if _, err := process.inspectGuards(t.Context(), nil); err == nil {
				t.Fatal("guard inspection accepted a missing root layout")
			}
			ctx, cancel := context.WithCancel(t.Context())
			cancel()
			if _, err := process.inspectGuards(ctx, layout); !errors.Is(err, context.Canceled) {
				t.Fatal("guard inspection lost cancellation")
			}
			if err := process.close(); err != nil {
				t.Fatal(err)
			}
			if _, err := process.inspectGuards(t.Context(), layout); !errors.Is(err, os.ErrClosed) {
				t.Fatal("guard inspection used a closed executor")
			}
		})
	}
}

func TestProcessRulesetInspectionRejectsIncompleteEvidence(t *testing.T) {
	t.Parallel()
	contract := reviewedRulesetFixture(t)
	layout, _ := guardListingFixture(t, false)
	for _, name := range []string{"nft-fixture", "nft-inventory", "nft-error"} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			process, _ := processFixture(t, name)
			if observation, err := process.inspectRuleset(t.Context(), contract, layout); err == nil || observation != nil {
				t.Fatal("incomplete listing or failed command produced verified ruleset evidence")
			}
			if _, err := process.inspectRuleset(t.Context(), nil, layout); err == nil {
				t.Fatal("complete inspection accepted missing reviewed objects")
			}
			if _, err := process.inspectRuleset(t.Context(), contract, nil); err == nil {
				t.Fatal("complete inspection accepted missing helper geometry")
			}
			ctx, cancel := context.WithCancel(t.Context())
			cancel()
			if _, err := process.inspectRuleset(ctx, contract, layout); !errors.Is(err, context.Canceled) {
				t.Fatal("complete inspection lost cancellation")
			}
			if err := process.close(); err != nil {
				t.Fatal(err)
			}
			if _, err := process.inspectRuleset(t.Context(), contract, layout); !errors.Is(err, os.ErrClosed) {
				t.Fatal("complete inspection used a closed executor")
			}
		})
	}
}

func TestPreparedProcessRejectsDelayClockChangesAndUnboundedPrograms(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name   string
		change func(*preparedBatch) *preparedBatch
	}{
		{name: "missing transaction", change: func(*preparedBatch) *preparedBatch { return nil }},
		{name: "missing clock", change: func(b *preparedBatch) *preparedBatch {
			b.preparedAt = time.Time{}
			return b
		}},
		{name: "missing monotonic fence", change: func(b *preparedBatch) *preparedBatch {
			b.startedAt = time.Time{}
			return b
		}},
		{name: "expired monotonic fence with fresh wall metadata", change: func(b *preparedBatch) *preparedBatch {
			b.startedAt = b.startedAt.Add(-time.Hour)
			return b
		}},
		{name: "future monotonic fence", change: func(b *preparedBatch) *preparedBatch {
			b.startedAt = b.startedAt.Add(time.Hour)
			return b
		}},
		{name: "extended preparation window", change: func(b *preparedBatch) *preparedBatch {
			b.startBefore = b.startBefore.Add(time.Hour)
			return b
		}},
		{name: "clock rollback", change: func(b *preparedBatch) *preparedBatch {
			b.preparedAt = b.preparedAt.Add(time.Hour)
			b.startBefore = b.preparedAt.Add(preparationBudget)
			return b
		}},
		{name: "expired preparation", change: func(b *preparedBatch) *preparedBatch {
			b.preparedAt = b.preparedAt.Add(-time.Hour)
			b.startBefore = b.preparedAt.Add(preparationBudget)
			return b
		}},
		{name: "arbitrary program", change: func(b *preparedBatch) *preparedBatch {
			b.data = []byte(`{"nftables":[{"flush":{"ruleset":null}}]}`)
			return b
		}},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			process, _ := processFixture(t, "nft-fixture")
			now := time.Now()
			batch := &preparedBatch{
				data: clearBatch(t), preparedAt: now, startBefore: now.Add(preparationBudget), startedAt: time.Now(),
			}
			if err := process.applyPrepared(t.Context(), test.change(batch)); err == nil {
				t.Fatal("unsafe prepared transaction reached the child")
			}
		})
	}
	process, _ := processFixture(t, "nft-inventory")
	now := time.Now()
	batch := &preparedBatch{
		data: clearBatch(t), preparedAt: now, startBefore: now.Add(preparationBudget), startedAt: time.Now(),
	}
	if err := process.applyPrepared(t.Context(), batch); err != nil {
		t.Fatalf("valid prepared transaction rejected: %v", err)
	}
}

func TestProcessVerifiesListingBeforeMutation(t *testing.T) {
	t.Parallel()
	for _, name := range []string{"nft-inventory", "nft-fixture", "nft-error"} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			process, _ := processFixture(t, name)
			inventory, err := process.inspectSets(t.Context())
			if name == "nft-inventory" {
				if err != nil || inventory == nil || inventory.leases != 1 {
					t.Fatalf("complete observation rejected: %v", err)
				}
				return
			}
			if err == nil || inventory != nil {
				t.Fatal("unverified listing produced an inventory")
			}
			now := time.Now()
			batch := &preparedBatch{
				data: clearBatch(t), preparedAt: now, startBefore: now.Add(preparationBudget), startedAt: time.Now(),
			}
			if err := process.applyPrepared(t.Context(), batch); err == nil {
				t.Fatal("prepared mutation accepted an unverified listing")
			}
		})
	}
}
