//go:build integration && kernel && linux

package firewall

import (
	"context"
	"encoding/json"
	"maps"
	"slices"
	"strings"
	"testing"
	"time"
)

// Interval sets cannot be packet-deleted by nft's dynamic-set statement. Model
// a stale early lookup with test-only copies, while withdrawing the REAL late
// leases and retaining final mirrors. Witness counters between the hooks prove
// packets reach the late interval gate with provisional authorization. This is
// not a concurrent-writer timing test or a production mutation facility.
func staleEarlyLeaseFixture(ctx context.Context, t *testing.T, layout *guardLayout, names ...string) func() {
	t.Helper()
	schema, err := layout.schema("inet")
	if err != nil {
		t.Fatal(err)
	}
	var listing struct {
		Objects []struct {
			Set *listedSet `json:"set"`
		} `json:"nftables"`
	}
	if err := json.Unmarshal(kernelFixtureCommand(ctx, t, "list", "table", "inet", ownedTable), &listing); err != nil {
		t.Fatal(err)
	}
	values := map[string][]json.RawMessage{}
	for _, object := range listing.Objects {
		if object.Set != nil && slices.Contains(names, object.Set.Name) {
			values[object.Set.Name], err = listedGuardLeases(ctx, object.Set.Elements)
			if err != nil {
				t.Fatal(err)
			}
		}
	}
	commands := []any{}
	for _, name := range names {
		if schema.sets[name] == nil || len(values[name]) == 0 {
			t.Fatal("stale-lookup fixture lacks a populated owned lease")
		}
		header := maps.Clone(schema.sets[name])
		header["name"] = "fixture_early_" + name
		commands = append(commands, map[string]any{"add": map[string]any{"set": header}},
			guardAdd("inet", "fixture_early_"+name, values[name]))
	}
	earlyRules := func(stale bool) []any {
		operations := []any{map[string]any{"flush": map[string]any{"chain": ownedRef("guard_forward")}}}
		for _, expressions := range schema.rules["guard_forward"] {
			raw, err := json.Marshal(expressions)
			if err != nil {
				t.Fatal(err)
			}
			if stale {
				for _, name := range names {
					raw = []byte(strings.ReplaceAll(string(raw), `"@`+name+`"`, `"@fixture_early_`+name+`"`))
				}
			}
			operations = append(operations, map[string]any{"add": map[string]any{"rule": map[string]any{
				"family": "inet", "table": ownedTable, "chain": "guard_forward", "expr": json.RawMessage(raw),
			}}})
		}
		return operations
	}
	commands = append(commands, earlyRules(true)...)
	for _, name := range names {
		commands = append(commands, change{Flush: &setChange{Set: ownedRef(name)}})
	}
	apply := func(ctx context.Context, operations []any) {
		t.Helper()
		data, err := json.Marshal(map[string]any{"nftables": operations})
		if err != nil {
			t.Fatal(err)
		}
		executeGuardFixture(ctx, t, data)
	}
	apply(ctx, commands)
	isRestored := false
	restore := func() {
		t.Helper()
		if isRestored {
			return
		}
		cleanup, cancel := context.WithTimeout(context.WithoutCancel(t.Context()), 3*time.Second)
		defer cancel()
		operations := earlyRules(false)
		for _, name := range names {
			operations = append(operations, map[string]any{"delete": map[string]any{"set": ownedRef("fixture_early_" + name)}})
		}
		apply(cleanup, operations)
		isRestored = true
	}
	t.Cleanup(restore)
	return restore
}
