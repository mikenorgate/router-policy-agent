package agent

import (
	"encoding/json"
	"github.com/mikenorgate/router-policy-agent/internal/ipc"
	"slices"
	"strings"
	"testing"
)

func TestProvenanceCannotRenewOrBlockEnforcement(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	engine := f.engine(t, f.options(Enforce))
	if _, err := engine.Process(t.Context(), f.directory); err != nil {
		t.Fatal(err)
	}
	before := slices.Clone(f.events)
	clock := engine.clock
	// Occupy the engine transaction gate. Observation queries must still return.
	engine.gate <- struct{}{}
	defer func() { <-engine.gate }()
	request := ipc.ObservationRequest{SchemaVersion: 1, Operation: "observations"}
	first, err := engine.Observations(t.Context(), request)
	if err != nil || first.Snapshot == nil || len(first.Snapshot.Grants) != 1 || len(first.Snapshot.Grants[0].Contributors) != 1 {
		t.Fatal(first, err)
	}
	expiry := first.Snapshot.Grants[0].Contributors[0].ExpiresAt
	first.Snapshot.Grants[0].Contributors[0].GroupID = "mutated"
	again, err := engine.Observations(t.Context(), request)
	if err != nil || again.Snapshot.Grants[0].Contributors[0].GroupID == "mutated" || !again.Snapshot.Grants[0].Contributors[0].ExpiresAt.Equal(expiry) {
		t.Fatal("mutable snapshot or refreshed deadline")
	}
	if !slices.Equal(before, f.events) || engine.clock != clock {
		t.Fatal("observations changed persistence, bindings, firewall or clock")
	}
	body, _ := json.Marshal(again)
	if strings.Contains(string(body), "reason") || strings.Contains(string(body), "network_policy_v1") {
		t.Fatal("raw directory text retained")
	}
	request.Generation = "other"
	changed, err := engine.Observations(t.Context(), request)
	if err != nil || changed.Code != "generation_changed" {
		t.Fatal(changed, err)
	}
}
