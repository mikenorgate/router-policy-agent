package radius

import (
	"encoding/json"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/mikenorgate/router-policy-agent/internal/binding"
)

func bindingPublisherFixture(t *testing.T, now time.Time) (BindingPublisherOptions, Collection) {
	t.Helper()
	options := fixtureCollectorOptions()
	placement := fixturePlacementOptions()
	placement.BindingMode = placementGuarded
	options.Placement = &placement
	originalTime := fixtureTime().Add(75 * time.Second)
	candidate, err := MatchIPv4(currentSession(t), fixtureLeaseObservation(), fixtureLeaseScope(), originalTime)
	if err != nil {
		t.Fatal(err)
	}
	record, err := bindPlacement(candidate, fixturePlacement(), fixtureLeaseScope(), placement, originalTime)
	if err != nil {
		t.Fatal(err)
	}
	shift := now.Sub(originalTime)
	record.AssociatedAt = record.AssociatedAt.Add(shift)
	record.Addresses[0].ObservedAt = record.Addresses[0].ObservedAt.Add(shift)
	record.Addresses[0].ValidUntil = record.Addresses[0].ValidUntil.Add(shift)
	return BindingPublisherOptions{
			Collector: options, Directory: "/synthetic/private", ManagedMACs: []string{record.MAC},
		}, Collection{
			ObservedAt: now, Generation: strings.Repeat("a", 64), PlacementChecked: true,
			PlacementMode: placementGuarded, ProposedBindings: []binding.Record{record},
		}
}

func TestBindingExportPreservesEvidenceAndRestrictsEnrollment(t *testing.T) {
	t.Parallel()
	now := fixtureTime().Add(75 * time.Second)
	options, collected := bindingPublisherFixture(t, now)
	want := collected.ProposedBindings[0]
	wantAddress := want.Addresses[0]
	snapshot, err := collectedBindings(collected, options, now)
	if err != nil {
		t.Fatal(err)
	}
	got := snapshot.Records[0]
	if got.AssociatedAt != want.AssociatedAt || got.AssociationID != want.AssociationID || got.Addresses[0] != want.Addresses[0] {
		t.Fatal("export replaced original identity, evidence times or expiry")
	}
	collected.ProposedBindings[0].Addresses[0].ValidUntil = now.Add(time.Hour)
	if snapshot.Records[0].Addresses[0] != wantAddress {
		t.Fatal("export shares mutable address storage with collection")
	}
	options.ManagedMACs = []string{"02:aa:bb:cc:dd:ff"}
	snapshot, err = collectedBindings(collected, options, now)
	if err != nil || !snapshot.Complete || len(snapshot.Records) != 0 {
		t.Fatal("unenrolled association was exported")
	}
}

func TestBindingExportRequiresGuardedFreshScopedEvidence(t *testing.T) {
	t.Parallel()
	for _, test := range []struct {
		name   string
		change func(*BindingPublisherOptions, *Collection)
	}{
		{name: "no placement", change: func(_ *BindingPublisherOptions, c *Collection) { c.PlacementChecked = false }},
		{name: "reachable mode", change: func(_ *BindingPublisherOptions, c *Collection) { c.PlacementMode = placementReachable }},
		{name: "stale association", change: func(_ *BindingPublisherOptions, c *Collection) {
			c.ProposedBindings[0].AssociatedAt = c.ObservedAt.Add(-2 * Freshness)
		}},
		{name: "expired ownership", change: func(_ *BindingPublisherOptions, c *Collection) {
			c.ProposedBindings[0].Addresses[0].ValidUntil = c.ObservedAt
		}},
		{name: "wrong interface", change: func(_ *BindingPublisherOptions, c *Collection) { c.ProposedBindings[0].Interface = "other22" }},
		{name: "wrong vlan", change: func(_ *BindingPublisherOptions, c *Collection) { c.ProposedBindings[0].VLAN++ }},
		{name: "wrong address prefix", change: func(_ *BindingPublisherOptions, c *Collection) {
			c.ProposedBindings[0].Addresses[0].IP = netip.MustParseAddr("203.0.113.80")
		}},
		{name: "duplicate ownership", change: func(_ *BindingPublisherOptions, c *Collection) {
			c.ProposedBindings = append(c.ProposedBindings, c.ProposedBindings[0])
		}},
		{name: "unqualified source", change: func(_ *BindingPublisherOptions, c *Collection) {
			c.ProposedBindings[0].Addresses[0].Source = "radius"
		}},
		{name: "empty enrollment", change: func(o *BindingPublisherOptions, _ *Collection) { o.ManagedMACs = []string{} }},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			now := fixtureTime().Add(75 * time.Second)
			options, collected := bindingPublisherFixture(t, now)
			test.change(&options, &collected)
			if _, err := collectedBindings(collected, options, now); err == nil {
				t.Fatal("unsafe binding admitted")
			}
		})
	}
}

func bindingsRuntimeFixture(t *testing.T) map[string]any {
	t.Helper()
	values := map[string]any{}
	if err := json.Unmarshal(runtimeFixture(), &values); err != nil {
		t.Fatal(err)
	}
	values["mode"] = "bindings"
	values["managed_macs"] = []string{"02:aa:bb:cc:dd:ee"}
	values["host_placement"] = map[string]any{
		"interface": "synthetic22", "parent": "synthetic0", "binding_mode": placementGuarded,
	}
	return values
}

func TestBindingRuntimeCannotAccidentallyPromoteShadow(t *testing.T) {
	t.Parallel()
	for _, test := range []struct {
		name   string
		change func(map[string]any)
		allow  bool
	}{
		{name: "explicit native binding mode", allow: true, change: func(map[string]any) {}},
		{name: "shadow mode", change: func(v map[string]any) { v["mode"] = "shadow" }},
		{name: "missing enrollment", change: func(v map[string]any) { delete(v, "managed_macs") }},
		{name: "duplicate enrollment", change: func(v map[string]any) {
			v["managed_macs"] = []string{"02:aa:bb:cc:dd:ee", "02:aa:bb:cc:dd:ee"}
		}},
		{name: "noncanonical enrollment", change: func(v map[string]any) { v["managed_macs"] = []string{"02AABBCCDDEE"} }},
		{name: "missing placement", change: func(v map[string]any) { delete(v, "host_placement") }},
		{name: "neighbor reachability only", change: func(v map[string]any) {
			v["host_placement"] = map[string]any{"interface": "synthetic22", "parent": "synthetic0"}
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			values := bindingsRuntimeFixture(t)
			test.change(values)
			data, err := json.Marshal(values)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := decodeBindingsRuntimeConfig(data); (err == nil) != test.allow {
				t.Fatal("unexpected binding mode admission")
			}
			if _, err := decodeRuntimeConfig(data); err == nil {
				t.Fatal("shadow entry point admitted binding configuration")
			}
		})
	}
	if _, err := decodeBindingsRuntimeConfig(runtimeFixture()); err == nil {
		t.Fatal("shadow configuration admitted as binding authority")
	}
}
