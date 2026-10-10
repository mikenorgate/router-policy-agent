package radius

import (
	"context"
	"encoding/json"
	"errors"
	"net/netip"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/mikenorgate/router-policy-agent/internal/binding"
	"github.com/mikenorgate/router-policy-agent/internal/kea"
)

func fixturePlacementOptions() PlacementOptions {
	return PlacementOptions{Interface: "synthetic22", Parent: "synthetic0", VLAN: 22, Timeout: time.Second}
}

func fixturePlacementLinks() []byte {
	return []byte(`[{"ifindex":2,"ifname":"synthetic0","link_type":"ether","address":"02:00:00:00:00:01","flags":["UP","LOWER_UP"]},{"ifindex":3,"ifname":"synthetic22","link":"synthetic0","link_type":"ether","address":"02:00:00:00:00:01","flags":["UP","LOWER_UP"],"operstate":"UP","linkinfo":{"info_kind":"vlan","info_data":{"id":22,"protocol":"802.1Q"}}}]`)
}

func fixturePlacement() placementObservation {
	return placementObservation{
		observedAt: fixtureTime().Add(74 * time.Second), identity: strings.Repeat("a", 64),
		neighbors: []ipv4Neighbor{{ip: netip.MustParseAddr("192.0.2.80"), mac: "02:aa:bb:cc:dd:ee", confirmedAt: fixtureTime().Add(20 * time.Second)}},
	}
}

func TestPlacementPinnedLinkGeometry(t *testing.T) {
	t.Parallel()
	valid, err := decodePlacementLinks(fixturePlacementLinks(), fixturePlacementOptions())
	if err != nil || valid.index != 3 || valid.parent != 2 {
		t.Fatalf("valid vlan path rejected: %v", err)
	}
	for _, test := range []struct{ name, from, to string }{
		{"wrong vlan", `"id":22`, `"id":23`},
		{"wrong parent", `"link":"synthetic0"`, `"link":"other"`},
		{"wrong kind", `"info_kind":"vlan"`, `"info_kind":"bridge"`},
		{"wrong protocol", `"802.1Q"`, `"802.1ad"`},
		{"down link", `"UP","LOWER_UP"`, `"LOWER_UP"`},
		{"no carrier", `"UP","LOWER_UP"`, `"UP"`},
		{"down operational state", `"operstate":"UP"`, `"operstate":"DOWN"`},
		{"duplicate index", `"ifindex":3`, `"ifindex":2`},
		{"duplicate name", `"ifname":"synthetic22"`, `"ifname":"synthetic0"`},
		{"duplicate key", `"id":22`, `"id":22,"id":22`},
		{"foreign namespace", `"operstate":"UP"`, `"operstate":"UP","link_netnsid":0`},
		{"enslaved link", `"operstate":"UP"`, `"operstate":"UP","master":"bridge0"`},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			data := []byte(strings.ReplaceAll(string(fixturePlacementLinks()), test.from, test.to))
			if _, err := decodePlacementLinks(data, fixturePlacementOptions()); err == nil {
				t.Fatal("unqualified host path accepted")
			}
		})
	}
}

func TestPlacementNeighborsKeepKernelConfirmationTime(t *testing.T) {
	t.Parallel()
	data := []byte(`[{"dst":"192.0.2.80","dev":"synthetic22","lladdr":"02:aa:bb:cc:dd:ee","state":["REACHABLE"],"used":0,"confirmed":10,"updated":0}]`)
	now := fixtureTime().Add(75 * time.Second)
	first, err := decodePlacementNeighbors(data, "synthetic22", now)
	if err != nil || len(first) != 1 || first[0].confirmedAt != now.Add(-11*time.Second) {
		t.Fatalf("kernel age not conservatively retained: %v", err)
	}
	reread := []byte(strings.Replace(string(data), `"confirmed":10`, `"confirmed":11`, 1))
	last, err := decodePlacementNeighbors(reread, "synthetic22", now.Add(time.Second))
	if err != nil || !slices.Equal(first, last) {
		t.Fatal("cache reread refreshed original placement")
	}
	for _, test := range []struct{ name, from, to string }{
		{"wrong interface", `synthetic22`, `other`},
		{"stale state", `REACHABLE`, `STALE`},
		{"permanent", `REACHABLE`, `PERMANENT`},
		{"probe", `REACHABLE`, `PROBE`},
		{"multiple states", `"REACHABLE"`, `"REACHABLE","STALE"`},
		{"expired confirmation", `"confirmed":10`, `"confirmed":90`},
		{"missing confirmation", `"confirmed":10,`, ``},
		{"null confirmation", `"confirmed":10`, `"confirmed":null`},
		{"negative confirmation", `"confirmed":10`, `"confirmed":-1`},
		{"overflow confirmation", `"confirmed":10`, `"confirmed":4294967296`},
		{"noncanonical mac", `02:aa:bb:cc:dd:ee`, `02AABBCCDDEE`},
		{"proxy", `"used":0`, `"proxy":null,"used":0`},
		{"externally learned", `"used":0`, `"extern_learn":null,"used":0`},
		{"offload", `"used":0`, `"offload":null,"used":0`},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			input := []byte(strings.ReplaceAll(string(data), test.from, test.to))
			got, err := decodePlacementNeighbors(input, "synthetic22", now)
			if err != nil || len(got) != 0 {
				t.Fatal("unqualified neighbor retained")
			}
		})
	}
	for _, input := range [][]byte{
		[]byte("null"), []byte("[null]"), append(data, []byte("[]")...),
		[]byte(strings.Replace(string(data), `"confirmed":10`, `"confirmed":10,"confirmed":10`, 1)),
		[]byte("[" + string(data[1:len(data)-1]) + "," + string(data[1:len(data)-1]) + "]"),
	} {
		if _, err := decodePlacementNeighbors(input, "synthetic22", now); err == nil {
			t.Fatal("ambiguous placement source accepted")
		}
	}
}

func TestBindPlacementClipsAndWithholds(t *testing.T) {
	t.Parallel()
	now := fixtureTime().Add(75 * time.Second)
	candidate, err := MatchIPv4(currentSession(t), fixtureLeaseObservation(), fixtureLeaseScope(), now)
	if err != nil {
		t.Fatal(err)
	}
	first, err := bindPlacement(candidate, fixturePlacement(), fixtureLeaseScope(), "synthetic22", now)
	if err != nil || first.Interface != "synthetic22" || first.VLAN != 22 || first.Addresses[0].ValidUntil != fixtureTime().Add(110*time.Second) {
		t.Fatalf("placement did not clip binding to original confirmation: %v", err)
	}
	if err := binding.Validate(binding.Snapshot{
		SchemaVersion: 1, Complete: true, Generation: strings.Repeat("b", 64), ObservedAt: now,
		Records: []binding.Record{first},
	}, now, Freshness, 16); err != nil {
		t.Fatal("proposed record does not satisfy the existing binding shape")
	}
	for _, name := range []string{"missing", "wrong mac", "duplicate", "expired", "future", "predates session", "stale source", "foreign ownership"} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			placement := fixturePlacement()
			value := candidate
			switch name {
			case "missing":
				placement.neighbors = []ipv4Neighbor{}
			case "wrong mac":
				placement.neighbors[0].mac = "02:aa:bb:cc:dd:ff"
			case "duplicate":
				placement.neighbors = append(placement.neighbors, placement.neighbors[0])
			case "expired":
				placement.neighbors[0].confirmedAt = now.Add(-Freshness)
			case "future":
				placement.neighbors[0].confirmedAt = now.Add(time.Second)
			case "predates session":
				placement.neighbors[0].confirmedAt = value.Session.StartedAt.Add(-time.Second)
			case "stale source":
				placement.observedAt = now.Add(-Freshness)
			case "foreign ownership":
				value.OwnershipID = strings.Repeat("f", 64)
			}
			if got, err := bindPlacement(value, placement, fixtureLeaseScope(), "synthetic22", now); err == nil || got.MAC != "" {
				t.Fatal("unqualified placement produced a record")
			}
		})
	}
}

func TestCollectorPlacementRecheck(t *testing.T) {
	t.Parallel()
	for _, name := range []string{"steady", "advanced confirmation", "missing first", "missing", "changed mac", "first loss", "last loss", "changed link", "expired at end"} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			options := fixtureCollectorOptions()
			placementOptions := fixturePlacementOptions()
			options.Placement = &placementOptions
			captured := fixtureCapturedHistory(t)
			calls := 0
			got, err := collectIPv4(t.Context(), options, collectionSources{
				history: func(context.Context) (history, error) { return captured, nil },
				lease:   func(context.Context, string) (kea.Observation, error) { return fixtureLeaseObservation(), nil },
				now:     func() time.Time { return captured.observedAt },
				placement: func(context.Context) (placementObservation, error) {
					calls++
					value := fixturePlacement()
					if name == "missing first" && calls == 1 {
						value.neighbors = []ipv4Neighbor{}
					}
					if name == "first loss" || name == "last loss" && calls == 2 {
						return placementObservation{}, errors.New("synthetic source loss")
					}
					if calls == 2 {
						switch name {
						case "advanced confirmation":
							value.neighbors[0].confirmedAt = captured.observedAt.Add(-time.Second)
						case "missing":
							value.neighbors = []ipv4Neighbor{}
						case "changed mac":
							value.neighbors[0].mac = "02:aa:bb:cc:dd:ff"
						case "changed link":
							value.identity = strings.Repeat("b", 64)
						case "expired at end":
							value.neighbors[0].confirmedAt = captured.observedAt.Add(-Freshness)
						}
					}
					return value, nil
				},
			})
			failed := name == "first loss" || name == "last loss" || name == "changed link"
			if failed {
				if err == nil || len(got.Candidates) != 0 || len(got.ProposedBindings) != 0 {
					t.Fatal("source loss or geometry change returned a collection")
				}
				return
			}
			if err != nil || !got.PlacementChecked || len(got.Candidates) != 1 {
				t.Fatalf("shadow correlation failed: %v", err)
			}
			if name == "steady" || name == "advanced confirmation" {
				if len(got.ProposedBindings) != 1 || got.PlacementWithheld != 0 {
					t.Fatal("matching placement not proposed")
				}
				if got.ProposedBindings[0].Addresses[0].ValidUntil != fixtureTime().Add(110*time.Second) {
					t.Fatal("placement recheck extended original deadline")
				}
			} else if len(got.ProposedBindings) != 0 || got.PlacementWithheld != 1 {
				t.Fatal("unqualified placement survived recheck")
			}
		})
	}
}

func TestRuntimePlacementIsExplicitAndStrict(t *testing.T) {
	t.Parallel()
	for _, test := range []struct {
		name, value string
		accepted    bool
	}{
		{name: "valid", value: `{"interface":"synthetic22","parent":"synthetic0"}`, accepted: true},
		{name: "null", value: `null`},
		{name: "missing parent", value: `{"interface":"synthetic22"}`},
		{name: "unknown field", value: `{"interface":"synthetic22","parent":"synthetic0","enabled":true}`},
		{name: "case variant", value: `{"Interface":"synthetic22","parent":"synthetic0"}`},
		{name: "argument injection", value: `{"interface":"--help","parent":"synthetic0"}`},
		{name: "same interface", value: `{"interface":"synthetic0","parent":"synthetic0"}`},
		{name: "loopback", value: `{"interface":"lo","parent":"synthetic0"}`},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			data := []byte(strings.TrimSuffix(string(runtimeFixture()), "}") + `,"host_placement":` + test.value + "}")
			got, err := decodeRuntimeConfig(data)
			if (err == nil) != test.accepted {
				t.Fatal("unexpected placement configuration decision")
			}
			if test.accepted {
				options, err := got.collectorOptions()
				if err != nil || options.Placement == nil || options.Placement.VLAN != got.VLAN {
					t.Fatal("placement scope not derived from collector vlan")
				}
			}
		})
	}
	encoded, err := json.Marshal(Collection{Candidates: []IPv4Candidate{}})
	if err != nil || strings.Contains(string(encoded), "placement") || strings.Contains(string(encoded), "proposed_bindings") {
		t.Fatal("disabled collector wire shape changed")
	}
}
