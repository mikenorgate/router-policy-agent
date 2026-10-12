package radius

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/mikenorgate/router-policy-agent/internal/kea"
)

func TestRuntimeGuardedPlacementMode(t *testing.T) {
	t.Parallel()
	for _, test := range []struct {
		name     string
		mode     string
		accepted bool
	}{
		{name: "omitted strict default", accepted: true},
		{name: "explicit strict", mode: `,"binding_mode":"reachable_neighbor"`, accepted: true},
		{name: "dhcp packet guarded", mode: `,"binding_mode":"dhcp_packet_guarded"`, accepted: true},
		{name: "empty mode", mode: `,"binding_mode":""`},
		{name: "null mode", mode: `,"binding_mode":null`},
		{name: "unknown mode", mode: `,"binding_mode":"ignore_neighbors"`},
		{name: "wrong type", mode: `,"binding_mode":true`},
		{name: "case variant", mode: `,"BindingMode":"dhcp_packet_guarded"`},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			placement := `,"host_placement":{"interface":"synthetic22","parent":"synthetic0"` + test.mode + `}`
			data := []byte(strings.TrimSuffix(string(runtimeFixture()), "}") + placement + "}")
			configuration, err := decodeRuntimeConfig(data)
			if (err == nil) != test.accepted {
				t.Fatalf("placement mode accepted=%v, want %v", err == nil, test.accepted)
			}
			if test.accepted {
				options, err := configuration.collectorOptions()
				if err != nil || options.Placement == nil || options.Placement.BindingMode != configuration.HostPlacement.BindingMode {
					t.Fatal("runtime mode not propagated to collector")
				}
			}
		})
	}
}

func TestGuardedNeighborsAllowIdleButPreserveConflicts(t *testing.T) {
	t.Parallel()
	row := `{"dst":"192.0.2.80","dev":"synthetic22","lladdr":"02:aa:bb:cc:dd:ee","state":["STALE"],"confirmed":3600}`
	for _, test := range []struct {
		name, data string
		allowed    bool
	}{
		{name: "absent", data: `[]`, allowed: true},
		{name: "stale with old confirmation", data: "[" + row + "]", allowed: true},
		{name: "reachable", data: "[" + strings.Replace(row, "STALE", "REACHABLE", 1) + "]", allowed: true},
		{name: "delay", data: "[" + strings.Replace(row, "STALE", "DELAY", 1) + "]", allowed: true},
		{name: "probe", data: "[" + strings.Replace(row, "STALE", "PROBE", 1) + "]", allowed: true},
		{name: "no confirmation", data: "[" + strings.Replace(row, `,"confirmed":3600`, "", 1) + "]", allowed: true},
		{name: "unrelated foreign entry", data: "[" + strings.ReplaceAll(strings.Replace(row, "192.0.2.80", "192.0.2.81", 1), "synthetic22", "other22") + "]", allowed: true},
		{name: "wrong mac", data: "[" + strings.Replace(row, "02:aa:bb:cc:dd:ee", "02:aa:bb:cc:dd:ff", 1) + "]"},
		{name: "foreign interface", data: "[" + strings.Replace(row, "synthetic22", "other22", 1) + "]"},
		{name: "both interfaces", data: "[" + row + "," + strings.Replace(row, "synthetic22", "other22", 1) + "]"},
		{name: "duplicate identity", data: "[" + row + "," + row + "]"},
		{name: "permanent", data: "[" + strings.Replace(row, "STALE", "PERMANENT", 1) + "]"},
		{name: "noarp", data: "[" + strings.Replace(row, "STALE", "NOARP", 1) + "]"},
		{name: "failed", data: "[" + strings.Replace(row, "STALE", "FAILED", 1) + "]"},
		{name: "incomplete", data: "[" + strings.Replace(row, "STALE", "INCOMPLETE", 1) + "]"},
		{name: "unknown state", data: "[" + strings.Replace(row, "STALE", "NEW_STATE", 1) + "]"},
		{name: "multiple states", data: "[" + strings.Replace(row, `"STALE"`, `"STALE","REACHABLE"`, 1) + "]"},
		{name: "missing state", data: "[" + strings.Replace(row, `"state":["STALE"],`, "", 1) + "]"},
		{name: "missing mac", data: "[" + strings.Replace(row, `"lladdr":"02:aa:bb:cc:dd:ee",`, "", 1) + "]"},
		{name: "noncanonical mac", data: "[" + strings.Replace(row, "02:aa:bb:cc:dd:ee", "02AABBCCDDEE", 1) + "]"},
		{name: "null confirmation", data: "[" + strings.Replace(row, "3600", "null", 1) + "]"},
		{name: "negative confirmation", data: "[" + strings.Replace(row, "3600", "-1", 1) + "]"},
		{name: "overflow confirmation", data: "[" + strings.Replace(row, "3600", "4294967296", 1) + "]"},
		{name: "duplicate key", data: "[" + strings.Replace(row, `"confirmed":3600`, `"confirmed":3600,"confirmed":0`, 1) + "]"},
		{name: "ipv6", data: "[" + strings.Replace(row, "192.0.2.80", "2001:db8::80", 1) + "]"},
		{name: "empty interface", data: "[" + strings.Replace(row, "synthetic22", "", 1) + "]"},
		{name: "malformed", data: `[{`},
		{name: "null", data: `null`},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			assertGuardedNeighborBinding(t, []byte(test.data), test.allowed)
		})
	}
	for _, flag := range []string{"proxy", "managed", "extern_learn", "offload", "extern_valid", "router", "deleted", "miss"} {
		t.Run(flag, func(t *testing.T) {
			t.Parallel()
			data := "[" + strings.TrimSuffix(row, "}") + `,"` + flag + `":null}]`
			assertGuardedNeighborBinding(t, []byte(data), false)
		})
	}
}

func assertGuardedNeighborBinding(t *testing.T, data []byte, allowed bool) {
	t.Helper()
	now := fixtureTime().Add(75 * time.Second)
	neighbors, err := decodePlacementNeighbors(data, "synthetic22", now, placementGuarded)
	if err != nil {
		if allowed {
			t.Fatalf("idle evidence rejected: %v", err)
		}
		return
	}
	candidate, err := MatchIPv4(currentSession(t), fixtureLeaseObservation(), fixtureLeaseScope(), now)
	if err != nil {
		t.Fatal(err)
	}
	options, observed := fixturePlacementOptions(), fixturePlacement()
	options.BindingMode, observed.neighbors = placementGuarded, neighbors
	record, err := bindPlacement(candidate, observed, fixtureLeaseScope(), options, now)
	if (err == nil) != allowed {
		t.Fatalf("proposal allowed=%v, want %v", err == nil, allowed)
	}
	if allowed && (len(record.Addresses) != 1 || record.Addresses[0].ValidUntil != candidate.ValidUntil ||
		record.Addresses[0].ObservedAt != candidate.LeaseObservedAt) {
		t.Fatal("guarded proposal replaced original evidence or expiry")
	}
	if !allowed && record.MAC != "" {
		t.Fatal("conflict returned partial binding")
	}
}

func TestGuardedBindingRetainsOriginalDeadlines(t *testing.T) {
	t.Parallel()
	for _, shortLease := range []bool{false, true} {
		name := "session expiry"
		if shortLease {
			name = "lease expiry"
		}
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			now := fixtureTime().Add(75 * time.Second)
			lease := fixtureLeaseObservation()
			if shortLease {
				lease.Leases[0].ValidUntil = now.Add(10 * time.Second)
			}
			candidate, err := MatchIPv4(currentSession(t), lease, fixtureLeaseScope(), now)
			if err != nil {
				t.Fatal(err)
			}
			options, observed := fixturePlacementOptions(), fixturePlacement()
			options.BindingMode, observed.neighbors = placementGuarded, nil
			first, err := bindPlacement(candidate, observed, fixtureLeaseScope(), options, now)
			if err != nil {
				t.Fatal(err)
			}
			observed.observedAt = now.Add(time.Second)
			last, err := bindPlacement(candidate, observed, fixtureLeaseScope(), options, observed.observedAt)
			if err != nil || last.Addresses[0] != first.Addresses[0] || first.Addresses[0].ValidUntil != candidate.ValidUntil {
				t.Fatal("placement reread rearmed binding lifetime")
			}
			observed.observedAt = candidate.ValidUntil
			if record, err := bindPlacement(candidate, observed, fixtureLeaseScope(), options, candidate.ValidUntil); err == nil || record.MAC != "" {
				t.Fatal("original expiry retained a proposal")
			}
		})
	}
}

func TestGuardedBindingNewSessionDoesNotNeedNewARPConfirmation(t *testing.T) {
	t.Parallel()
	start, interim := fixtureEvent("Start", 70), fixtureEvent("Alive", 74)
	start.SessionSeconds, interim.SessionSeconds = "0", "4"
	start.SessionIDHex, interim.SessionIDHex = "73657373696f6e2d32", "73657373696f6e2d32"
	now := fixtureTime().Add(75 * time.Second)
	observation, err := Replay(fixtureHistory(t, start, interim), fixtureScope(), now)
	if err != nil || len(observation.Sessions) != 1 {
		t.Fatalf("new session missing: %v", err)
	}
	candidate, err := MatchIPv4(observation.Sessions[0], fixtureLeaseObservation(), fixtureLeaseScope(), now)
	if err != nil {
		t.Fatal(err)
	}
	options := fixturePlacementOptions()
	if _, err := bindPlacement(candidate, fixturePlacement(), fixtureLeaseScope(), options, now); err == nil {
		t.Fatal("strict default accepted confirmation before new Start")
	}
	options.BindingMode = placementGuarded
	if record, err := bindPlacement(candidate, fixturePlacement(), fixtureLeaseScope(), options, now); err != nil ||
		record.AssociationID != candidate.Session.AssociationID || record.Addresses[0].ValidUntil != candidate.ValidUntil {
		t.Fatal("guarded mode did not retain current session and original expiry")
	}
}

func TestGuardedBindingStillRejectsInvalidInputs(t *testing.T) {
	t.Parallel()
	for _, name := range []string{"stale source", "future source", "wrong scope", "unknown mode", "foreign ownership"} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			now := fixtureTime().Add(75 * time.Second)
			candidate, err := MatchIPv4(currentSession(t), fixtureLeaseObservation(), fixtureLeaseScope(), now)
			if err != nil {
				t.Fatal(err)
			}
			options, observed := fixturePlacementOptions(), fixturePlacement()
			options.BindingMode, observed.neighbors = placementGuarded, nil
			switch name {
			case "stale source":
				observed.observedAt = now.Add(-Freshness)
			case "future source":
				observed.observedAt = now.Add(time.Second)
			case "wrong scope":
				options.VLAN++
			case "unknown mode":
				options.BindingMode = "unknown"
			case "foreign ownership":
				candidate.OwnershipID = strings.Repeat("f", 64)
			}
			if record, err := bindPlacement(candidate, observed, fixtureLeaseScope(), options, now); err == nil || record.MAC != "" {
				t.Fatal("invalid input produced a guarded proposal")
			}
		})
	}
}

func TestGuardedCollectorRechecksPlacementWithoutReachability(t *testing.T) {
	t.Parallel()
	for _, name := range []string{"absent", "idle", "missing first", "missing last", "first conflict", "last conflict", "first source loss", "last source loss", "changed geometry"} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			options := fixtureCollectorOptions()
			placement := fixturePlacementOptions()
			placement.BindingMode, options.Placement = placementGuarded, &placement
			captured, calls := fixtureCapturedHistory(t), 0
			result, err := collectIPv4(t.Context(), options, collectionSources{
				history: func(context.Context) (history, error) { return captured, nil },
				lease:   func(context.Context, string) (kea.Observation, error) { return fixtureLeaseObservation(), nil },
				now:     func() time.Time { return captured.observedAt },
				placement: func(context.Context) (placementObservation, error) {
					calls++
					observed := fixturePlacement()
					observed.neighbors[0].confirmedAt = fixtureTime().Add(-time.Hour)
					if name == "absent" || name == "missing first" && calls == 1 || name == "missing last" && calls == 2 {
						observed.neighbors = nil
					}
					if name == "first conflict" && calls == 1 || name == "last conflict" && calls == 2 {
						observed.neighbors[0].conflict = true
					}
					if name == "first source loss" && calls == 1 || name == "last source loss" && calls == 2 {
						return placementObservation{}, errors.New("synthetic source loss")
					}
					if name == "changed geometry" && calls == 2 {
						observed.identity = strings.Repeat("b", 64)
					}
					return observed, nil
				},
			})
			failed := strings.Contains(name, "source loss") || name == "changed geometry"
			if failed {
				if err == nil || len(result.Candidates) != 0 || len(result.ProposedBindings) != 0 {
					t.Fatal("source failure returned a collection")
				}
				return
			}
			if err != nil || !result.PlacementChecked || result.PlacementMode != placementGuarded || len(result.Candidates) != 1 || calls != 2 {
				t.Fatalf("guarded source checks incomplete: %v", err)
			}
			conflict := strings.Contains(name, "conflict")
			if conflict {
				if len(result.ProposedBindings) != 0 || result.PlacementWithheld != 1 {
					t.Fatal("conflict survived double check")
				}
			} else if len(result.ProposedBindings) != 1 || result.PlacementWithheld != 0 ||
				result.ProposedBindings[0].Addresses[0].ValidUntil != result.Candidates[0].ValidUntil {
				t.Fatal("idle device lost proposal or original expiry")
			}
		})
	}
}
