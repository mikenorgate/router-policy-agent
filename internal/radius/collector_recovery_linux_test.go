package radius

import (
	"context"
	"testing"
	"time"

	"github.com/mikenorgate/router-policy-agent/internal/kea"
)

func TestCollectIPv4WithholdsOnlyUnqualifiedDevice(t *testing.T) {
	t.Parallel()
	for _, name := range []string{"address not reported", "lease missing", "address mismatch", "ambiguous lease"} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			other := sessionEvent("Start", 5, 0)
			other.MAC, other.SessionIDHex = "02AABBCCDDFF", "616e6f746865722d73657373696f6e"
			if name == "address not reported" {
				other.IPv4 = ""
			} else {
				other.IPv4 = "192.0.2.81"
			}
			captured := history{
				data:  fixtureHistory(t, fixtureEvent("Start", 0), other, fixtureEvent("Alive", 60)),
				scope: fixtureScope(), observedAt: fixtureTime().Add(75 * time.Second),
			}
			result, err := collectIPv4(t.Context(), fixtureCollectorOptions(), collectionSources{
				history: func(context.Context) (history, error) { return captured, nil },
				lease: func(_ context.Context, mac string) (kea.Observation, error) {
					lease := fixtureLeaseObservation()
					if mac != "02:aa:bb:cc:dd:ff" {
						return lease, nil
					}
					if name == "address not reported" {
						t.Fatal("queried ownership for a session with no reported address")
					}
					lease.Leases[0].MAC = mac
					if name == "lease missing" {
						lease.Leases = []kea.Lease{}
					}
					if name == "ambiguous lease" {
						lease.Leases = append(lease.Leases, lease.Leases[0])
					}
					return lease, nil
				},
				now: func() time.Time { return captured.observedAt },
			})
			if err != nil || len(result.Candidates) != 1 || result.Withheld != 1 || result.Generation == "" {
				t.Fatalf("one unqualified device blocked the healthy device: %+v, %v", result, err)
			}
			if result.Candidates[0].Session.MAC != "02:aa:bb:cc:dd:ee" {
				t.Fatal("unqualified device received a candidate")
			}
		})
	}
}

func TestCollectIPv4RecoversWithoutStart(t *testing.T) {
	t.Parallel()
	captured := history{
		data: recoveryHistory(t, fixtureTime().Add(550*time.Second),
			sessionEvent("Alive", 600, 600), sessionEvent("Alive", 660, 660)),
		scope: fixtureScope(), observedAt: fixtureTime().Add(675 * time.Second),
	}
	lease := fixtureLeaseObservation()
	lease.ObservedAt = captured.observedAt
	lease.Leases[0].ValidUntil = fixtureTime().Add(3600 * time.Second)
	historyReads, leaseReads := 0, 0
	result, err := collectIPv4(t.Context(), fixtureCollectorOptions(), collectionSources{
		history: func(context.Context) (history, error) {
			historyReads++
			return captured, nil
		},
		lease: func(context.Context, string) (kea.Observation, error) {
			leaseReads++
			return lease, nil
		},
		now: func() time.Time { return captured.observedAt },
	})
	if err != nil || len(result.Candidates) != 1 || result.Withheld != 0 || historyReads != 3 || leaseReads != 2 {
		t.Fatalf("recovered session did not pass the normal source checks: %+v, %v", result, err)
	}
	if result.Candidates[0].ValidUntil != fixtureTime().Add(750*time.Second) {
		t.Fatal("collecting a recovered session extended its evidence deadline")
	}
}
