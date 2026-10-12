package radius

import (
	"net/netip"
	"testing"
	"time"

	"github.com/mikenorgate/router-policy-agent/internal/kea"
)

func fixtureLeaseScope() LeaseScope {
	return LeaseScope{SubnetID: 22, Prefix: netip.MustParsePrefix("192.0.2.0/24"), VLAN: 22}
}

func fixtureLeaseObservation() kea.Observation {
	return kea.Observation{ObservedAt: fixtureTime().Add(74 * time.Second), Leases: []kea.Lease{{
		IP: netip.MustParseAddr("192.0.2.80"), MAC: "02AABBCCDDEE", SubnetID: 22,
		UpdatedAt: fixtureTime().Add(-time.Hour), ValidUntil: fixtureTime().Add(time.Hour),
	}}}
}

func TestMatchIPv4PreservesLeaseAndSessionBounds(t *testing.T) {
	t.Parallel()
	session := currentSession(t)
	observation := fixtureLeaseObservation()
	now := fixtureTime().Add(75 * time.Second)
	first, err := MatchIPv4(session, observation, fixtureLeaseScope(), now)
	if err != nil || first.ValidUntil != session.ValidUntil || first.LeaseUpdatedAt != observation.Leases[0].UpdatedAt ||
		first.LeaseValidUntil != observation.Leases[0].ValidUntil || first.LeaseObservedAt != observation.ObservedAt {
		t.Fatalf("candidate extended or replaced original lifetime: %v", err)
	}
	observation.ObservedAt = now
	reread, err := MatchIPv4(session, observation, fixtureLeaseScope(), now.Add(time.Second))
	if err != nil || reread.ValidUntil != first.ValidUntil || reread.OwnershipID != first.OwnershipID {
		t.Fatal("query reread renewed identity or lifetime")
	}
	observation.Leases[0].ValidUntil = now.Add(10 * time.Second)
	shorter, err := MatchIPv4(session, observation, fixtureLeaseScope(), now)
	if err != nil || shorter.ValidUntil != observation.Leases[0].ValidUntil || shorter.OwnershipID == first.OwnershipID {
		t.Fatal("original DHCP expiry did not clip candidate")
	}
}

func TestMatchIPv4WithholdsLeaseReuseStalenessAndAmbiguity(t *testing.T) {
	t.Parallel()
	for _, name := range []string{"reassigned", "missing", "multiple", "wrong address", "wrong subnet", "wrong prefix",
		"expired", "future renewal", "reversed lease", "stale query", "future query", "stale session", "future session",
		"extended session", "reported vlan", "invalid scope", "noncanonical mac", "invalid association", "missing framed ip"} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			session, observation, scope := currentSession(t), fixtureLeaseObservation(), fixtureLeaseScope()
			now := fixtureTime().Add(75 * time.Second)
			switch name {
			case "reassigned":
				observation.Leases[0].MAC = "02AABBCCDDFF"
			case "missing":
				observation.Leases = nil
			case "multiple":
				observation.Leases = append(observation.Leases, observation.Leases[0])
			case "wrong address":
				observation.Leases[0].IP = netip.MustParseAddr("192.0.2.81")
			case "wrong subnet":
				observation.Leases[0].SubnetID = 33
			case "wrong prefix":
				scope.Prefix = netip.MustParsePrefix("203.0.113.0/24")
			case "expired":
				observation.Leases[0].ValidUntil = now
			case "future renewal":
				observation.Leases[0].UpdatedAt = now.Add(time.Second)
			case "reversed lease":
				observation.Leases[0].UpdatedAt = observation.Leases[0].ValidUntil
			case "stale query":
				observation.ObservedAt = now.Add(-Freshness)
			case "future query":
				observation.ObservedAt = now.Add(time.Second)
			case "stale session":
				now = session.ValidUntil
			case "future session":
				session.ObservedAt = now.Add(time.Second)
			case "extended session":
				session.ValidUntil = session.ValidUntil.Add(time.Second)
			case "reported vlan":
				session.ReportedVLAN = 33
			case "invalid scope":
				scope.SubnetID = 0
			case "noncanonical mac":
				session.MAC = "02AABBCCDDEE"
			case "invalid association":
				session.AssociationID = ""
			case "missing framed ip":
				session.IPv4 = netip.Addr{}
			}
			candidate, err := MatchIPv4(session, observation, scope, now)
			if err == nil || candidate.IP.IsValid() || !candidate.ValidUntil.IsZero() {
				t.Fatal("unsafe match returned a partial candidate")
			}
		})
	}
}

func TestReplayAndMatchWithdrawAfterStopOrReassignment(t *testing.T) {
	t.Parallel()
	history := fixtureHistory(t, fixtureEvent("Start", 0), fixtureEvent("Alive", 60))
	now := fixtureTime().Add(75 * time.Second)
	result, err := Replay(history, fixtureScope(), now)
	if err != nil || len(result.Sessions) != 1 {
		t.Fatal("initial session missing")
	}
	lease := fixtureLeaseObservation()
	if _, err := MatchIPv4(result.Sessions[0], lease, fixtureLeaseScope(), now); err != nil {
		t.Fatal(err)
	}
	lease.Leases[0].MAC = "02AABBCCDDFF"
	if _, err := MatchIPv4(result.Sessions[0], lease, fixtureLeaseScope(), now); err == nil {
		t.Fatal("address reuse retained previous candidate")
	}
	history = append(history, fixtureHistory(t, fixtureEvent("Stop", 74))...)
	for range 2 { // Reconstructing the replay core must retain the Stop tombstone.
		result, err = Replay(history, fixtureScope(), now)
		if err != nil || len(result.Sessions) != 0 {
			t.Fatal("replay/restart restored stopped session")
		}
	}
}
