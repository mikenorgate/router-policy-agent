package radius

import (
	"errors"
	"net/netip"
	"strconv"
	"time"

	"github.com/mikenorgate/router-policy-agent/internal/binding"
	"github.com/mikenorgate/router-policy-agent/internal/kea"
	"github.com/mikenorgate/router-policy-agent/internal/policy"
)

// LeaseScope pins router-owned DHCP geometry, never directory-supplied values.
// A matching ReportedVLAN remains corroboration, not actual VLAN proof.
type LeaseScope struct {
	SubnetID uint32
	Prefix   netip.Prefix
	VLAN     uint16
}

// IPv4Candidate is a consistency result, deliberately not binding.Record.
// It cannot supply independent placement, anti-spoofing or IPv6 qualification.
// ValidUntil is clipped to both the session heartbeat and original DHCP expiry.
type IPv4Candidate struct {
	Session         Session    `json:"session"`
	IP              netip.Addr `json:"ip"`
	OwnershipID     string     `json:"ownership_id"`
	LeaseObservedAt time.Time  `json:"lease_observed_at"`
	LeaseUpdatedAt  time.Time  `json:"lease_updated_at"`
	LeaseValidUntil time.Time  `json:"lease_valid_until"`
	ValidUntil      time.Time  `json:"valid_until"`
}

// MatchIPv4 joins one current session with one authoritative Kea observation.
// No partial candidate is returned for stale, absent, ambiguous, mismatched or
// reassigned ownership. Caller must recheck session/lease consistency before
// publishing, and obtain independent qualified placement and source evidence.
// A candidate never authorizes traffic and is not accepted by the helper feed.
func MatchIPv4(session Session, observation kea.Observation, scope LeaseScope, now time.Time) (IPv4Candidate, error) {
	mac, err := policy.CanonicalMAC(session.MAC)
	if err != nil || mac != session.MAC || scope.SubnetID == 0 || scope.VLAN == 0 || scope.VLAN > 4094 ||
		!scope.Prefix.IsValid() || !scope.Prefix.Addr().Is4() || scope.Prefix != scope.Prefix.Masked() ||
		!session.NAS.IsGlobalUnicast() || session.NAS.Is4In6() || session.NAS.Zone() != "" ||
		len(session.AssociationID) != 64 || session.StartedAt.IsZero() || session.StartedAt.After(session.ObservedAt) ||
		!binding.Fresh(session.ObservedAt, now, Freshness) || session.ValidUntil != session.ObservedAt.Add(Freshness) ||
		!session.IPv4.Is4() || !session.IPv4.IsGlobalUnicast() ||
		(session.ReportedVLAN != 0 && session.ReportedVLAN != scope.VLAN) ||
		!binding.Fresh(observation.ObservedAt, now, Freshness) || len(observation.Leases) != 1 {
		return IPv4Candidate{}, errors.New("radius: unqualified session or lease observation")
	}
	lease := observation.Leases[0]
	owner, err := policy.CanonicalMAC(lease.MAC)
	if err != nil || owner != mac || lease.IP != session.IPv4 || !scope.Prefix.Contains(lease.IP) ||
		lease.SubnetID != scope.SubnetID || lease.UpdatedAt.IsZero() || lease.UpdatedAt.After(now) ||
		!now.Before(lease.ValidUntil) || !lease.UpdatedAt.Before(lease.ValidUntil) {
		return IPv4Candidate{}, errors.New("radius: lease owner, geometry or lifetime conflict")
	}
	until := lease.ValidUntil
	if session.ValidUntil.Before(until) {
		until = session.ValidUntil
	}
	return IPv4Candidate{
		Session: session, IP: lease.IP,
		OwnershipID: digest(mac, lease.IP.String(), strconv.FormatUint(uint64(lease.SubnetID), 10),
			lease.UpdatedAt.UTC().Format(time.RFC3339Nano), lease.ValidUntil.UTC().Format(time.RFC3339Nano)),
		LeaseObservedAt: observation.ObservedAt, LeaseUpdatedAt: lease.UpdatedAt,
		LeaseValidUntil: lease.ValidUntil, ValidUntil: until,
	}, nil
}
