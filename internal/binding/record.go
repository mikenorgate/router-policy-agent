// Package binding describes independently collected address-ownership evidence.
// It does not turn a RADIUS acceptance or an NDP observation into authorization.
package binding

import (
	"errors"
	"net/netip"
	"time"
)

// Snapshot must be produced by a router-trusted collector, not the directory
// reader. The applier checks file/socket ownership separately from this schema.
type Snapshot struct {
	SchemaVersion int       `json:"schema_version"`
	Generation    string    `json:"generation"`
	ObservedAt    time.Time `json:"observed_at"`
	Complete      bool      `json:"complete"`
	Records       []Record  `json:"records"`
}

// Record combines a current, actual NAS association with address ownership.
// The NAS source must check the observed VLAN, not just a RADIUS reply attribute.
type Record struct {
	MAC           string    `json:"mac"`
	NAS           string    `json:"nas"`
	Interface     string    `json:"interface"`
	VLAN          uint16    `json:"vlan"`
	AssociatedAt  time.Time `json:"associated_at"`
	AssociationID string    `json:"association_id"`
	Addresses     []Address `json:"addresses"`
}

// Address identifies the qualified producer and the latest observation of a
// lease or equivalent ownership evidence. Unknown IPv6/privacy addresses deny.
type Address struct {
	IP          netip.Addr `json:"ip"`
	Source      string     `json:"source"`
	OwnershipID string     `json:"ownership_id"`
	ObservedAt  time.Time  `json:"observed_at"`
	ValidUntil  time.Time  `json:"valid_until"`
}

// Fresh requires non-future evidence still within its bounded authorization
// lifetime. A delayed refresh cannot turn old evidence into a fresh lease.
func Fresh(observed, now time.Time, lease time.Duration) bool {
	return !observed.IsZero() && !observed.After(now) && now.Before(observed.Add(lease))
}

// Validate checks the bounded evidence envelope. Role/subnet ownership and
// protected-floor checks belong to the independently configured compiler.
func Validate(snapshot Snapshot, now time.Time, lease time.Duration, maximum int) error {
	if snapshot.SchemaVersion != 1 || !snapshot.Complete || len(snapshot.Records) > maximum ||
		!Fresh(snapshot.ObservedAt, now, lease) || snapshot.Generation == "" {
		return errors.New("binding: incomplete, stale or oversized evidence")
	}
	owners := map[netip.Addr]string{}
	identities := map[string]bool{}
	for _, record := range snapshot.Records {
		if record.MAC == "" || identities[record.MAC] || record.NAS == "" ||
			record.AssociationID == "" || len(record.NAS) > 128 || len(record.AssociationID) > 128 ||
			len(record.Addresses) > 16 || !Fresh(record.AssociatedAt, now, lease) {
			return errors.New("binding: conflicting or unqualified association")
		}
		identities[record.MAC] = true
		for _, address := range record.Addresses {
			isQualifiedSource := address.Source == "kea_dhcp4" && address.IP.Is4() ||
				(address.Source == "kea_dhcp6" || address.Source == "qualified_ipv6") && address.IP.Is6()
			if !isQualifiedSource || !address.IP.IsValid() || address.IP.Is4In6() ||
				!address.IP.IsGlobalUnicast() || address.IP.Zone() != "" ||
				address.OwnershipID == "" || len(address.OwnershipID) > 128 ||
				!Fresh(address.ObservedAt, now, lease) || !now.Before(address.ValidUntil) {
				return errors.New("binding: stale or unqualified address")
			}
			if _, exists := owners[address.IP]; exists {
				return errors.New("binding: duplicate address ownership")
			}
			owners[address.IP] = record.MAC
		}
	}
	return nil
}
