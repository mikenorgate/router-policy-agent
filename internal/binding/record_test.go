package binding

import (
	"net/netip"
	"testing"
	"time"
)

func TestValidate(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	valid := func() Snapshot {
		return Snapshot{SchemaVersion: 1, Generation: "synthetic-v1", ObservedAt: now, Complete: true,
			Records: []Record{{MAC: "02:00:00:00:00:01", NAS: "synthetic-nas", AssociationID: "assoc-1",
				AssociatedAt: now, Interface: "lan13", VLAN: 13, Addresses: []Address{
					{IP: netip.MustParseAddr("10.240.3.10"), Source: "kea_dhcp4", OwnershipID: "lease-1",
						ObservedAt: now, ValidUntil: now.Add(time.Hour)},
				}}},
		}
	}
	tests := []struct {
		name      string
		mutate    func(*Snapshot)
		wantError bool
	}{
		{name: "valid", mutate: func(_ *Snapshot) {}},
		{name: "schema", mutate: func(s *Snapshot) { s.SchemaVersion = 2 }, wantError: true},
		{name: "partial", mutate: func(s *Snapshot) { s.Complete = false }, wantError: true},
		{name: "missing generation", mutate: func(s *Snapshot) { s.Generation = "" }, wantError: true},
		{name: "stale", mutate: func(s *Snapshot) { s.ObservedAt = now.Add(-90 * time.Second) }, wantError: true},
		{name: "future", mutate: func(s *Snapshot) { s.ObservedAt = now.Add(time.Second) }, wantError: true},
		{name: "missing association", mutate: func(s *Snapshot) { s.Records[0].AssociationID = "" }, wantError: true},
		{name: "stale association", mutate: func(s *Snapshot) { s.Records[0].AssociatedAt = now.Add(-90 * time.Second) }, wantError: true},
		{name: "NDP alone", mutate: func(s *Snapshot) { s.Records[0].Addresses[0].Source = "ndp" }, wantError: true},
		{name: "mismatched family", mutate: func(s *Snapshot) { s.Records[0].Addresses[0].Source = "kea_dhcp6" }, wantError: true},
		{name: "expired lease", mutate: func(s *Snapshot) { s.Records[0].Addresses[0].ValidUntil = now }, wantError: true},
		{name: "stale ownership", mutate: func(s *Snapshot) { s.Records[0].Addresses[0].ObservedAt = now.Add(-90 * time.Second) }, wantError: true},
		{name: "no ownership id", mutate: func(s *Snapshot) { s.Records[0].Addresses[0].OwnershipID = "" }, wantError: true},
		{name: "loopback", mutate: func(s *Snapshot) { s.Records[0].Addresses[0].IP = netip.MustParseAddr("::1") }, wantError: true},
		{name: "same mac twice", mutate: func(s *Snapshot) { s.Records = append(s.Records, s.Records[0]) }, wantError: true},
		{name: "same ip twice", mutate: func(s *Snapshot) { s.Records[0].Addresses = append(s.Records[0].Addresses, s.Records[0].Addresses[0]) }, wantError: true},
		{name: "qualified ipv6", mutate: func(s *Snapshot) {
			s.Records[0].Addresses[0].Source = "qualified_ipv6"
			s.Records[0].Addresses[0].IP = netip.MustParseAddr("fdca:1a2b:3::10")
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			snapshot := valid()
			test.mutate(&snapshot)
			if err := Validate(snapshot, now, 90*time.Second, 4096); (err != nil) != test.wantError {
				t.Fatalf("Validate error = %v; want error %v", err, test.wantError)
			}
		})
	}
}
