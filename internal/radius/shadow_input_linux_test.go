package radius

import (
	"encoding/json"
	"net/netip"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/mikenorgate/router-policy-agent/internal/binding"
)

func shadowInputFixture(t testing.TB) shadowReport {
	t.Helper()
	now := fixtureTime().Add(75 * time.Second)
	candidate, err := MatchIPv4(currentSession(t), fixtureLeaseObservation(), fixtureLeaseScope(), now)
	if err != nil {
		t.Fatal(err)
	}
	options := fixturePlacementOptions()
	options.BindingMode = placementGuarded
	record, err := bindPlacement(candidate, fixturePlacement(), fixtureLeaseScope(), options, now)
	if err != nil {
		t.Fatal(err)
	}
	return shadowReport{
		Kind: "radius_ipv4_shadow_v1", Mode: "shadow", Complete: true, SampledAt: now.Add(time.Second),
		Collection: Collection{
			ObservedAt: now, Generation: strings.Repeat("a", 64), Candidates: []IPv4Candidate{candidate},
			PlacementChecked: true, PlacementMode: placementGuarded, ProposedBindings: []binding.Record{record},
		},
	}
}

func shadowInputBytes(t testing.TB, report shadowReport) []byte {
	t.Helper()
	data, err := json.Marshal(report)
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func TestDecodeShadowProposalsPreservesEvidenceAndEmptyWithdrawal(t *testing.T) {
	t.Parallel()
	for _, name := range []string{"guarded", "strict", "placement withheld", "stopped"} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			report := shadowInputFixture(t)
			switch name {
			case "strict":
				report.Collection.PlacementMode = ""
				report.Collection.ProposedBindings[0].Addresses[0].ValidUntil = report.SampledAt.Add(10 * time.Second)
			case "placement withheld":
				report.Collection.ProposedBindings = []binding.Record{}
				report.Collection.PlacementWithheld = 1
			case "stopped":
				report.Collection.Candidates = []IPv4Candidate{}
				report.Collection.ProposedBindings = []binding.Record{}
			}
			now := report.SampledAt.Add(time.Second)
			got, err := decodeShadowProposals(shadowInputBytes(t, report), now)
			if err != nil {
				t.Fatalf("valid shadow input rejected: %v", err)
			}
			if got.Generation != report.Collection.Generation || !got.ObservedAt.Equal(report.Collection.ObservedAt) ||
				len(got.Records) != len(report.Collection.ProposedBindings) || !got.Complete {
				t.Fatal("adapter replaced original envelope or record count")
			}
			for index, record := range got.Records {
				if !reflect.DeepEqual(record, report.Collection.ProposedBindings[index]) {
					t.Fatal("adapter changed original ownership or deadlines")
				}
			}
			if err := binding.Validate(got, now, Freshness, 256); err != nil {
				t.Fatal("adapted shadow evidence did not satisfy the consumer envelope")
			}
		})
	}
}

func TestDecodeShadowProposalsRejectsUnsafeReports(t *testing.T) {
	t.Parallel()
	for _, name := range []string{
		"incomplete", "enforcement ready", "wrong kind", "wrong mode", "stale report", "future report",
		"future collection", "no placement", "unknown placement", "negative withheld", "oversized withheld",
		"count mismatch", "bad generation", "duplicate candidate", "noncanonical mac", "bad nas",
		"bad association", "bad owner", "wrong framed ip", "extended session", "future session start",
		"future lease observation", "future lease renewal", "extended candidate", "orphan proposal",
		"wrong nas", "wrong association", "refreshed association", "wrong vlan", "wrong interface",
		"extra address", "ipv6 address", "wrong address source", "bad proposal owner", "refreshed lease",
		"extended proposal", "clipped guarded proposal",
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			report := shadowInputFixture(t)
			candidate := &report.Collection.Candidates[0]
			record := &report.Collection.ProposedBindings[0]
			address := &record.Addresses[0]
			switch name {
			case "incomplete":
				report.Complete = false
			case "enforcement ready":
				report.EnforcementReady = true
			case "wrong kind":
				report.Kind = "bindings_v1"
			case "wrong mode":
				report.Mode = "enforce"
			case "stale report":
				report.SampledAt = report.SampledAt.Add(-Freshness)
			case "future report":
				report.SampledAt = report.SampledAt.Add(2 * time.Second)
			case "future collection":
				report.Collection.ObservedAt = report.SampledAt.Add(time.Second)
			case "no placement":
				report.Collection.PlacementChecked = false
			case "unknown placement":
				report.Collection.PlacementMode = "unknown"
			case "negative withheld":
				report.Collection.Withheld = -1
			case "oversized withheld":
				report.Collection.Withheld = 4097
			case "count mismatch":
				report.Collection.PlacementWithheld = 1
			case "bad generation":
				report.Collection.Generation = "unknown"
			case "duplicate candidate":
				report.Collection.Candidates = append(report.Collection.Candidates, *candidate)
				report.Collection.PlacementWithheld = 1
			case "noncanonical mac":
				candidate.Session.MAC = "02AABBCCDDEE"
			case "bad nas":
				candidate.Session.NAS = netip.MustParseAddr("::1")
			case "bad association":
				candidate.Session.AssociationID = "invalid"
			case "bad owner":
				candidate.OwnershipID = "invalid"
			case "wrong framed ip":
				candidate.Session.IPv4 = netip.MustParseAddr("192.0.2.81")
			case "extended session":
				candidate.Session.ValidUntil = candidate.Session.ValidUntil.Add(time.Second)
			case "future session start":
				candidate.Session.StartedAt = candidate.Session.ObservedAt.Add(time.Second)
			case "future lease observation":
				candidate.LeaseObservedAt = report.SampledAt.Add(2 * time.Second)
			case "future lease renewal":
				candidate.LeaseUpdatedAt = candidate.LeaseObservedAt.Add(time.Second)
			case "extended candidate":
				candidate.ValidUntil = candidate.ValidUntil.Add(time.Second)
			case "orphan proposal":
				record.MAC = "02:aa:bb:cc:dd:ff"
			case "wrong nas":
				record.NAS = "192.0.2.2"
			case "wrong association":
				record.AssociationID = strings.Repeat("b", 64)
			case "refreshed association":
				record.AssociatedAt = record.AssociatedAt.Add(time.Second)
			case "wrong vlan":
				record.VLAN++
			case "wrong interface":
				record.Interface = "lo"
			case "extra address":
				record.Addresses = append(record.Addresses, *address)
			case "ipv6 address":
				address.IP = netip.MustParseAddr("2001:db8::80")
			case "wrong address source":
				address.Source = "qualified_ipv6"
			case "bad proposal owner":
				address.OwnershipID = "invalid"
			case "refreshed lease":
				address.ObservedAt = address.ObservedAt.Add(time.Second)
			case "extended proposal":
				address.ValidUntil = address.ValidUntil.Add(time.Second)
			case "clipped guarded proposal":
				address.ValidUntil = address.ValidUntil.Add(-time.Second)
			}
			got, err := decodeShadowProposals(shadowInputBytes(t, report), fixtureTime().Add(77*time.Second))
			if err == nil || got.Complete || len(got.Records) != 0 {
				t.Fatal("unsafe report returned successful or partial evidence")
			}
		})
	}
}

func TestDecodeShadowProposalsExpiresWithoutStopOrReadRenewal(t *testing.T) {
	t.Parallel()
	report := shadowInputFixture(t)
	data := shadowInputBytes(t, report)
	deadline := report.Collection.Candidates[0].ValidUntil
	for _, now := range []time.Time{report.SampledAt, deadline.Add(-time.Nanosecond)} {
		got, err := decodeShadowProposals(data, now)
		if err != nil || !got.Records[0].Addresses[0].ValidUntil.Equal(deadline) {
			t.Fatal("reread changed the original deadline")
		}
	}
	for _, now := range []time.Time{deadline, deadline.Add(time.Second)} {
		if got, err := decodeShadowProposals(data, now); err == nil || got.Complete {
			t.Fatal("missing Stop retained evidence after original expiry")
		}
	}
	report.SampledAt, report.Collection.ObservedAt = deadline.Add(time.Second), deadline.Add(time.Second)
	if _, err := decodeShadowProposals(shadowInputBytes(t, report), deadline.Add(2*time.Second)); err == nil {
		t.Fatal("refreshing only envelope timestamps revived expired source evidence")
	}
}

func TestDecodeShadowProposalsRequiresCanonicalProducerSchema(t *testing.T) {
	t.Parallel()
	report := shadowInputFixture(t)
	valid := string(shadowInputBytes(t, report))
	for _, name := range []string{"unknown", "duplicate", "case alias", "missing", "null", "whitespace", "oversized"} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			data := valid
			switch name {
			case "unknown":
				data = strings.Replace(data, `"mode":"shadow"`, `"mode":"shadow","token":"synthetic-private-value"`, 1)
			case "duplicate":
				data = strings.Replace(data, `"mode":"shadow"`, `"mode":"shadow","mode":"shadow"`, 1)
			case "case alias":
				data = strings.Replace(data, `"associated_at"`, `"Associated_At"`, 1)
			case "missing":
				data = strings.Replace(data, `"enforcement_ready":false,`, ``, 1)
			case "null":
				data = strings.Replace(data, `"enforcement_ready":false`, `"enforcement_ready":null`, 1)
			case "whitespace":
				data += "\n"
			case "oversized":
				data = strings.Repeat(" ", maximumShadow+1)
			}
			if _, err := decodeShadowProposals([]byte(data), report.SampledAt); err == nil || strings.Contains(err.Error(), "synthetic-private-value") {
				t.Fatal("invalid input was accepted or exposed through diagnostics")
			}
		})
	}
}

func FuzzDecodeShadowProposals(f *testing.F) {
	report := shadowInputFixture(f)
	f.Add(shadowInputBytes(f, report))
	f.Add([]byte(`{}`))
	f.Fuzz(func(t *testing.T, data []byte) {
		got, err := decodeShadowProposals(data, report.SampledAt)
		if err == nil {
			if err := binding.Validate(got, report.SampledAt, Freshness, 256); err != nil {
				t.Fatal("successful adapter returned invalid evidence")
			}
		}
	})
}
