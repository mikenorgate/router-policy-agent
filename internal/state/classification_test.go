package state

import (
	"encoding/json"
	"net/netip"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/mikenorgate/router-policy-agent/internal/policy"
)

func classified(t *testing.T) Document {
	t.Helper()
	document, err := RememberAddresses(advanced(t), []netip.Addr{
		netip.MustParseAddr("10.240.3.10"), netip.MustParseAddr("fdca:1a2b:3::10"),
	})
	if err != nil {
		t.Fatal(err)
	}
	return document
}

func TestAddressHistoryRoundTripAndTransition(t *testing.T) {
	t.Parallel()
	previous := classified(t)
	next, err := RememberAddresses(previous, []netip.Addr{
		netip.MustParseAddr("10.240.3.10"), netip.MustParseAddr("10.240.3.11"),
		netip.MustParseAddr("fdca:1a2b:3::11"),
	})
	if err != nil || CheckTransition(previous, next) != nil {
		t.Fatalf("valid classifier extension rejected: %v", err)
	}
	data, err := json.Marshal(next)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := Decode(data)
	if err != nil || !slices.Equal(decoded.ClassifiedIPv4, next.ClassifiedIPv4) ||
		!slices.Equal(decoded.ClassifiedIPv6, next.ClassifiedIPv6) {
		t.Fatalf("address history did not round trip: %v", err)
	}
	for _, family := range []string{"ipv4", "ipv6"} {
		t.Run(family, func(t *testing.T) {
			t.Parallel()
			shrunk, err := Clone(next)
			if err != nil {
				t.Fatal(err)
			}
			if family == "ipv4" {
				shrunk.ClassifiedIPv4 = shrunk.ClassifiedIPv4[1:]
			} else {
				shrunk.ClassifiedIPv6 = shrunk.ClassifiedIPv6[1:]
			}
			if CheckTransition(next, shrunk) == nil {
				t.Fatal("normal state update erased historical classification")
			}
		})
	}
	removed := snapshot()
	removed.Devices = []policy.Device{}
	removed.ObservedAt = observed.Add(time.Second)
	ledger := next.Ledger
	ledger.LastValidated = removed.ObservedAt
	retained, err := Advance(next, removed, ledger)
	if err != nil || !slices.Equal(retained.ClassifiedIPv4, next.ClassifiedIPv4) ||
		!slices.Equal(retained.ClassifiedIPv6, next.ClassifiedIPv6) {
		t.Fatalf("directory removal erased address history: %v", err)
	}
}

func TestClassificationValidation(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name   string
		mutate func(*Classification)
	}{
		{name: "nil macs", mutate: func(c *Classification) { c.MACs = nil }},
		{name: "nil ipv4", mutate: func(c *Classification) { c.IPv4 = nil }},
		{name: "nil ipv6", mutate: func(c *Classification) { c.IPv6 = nil }},
		{name: "orphan address", mutate: func(c *Classification) { c.MACs = []string{} }},
		{name: "wrong ipv4 family", mutate: func(c *Classification) { c.IPv4[0] = c.IPv6[0] }},
		{name: "wrong ipv6 family", mutate: func(c *Classification) { c.IPv6[0] = c.IPv4[0] }},
		{name: "duplicate address", mutate: func(c *Classification) { c.IPv4 = append(c.IPv4, c.IPv4[0]) }},
		{name: "unsorted address", mutate: func(c *Classification) { c.IPv4 = []string{"10.240.3.11", "10.240.3.10"} }},
		{name: "noncanonical address", mutate: func(c *Classification) { c.IPv6[0] = "FDCA:1A2B:3::10" }},
		{name: "zoned address", mutate: func(c *Classification) { c.IPv6[0] += "%lan13" }},
		{name: "mapped address", mutate: func(c *Classification) { c.IPv6[0] = "::ffff:10.240.3.10" }},
		{name: "loopback", mutate: func(c *Classification) { c.IPv4[0] = "127.0.0.1" }},
		{name: "prefix", mutate: func(c *Classification) { c.IPv4[0] += "/32" }},
		{name: "address capacity", mutate: func(c *Classification) { c.IPv6 = make([]string, maximumClassifiedAddresses+1) }},
		{name: "cohort capacity", mutate: func(c *Classification) { c.MACs = make([]string, maximumCohort+1) }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			classification, err := Classifiers(classified(t))
			if err != nil {
				t.Fatal(err)
			}
			test.mutate(&classification)
			if _, err := CloneClassification(classification); err == nil {
				t.Fatal("unsafe classifier handoff accepted")
			}
		})
	}
}

func TestClassificationCopiesAndRejectsUnsafeHistory(t *testing.T) {
	t.Parallel()
	document := classified(t)
	handoff, err := Classifiers(document)
	if err != nil {
		t.Fatal(err)
	}
	handoff.MACs[0] = "02:00:00:00:00:02"
	handoff.IPv4[0] = "10.240.3.11"
	handoff.IPv6[0] = "fdca:1a2b:3::11"
	if document.CohortMACs[0] != "02:00:00:00:00:01" || document.ClassifiedIPv4[0] != "10.240.3.10" ||
		document.ClassifiedIPv6[0] != "fdca:1a2b:3::10" {
		t.Fatal("backend handoff aliases durable state")
	}
	for _, addresses := range [][]netip.Addr{
		{netip.Addr{}}, {netip.MustParseAddr("127.0.0.1")}, make([]netip.Addr, 2*maximumClassifiedAddresses+1),
	} {
		if _, err := RememberAddresses(document, addresses); err == nil {
			t.Fatal("unsafe history extension accepted")
		}
	}
	if _, err := RememberAddresses(Initial(), []netip.Addr{netip.MustParseAddr("10.240.3.10")}); err == nil {
		t.Fatal("initial state accepted unanchored address classification")
	}
	if _, err := CloneClassification(EmptyClassification()); err != nil {
		t.Fatal(err)
	}
}

func TestStateRequiresExplicitAddressHistorySchema(t *testing.T) {
	t.Parallel()
	valid, err := json.Marshal(classified(t))
	if err != nil {
		t.Fatal(err)
	}
	for _, raw := range []string{
		strings.Replace(string(valid), `"schema_version":2`, `"schema_version":1`, 1),
		strings.Replace(string(valid), `"classified_ipv4":["10.240.3.10"],`, "", 1),
		strings.Replace(string(valid), `"classified_ipv6":["fdca:1a2b:3::10"]`, `"classified_ipv6":null`, 1),
		`{"classified_ipv4":[],` + string(valid[1:]),
	} {
		if _, err := Decode([]byte(raw)); err == nil {
			t.Fatal("missing, duplicate, null or pre-history schema silently accepted")
		}
	}
	unsafe := documentWithInitialAddresses()
	if _, err := Clone(unsafe); err == nil {
		t.Fatal("initial observation accepted invented history")
	}
}

func TestHistoricalClassifierCapacityCannotBeReset(t *testing.T) {
	t.Parallel()
	document := advanced(t)
	address := netip.MustParseAddr("10.244.0.1")
	for range maximumClassifiedAddresses {
		document.ClassifiedIPv4 = append(document.ClassifiedIPv4, address.String())
		address = address.Next()
	}
	slices.Sort(document.ClassifiedIPv4)
	if _, err := Clone(document); err != nil {
		t.Fatal(err)
	}
	if _, err := RememberAddresses(document, []netip.Addr{address}); err == nil {
		t.Fatal("historical capacity silently shrank or truncated to admit another address")
	}
	if _, err := RememberAddresses(document, []netip.Addr{netip.MustParseAddr(document.ClassifiedIPv4[0])}); err != nil {
		t.Fatalf("existing classifier rejected at capacity: %v", err)
	}
}

func documentWithInitialAddresses() Document {
	document := Initial()
	document.CohortMACs = []string{"02:00:00:00:00:01"}
	document.ClassifiedIPv4 = []string{"10.240.3.10"}
	return document
}
