package policy

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"slices"
	"testing"
	"time"

	"github.com/mikenorgate/router-policy-agent/internal/binding"
)

func TestClassificationIncludesZeroGrantBindingsAndCounterparts(t *testing.T) {
	t.Parallel()
	input := testInput(t)
	input.Directory.Devices[0].Active = false
	input.Bindings.Records[0].Addresses = append(input.Bindings.Records[0].Addresses, binding.Address{
		IP: netip.MustParseAddr("10.240.3.10"), Source: "kea_dhcp4", OwnershipID: "synthetic-v4",
		ObservedAt: testNow, ValidUntil: testNow.Add(time.Hour),
	})
	baseline := testBaseline()
	baseline.NAT46 = append(baseline.NAT46, NAT46{
		ID: "device46", Alias: netip.MustParseAddr("10.250.0.60"),
		Target: input.Bindings.Records[0].Addresses[0].IP, Ready: true,
	})
	compiler := testCompiler(t, baseline)
	cohort := []string{input.Directory.Devices[0].MAC}
	addresses, err := compiler.ClassifyBindings(t.Context(), input.Bindings, cohort, testNow)
	if err != nil {
		t.Fatal(err)
	}
	for _, address := range []string{
		"10.240.3.10", "fdca:1a2b:3::10", "fdca:1a2b:64::af0:30a",
		"10.250.0.60", "fdca:1a2b:64::afa:3c",
	} {
		if !slices.Contains(addresses, netip.MustParseAddr(address)) {
			t.Fatal("zero-grant device lost a qualified native or NAT counterpart classifier")
		}
	}
	candidate, err := compiler.Compile(input)
	if err != nil || len(candidate.Grants) != 0 {
		t.Fatalf("deny-only classification supplied authorization: %v", err)
	}
	input.Bindings.Records[0].MAC = "02:00:00:00:00:02"
	addresses, err = compiler.ClassifyBindings(t.Context(), input.Bindings, cohort, testNow)
	if err != nil || len(addresses) != 0 {
		t.Fatalf("unmanaged IP reuse inherited managed classification: %v", err)
	}
}

func TestClassificationRequiresFreshRootQualifiedGeometry(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name   string
		mutate func(*Input)
		err    bool
	}{
		{name: "incomplete", mutate: func(i *Input) { i.Bindings.Complete = false }, err: true},
		{name: "expired", mutate: func(i *Input) { i.Bindings.ObservedAt = testNow.Add(-90 * time.Second) }, err: true},
		{name: "wrong interface", mutate: func(i *Input) { i.Bindings.Records[0].Interface = "lan10" }},
		{name: "wrong vlan", mutate: func(i *Input) { i.Bindings.Records[0].VLAN = 10 }},
		{name: "wrong subnet", mutate: func(i *Input) { i.Bindings.Records[0].Addresses[0].IP = netip.MustParseAddr("fdca:1a2b:2::10") }},
		{name: "reserved host", mutate: func(i *Input) {
			i.Bindings.Records[0].Addresses[0].IP = netip.MustParseAddr("10.240.3.0")
			i.Bindings.Records[0].Addresses[0].Source = "kea_dhcp4"
		}},
		{name: "invalid mac", mutate: func(i *Input) { i.Bindings.Records[0].MAC = "invalid" }, err: true},
		{name: "invalid generation", mutate: func(i *Input) { i.Bindings.Generation = "invalid generation" }, err: true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			input := testInput(t)
			test.mutate(&input)
			addresses, err := testCompiler(t, testBaseline()).ClassifyBindings(
				t.Context(),
				input.Bindings,
				[]string{input.Directory.Devices[0].MAC},
				testNow,
			)
			if (err != nil) != test.err || len(addresses) != 0 {
				t.Fatalf("unqualified binding supplied classifier or incorrect failure: %v", err)
			}
		})
	}
}

func TestClassificationRejectsInvalidDependencies(t *testing.T) {
	t.Parallel()
	compiler := testCompiler(t, testBaseline())
	input := testInput(t)
	cohort := []string{input.Directory.Devices[0].MAC}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if addresses, err := compiler.ClassifyBindings(ctx, input.Bindings, cohort, testNow); !errors.Is(err, context.Canceled) || addresses != nil {
		t.Fatal("canceled classifier returned a partial observation")
	}
	var missing *Compiler
	if _, err := missing.ClassifyBindings(t.Context(), input.Bindings, cohort, testNow); err == nil {
		t.Fatal("nil compiler accepted")
	}
	//nolint:staticcheck // Verify fail-closed rejection at the public boundary.
	if _, err := compiler.ClassifyBindings(nil, input.Bindings, cohort, testNow); err == nil {
		t.Fatal("nil context accepted")
	}
	for _, invalid := range [][]string{nil, {"invalid"}, {cohort[0], cohort[0]}, make([]string, 4097)} {
		if addresses, err := compiler.ClassifyBindings(t.Context(), input.Bindings, invalid, testNow); err == nil || addresses != nil {
			t.Fatal("invalid cohort returned a classification")
		}
	}
}

func TestClassificationRejectsWholeOversizedObservation(t *testing.T) {
	t.Parallel()
	input := testInput(t)
	input.Bindings.Records = []binding.Record{}
	cohort := []string{}
	address := netip.MustParseAddr("fdca:1a2b:3::1000")
	for device := range 1025 {
		mac := fmt.Sprintf("02:00:00:00:%02x:%02x", device/256, device%256)
		cohort = append(cohort, mac)
		record := binding.Record{
			MAC: mac, NAS: "synthetic-nas", Interface: "lan13", VLAN: 13,
			AssociatedAt: testNow, AssociationID: "synthetic-association", Addresses: []binding.Address{},
		}
		for range 16 {
			record.Addresses = append(record.Addresses, binding.Address{
				IP: address, Source: "qualified_ipv6", OwnershipID: "synthetic-ownership",
				ObservedAt: testNow, ValidUntil: testNow.Add(time.Hour),
			})
			address = address.Next()
		}
		input.Bindings.Records = append(input.Bindings.Records, record)
	}
	compiler := testCompiler(t, testBaseline())
	atLimit := input.Bindings
	atLimit.Records = atLimit.Records[:1024]
	addresses, err := compiler.ClassifyBindings(t.Context(), atLimit, cohort, testNow)
	if err != nil || len(addresses) != 16384 {
		t.Fatalf("exact classifier capacity failed: count=%d, error=%v", len(addresses), err)
	}
	if addresses, err := compiler.ClassifyBindings(t.Context(), input.Bindings, cohort, testNow); err == nil || addresses != nil {
		t.Fatal("oversized ownership observation returned a truncated or partial classification")
	}
}
