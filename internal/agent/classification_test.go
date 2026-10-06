package agent

import (
	"context"
	"errors"
	"net/netip"
	"slices"
	"testing"
	"time"

	"github.com/mikenorgate/router-policy-agent/internal/binding"
	"github.com/mikenorgate/router-policy-agent/internal/ipc"
	"github.com/mikenorgate/router-policy-agent/internal/policy"
	"github.com/mikenorgate/router-policy-agent/internal/state"
)

func addIPv4Binding(f *fixture) {
	f.bindings.Records[0].Addresses = append(f.bindings.Records[0].Addresses, binding.Address{
		IP: netip.MustParseAddr("10.240.3.10"), Source: "kea_dhcp4", OwnershipID: "synthetic-v4",
		ObservedAt: f.directory.ObservedAt, ValidUntil: f.now.Add(time.Hour),
	})
}

func TestColdHelperStartRestoresDenyOnlyAddressHistory(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	addIPv4Binding(f)
	f.directory.Devices[0].Active = false
	engine := f.engine(t, f.options(Enforce))
	if receipt, err := engine.Process(t.Context(), f.directory); err != nil || receipt.GrantCount != 0 ||
		len(f.store.document.ClassifiedIPv4) != 1 || len(f.store.document.ClassifiedIPv6) != 2 {
		t.Fatalf("inactive zero-grant identity lost native/NAT deny-only history: %+v, %v", receipt, err)
	}
	if err := engine.Stop(t.Context()); err != nil {
		t.Fatal(err)
	}
	// Model losing all process-local kernel fixtures at cold startup. This is
	// a callback-contract test, not evidence that boot admits no actual packets.
	f.firewall = memoryFirewall{events: &f.events}
	restarted, err := New(f.baseline, f.options(Enforce))
	if err != nil {
		t.Fatal(err)
	}
	if err := restarted.Start(t.Context()); err != nil || len(f.firewall.active) != 0 ||
		!slices.Equal(f.firewall.ipv4, f.store.document.ClassifiedIPv4) ||
		!slices.Equal(f.firewall.ipv6, f.store.document.ClassifiedIPv6) || len(f.firewall.cohort) != 1 {
		t.Fatalf("cold helper start lost deny history or restored a permission: %v", err)
	}
	if _, err := restarted.Process(t.Context(), f.directory); err == nil || len(f.firewall.active) != 0 {
		t.Fatal("cold helper start treated historical classification as fresh authorization")
	}
}

func TestBindingChangesAndUnmanagedReuseCannotEraseHistory(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	engine := f.engine(t, f.options(Enforce))
	if _, err := engine.Process(t.Context(), f.directory); err != nil {
		t.Fatal(err)
	}
	historical := f.store.document.ClassifiedIPv6[0]
	for _, phase := range []string{"privacy change", "inactive account", "removed account", "unmanaged reuse", "disconnected"} {
		f.setUTC(f.now.Add(time.Second))
		f.directory.ObservedAt, f.bindings.ObservedAt = f.now, f.now
		if len(f.bindings.Records) != 0 {
			f.bindings.Records[0].AssociatedAt = f.now
			f.bindings.Records[0].Addresses[0].ObservedAt = f.now
		}
		switch phase {
		case "privacy change":
			f.bindings.Records[0].Addresses[0].IP = netip.MustParseAddr("fdca:1a2b:3::11")
		case "inactive account":
			f.directory.Devices[0].Active = false
		case "removed account":
			f.directory.Devices = []policy.Device{}
			f.bindings.Records[0].Addresses[0].IP = netip.MustParseAddr("fdca:1a2b:3::12")
		case "unmanaged reuse":
			f.bindings.Records[0].MAC = "02:00:00:00:00:02"
			f.bindings.Records[0].Addresses[0].IP = netip.MustParseAddr(historical)
		case "disconnected":
			f.bindings.Records = []binding.Record{}
		}
		receipt, err := engine.Process(t.Context(), f.directory)
		if err != nil || !slices.Contains(f.store.document.ClassifiedIPv6, historical) ||
			!slices.Contains(f.firewall.ipv6, historical) {
			t.Fatalf("identity lifecycle erased historical deny during %s: %v", phase, err)
		}
		if phase != "privacy change" && (receipt.GrantCount != 0 || len(f.firewall.active) != 0) {
			t.Fatalf("historical address ownership leaked permission during %s", phase)
		}
	}
	if !slices.Contains(f.store.document.ClassifiedIPv6, "fdca:1a2b:3::12") || len(f.store.document.CohortMACs) != 1 {
		t.Fatal("managed identity absent from directory was not classified, or IP reuse added a new identity")
	}
}

func TestClassificationSaveFailureStillSealsNewAddresses(t *testing.T) {
	t.Parallel()
	for _, advanced := range []bool{false, true} {
		t.Run(map[bool]string{false: "failure before rename", true: "failure after rename"}[advanced], func(t *testing.T) {
			t.Parallel()
			f := newFixture(t)
			engine := f.engine(t, f.options(Enforce))
			f.store.failSave, f.store.advanceThenFail = 2, advanced
			receipt, err := engine.Process(t.Context(), f.directory)
			if !errors.Is(err, errFixture) || receipt.Status != "" || len(f.firewall.active) != 0 ||
				!slices.Contains(f.firewall.ipv6, "fdca:1a2b:3::10") || len(f.firewall.candidates) != 0 {
				t.Fatalf("failed classification persistence authorized or lost closed cleanup: %v", err)
			}
		})
	}
}

func TestFailedClassifierRestoreDoesNotStartHelper(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	engine := f.engine(t, f.options(Enforce))
	if _, err := engine.Process(t.Context(), f.directory); err != nil {
		t.Fatal(err)
	}
	options := f.options(Enforce)
	seal := options.Firewall.Seal
	options.Firewall.Seal = func(ctx context.Context, classification state.Classification) error {
		if len(classification.IPv6) != 0 {
			return errFixture
		}
		return seal(ctx, classification)
	}
	failed, err := New(f.baseline, options)
	if err != nil {
		t.Fatal(err)
	}
	if err := failed.Start(t.Context()); !errors.Is(err, errFixture) || len(f.firewall.active) != 0 {
		t.Fatalf("failed restore started or retained permits: %v", err)
	}
	if receipt, err := failed.Process(t.Context(), f.directory); err == nil || receipt.Status != "" {
		t.Fatal("helper accepted a request without complete classifier restoration")
	}
}

func TestBackendCannotMutateDurableClassification(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	options := f.options(Enforce)
	apply := options.Firewall.Apply
	options.Firewall.Apply = func(ctx context.Context, authorization policy.Authorization, classification state.Classification) error {
		if err := apply(ctx, authorization, classification); err != nil {
			return err
		}
		classification.MACs[0] = "02:00:00:00:00:02"
		classification.IPv6[0] = "fdca:1a2b:3::99"
		return nil
	}
	engine := f.engine(t, options)
	if receipt, err := engine.Process(t.Context(), f.directory); err != nil || receipt.Status != ipc.StatusApplied {
		t.Fatal(err)
	}
	if f.store.document.CohortMACs[0] != "02:00:00:00:00:01" ||
		f.store.document.ClassifiedIPv6[0] != "fdca:1a2b:3::10" {
		t.Fatal("backend modified durable classification through a shared slice")
	}
}

func TestZeroAccessPolicyStillClassifiesDeviceAddresses(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	f.directory.Devices[0].GroupIDs = f.directory.Devices[0].GroupIDs[:1]
	engine := f.engine(t, f.options(Enforce))
	receipt, err := engine.Process(t.Context(), f.directory)
	if err != nil || receipt.GrantCount != 0 || receipt.DenialCount != 0 ||
		!slices.Contains(f.store.document.ClassifiedIPv6, "fdca:1a2b:3::10") ||
		!slices.Contains(f.firewall.ipv6, "fdca:1a2b:3::10") {
		t.Fatalf("valid zero-access policy lost deny-only classification: %+v, %v", receipt, err)
	}
}

func TestCompilerFailureCannotDiscardNewClassifiers(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	f.baseline.MaximumTuples = 1
	addIPv4Binding(f)
	engine := f.engine(t, f.options(Enforce))
	receipt, err := engine.Process(t.Context(), f.directory)
	if err == nil || receipt.Status != "" || f.store.saves != 2 || len(f.firewall.candidates) != 0 ||
		!slices.Contains(f.store.document.ClassifiedIPv4, "10.240.3.10") ||
		!slices.Contains(f.firewall.ipv4, "10.240.3.10") || len(f.firewall.active) != 0 {
		t.Fatalf("compiler overflow lost persisted classification or admitted partial grants: %v", err)
	}
}
