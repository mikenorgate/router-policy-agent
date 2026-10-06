package firewall

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net"
	"net/netip"
	"slices"
	"strings"
	"testing"

	"github.com/mikenorgate/router-policy-agent/internal/state"
)

func guardClassificationFixture() state.Classification {
	return state.Classification{
		MACs: []string{"02:00:00:00:00:01", "02:00:00:00:00:02"},
		IPv4: []string{"10.240.3.10", "10.250.0.30"},
		IPv6: []string{"fdca:1a2b:3::10", "fdca:1a2b:3::11", "fdca:1a2b:64::af0:30a"},
	}
}

func TestGuardClassificationRestoresWithoutGrantsAndOwnsHistory(t *testing.T) {
	t.Parallel()
	history := guardClassificationFixture()
	prepared, err := prepareGuardSeal(t.Context(), history)
	if err != nil {
		t.Fatal(err)
	}
	before := bytes.Clone(prepared.batch.data)
	history.MACs[0], history.IPv4[0], history.IPv6[0] = "mutated", "mutated", "mutated"
	if err := validatePreparedGuardBatch(t.Context(), prepared); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(before, prepared.batch.data) || prepared.classification.MACs[0] == "mutated" {
		t.Fatal("preparation retained caller-owned history")
	}
	if err := validateGuardBatch(t.Context(), prepared.batch.data); err == nil {
		t.Fatal("raw guarded schema admitted independently supplied history")
	}
	if err := validateBatch(prepared.batch.data); err == nil {
		t.Fatal("set-only executor admitted the classified restoration schema")
	}
	counts := renderedCounts(t, prepared.batch.data)
	if counts[cohortSet] != 2 || counts[classified4Set] != 2 || counts[classified6Set] != 3 {
		t.Fatal("zero-grant restoration omitted native, counterpart or previous device classifiers")
	}
	decoded, err := decodeGuardChanges(prepared.batch.data)
	if err != nil {
		t.Fatal(err)
	}
	flushes, cohorts := 0, 0
	for _, command := range decoded.Commands {
		if command.Flush != nil {
			flushes++
			continue
		}
		name := command.Add.Element.Name
		if name == cohortSet {
			cohorts++
			continue
		}
		if name != classified4Set && name != classified6Set {
			t.Fatal("deny-only restoration invented a lease")
		}
	}
	if flushes != 3*len(grantSets) || cohorts != 2 || !prepared.batch.startedAt.IsZero() {
		t.Fatal("sealing omitted mirrors or invented an authorization age")
	}
	// An empty startup/stop handoff still clears only leases; no permanent-set
	// flush or deletion is manufactured to match the absence of additions.
	empty, err := prepareGuardSeal(t.Context(), state.EmptyClassification())
	if err != nil || validatePreparedGuardBatch(t.Context(), empty) != nil {
		t.Fatalf("empty deny-only handoff was rejected: %v", err)
	}
	decoded, err = decodeGuardChanges(empty.batch.data)
	if err != nil || len(decoded.Commands) != 3*len(grantSets) {
		t.Fatal("empty handoff changed more than the fixed lease mirrors")
	}
}

func TestGuardClassificationRetainsOriginalLeaseAndPreparationFence(t *testing.T) {
	t.Parallel()
	renderer, input, _, _ := renderFixture(t)
	logical, err := renderer.prepare(t.Context(), input)
	if err != nil {
		t.Fatal(err)
	}
	original := bytes.Clone(logical.data)
	guarded, err := prepareClassifiedGuards(t.Context(), logical, guardClassificationFixture())
	if err != nil || validatePreparedGuardBatch(t.Context(), guarded) != nil {
		t.Fatalf("saved classifiers could not accompany renderer leases: %v", err)
	}
	if !bytes.Equal(logical.data, original) || guarded.batch.startedAt != logical.startedAt ||
		guarded.batch.preparedAt != logical.preparedAt || guarded.batch.startBefore != logical.startBefore {
		t.Fatal("restoring classification renewed or changed the renderer's preparation fence")
	}
	counts := renderedCounts(t, guarded.batch.data)
	for _, name := range []string{"lease_to6_tcp", "inbound_lease_to6_tcp", "egress_lease_to6_tcp"} {
		if counts[name] != 1 {
			t.Fatal("classification restoration changed exact active mirror scope")
		}
	}
	decoded, err := decodeGuardChanges(guarded.batch.data)
	if err != nil {
		t.Fatal(err)
	}
	for _, command := range decoded.Commands {
		if command.Add != nil && command.Add.Element.Name == "lease_to6_tcp" &&
			!bytes.Contains(command.Add.Element.Values[0], []byte(`"timeout":85`)) {
			t.Fatal("classification restoration altered the original lease duration")
		}
	}
}

func TestGuardClassificationRequiresSavedIdentitiesAndStrictHandoffs(t *testing.T) {
	t.Parallel()
	for _, name := range []string{
		"nil arrays", "orphan address", "noncanonical mac", "wrong address family",
		"duplicate address", "unsorted addresses", "missing cohort delta", "missing leased address",
		"missing leased mac", "invalid logical batch",
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			history, source := guardClassificationFixture(), leasedBatch(t)
			switch name {
			case "nil arrays":
				history.IPv4 = nil
			case "orphan address":
				history.MACs = []string{}
			case "noncanonical mac":
				history.MACs[0] = "02-00-00-00-00-01"
			case "wrong address family":
				history.IPv6 = []string{"10.240.3.10"}
			case "duplicate address":
				history.IPv4 = append(history.IPv4[:1], history.IPv4[0])
			case "unsorted addresses":
				slices.Reverse(history.IPv6)
			case "missing cohort delta":
				history.MACs = history.MACs[1:]
			case "missing leased address":
				history.IPv6 = []string{}
			case "missing leased mac":
				history.MACs = history.MACs[1:]
				var changes guardChanges
				if err := json.Unmarshal(source, &changes); err != nil {
					t.Fatal(err)
				}
				changes.Commands = append(changes.Commands[:len(grantSets)], changes.Commands[len(grantSets)+1:]...)
				var err error
				source, err = json.Marshal(changes)
				if err != nil {
					t.Fatal(err)
				}
			case "invalid logical batch":
				source = []byte(`{"nftables":[]}`)
			}
			if prepared, err := prepareClassifiedGuards(t.Context(), &preparedBatch{data: source}, history); err == nil || prepared != nil {
				t.Fatal("invalid or unsaved classifier produced a transaction")
			}
		})
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if prepared, err := prepareGuardSeal(ctx, guardClassificationFixture()); !errors.Is(err, context.Canceled) || prepared != nil {
		t.Fatal("sealing discarded cancellation or returned partial preparation")
	}
	//nolint:staticcheck // Intentionally invalid context tests the rejection boundary.
	if prepared, err := prepareGuardSeal(nil, state.EmptyClassification()); err == nil || prepared != nil {
		t.Fatal("missing sealing context was accepted")
	}
	if err := validatePreparedGuardBatch(t.Context(), nil); err == nil {
		t.Fatal("missing prepared transaction was accepted")
	}
	//nolint:staticcheck // Intentionally invalid context tests the rejection boundary.
	if _, err := classifyGuardChanges(nil, guardChanges{}, state.EmptyClassification()); err == nil {
		t.Fatal("classification normalization accepted a missing context")
	}
	if _, err := classifyGuardChanges(t.Context(), guardChanges{Commands: []change{{}}}, state.EmptyClassification()); err == nil {
		t.Fatal("classification normalization accepted a missing operation")
	}
}

func TestGuardClassificationValidatorRejectsStateAndOperationDrift(t *testing.T) {
	t.Parallel()
	sealed, err := prepareGuardSeal(t.Context(), guardClassificationFixture())
	if err != nil {
		t.Fatal(err)
	}
	valid := string(sealed.batch.data)
	for _, test := range []struct{ name, raw string }{
		{name: "changed historical address", raw: strings.Replace(valid, "fdca:1a2b:3::11", "fdca:1a2b:3::12", 1)},
		{name: "missing historical address", raw: strings.Replace(valid, `,"fdca:1a2b:3::11"`, "", 1)},
		{name: "prefix instead of host", raw: strings.Replace(valid, "fdca:1a2b:3::11", "fdca:1a2b:3::/64", 1)},
		{name: "timeout on classifier", raw: strings.Replace(valid, `"10.240.3.10"`, `{"elem":{"val":"10.240.3.10","timeout":87}}`, 1)},
		{name: "both cohort mirrors omitted", raw: strings.ReplaceAll(valid, `,"02:00:00:00:00:02"`, "")},
		{name: "flushed permanent classifier", raw: strings.Replace(valid, `"lease_from4_tcp"`, `"classified_addresses4"`, 1)},
		{name: "foreign object", raw: strings.Replace(valid, ownedTable, "unrelated_fixture", 1)},
		{name: "delete operation", raw: strings.Replace(valid, `"flush"`, `"delete"`, 1)},
		{name: "extra field", raw: strings.Replace(valid, `"name":"managed_macs"`, `"name":"managed_macs","flags":["interval"]`, 1)},
		{name: "trailing program", raw: valid + `{}`},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			if test.raw == valid {
				t.Fatal("rejection fixture did not mutate its target")
			}
			if err := validateGuardBatchWithClassification(t.Context(), []byte(test.raw), sealed.classification); err == nil {
				t.Fatal("state mismatch or privilege expansion was accepted")
			}
		})
	}
}

func TestGuardClassifiedInventoryPreservesHistoryAndUnionCapacity(t *testing.T) {
	t.Parallel()
	layout, listings := guardListingFixture(t, true)
	inventory, err := layout.inspect(t.Context(), listings)
	if err != nil {
		t.Fatal(err)
	}
	for _, history := range []state.Classification{state.EmptyClassification(), guardClassificationFixture()} {
		sealed, err := prepareGuardSeal(t.Context(), history)
		if err != nil || inventory.checkPreparedReplacement(t.Context(), sealed) != nil {
			t.Fatalf("verified inventory could not retain or restore historical classifiers: %v", err)
		}
	}
	if inventory.leases != 1 || len(inventory.cohort) != 1 || len(inventory.addresses6) != 1 {
		t.Fatal("replacement checking changed the observed inventory")
	}
	history := guardClassificationFixture()
	history.IPv4 = make([]string, 0, maximumTupleCount)
	for index := range maximumTupleCount {
		address := netip.AddrFrom4([4]byte{10, 242, byte(index >> 8), byte(index & 255)})
		history.IPv4 = append(history.IPv4, address.String())
	}
	slices.Sort(history.IPv4)
	sealed, err := prepareGuardSeal(t.Context(), history)
	if err != nil {
		t.Fatal(err)
	}
	if err := inventory.checkPreparedReplacement(t.Context(), sealed); err != nil {
		t.Fatal("exact permanent address capacity was rejected")
	}
	full := *inventory
	full.addresses4 = []netip.Addr{netip.MustParseAddr("10.240.3.10")}
	if err := full.checkPreparedReplacement(t.Context(), sealed); err == nil {
		t.Fatal("restoration exceeded the kernel/state address union capacity")
	}
	macFull := *inventory
	macFull.cohort = make([]string, 0, maximumCohortSize)
	for index := range maximumCohortSize {
		// The fixed quota is below 2^16; split only that bounded index.
		mac := []byte{2, 0, 0, 1, byte(index >> 8), byte(index & 255)}
		macFull.cohort = append(macFull.cohort, net.HardwareAddr(mac).String())
	}
	if err := macFull.checkPreparedReplacement(t.Context(), sealed); err == nil {
		t.Fatal("restoration exceeded the kernel/state MAC union capacity")
	}
	history.IPv4 = append(history.IPv4, "10.253.0.10")
	if prepared, err := prepareGuardSeal(t.Context(), history); err == nil || prepared != nil {
		t.Fatal("over-capacity state produced a partial restoration")
	}
	if err := inventory.checkPreparedReplacement(t.Context(), nil); err == nil {
		t.Fatal("inventory accepted a missing preparation")
	}
	if err := (*guardInventory)(nil).checkPreparedReplacement(t.Context(), sealed); err == nil {
		t.Fatal("classified replacement accepted a missing inventory")
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if err := inventory.checkPreparedReplacement(ctx, sealed); !errors.Is(err, context.Canceled) {
		t.Fatal("classified replacement discarded cancellation")
	}
}

func FuzzGuardClassifiedSeal(f *testing.F) {
	sealed, err := prepareGuardSeal(f.Context(), guardClassificationFixture())
	if err != nil {
		f.Fatal(err)
	}
	f.Add(sealed.batch.data)
	f.Add([]byte(`{"nftables":null}`))
	f.Fuzz(func(t *testing.T, data []byte) {
		if err := validateGuardBatchWithClassification(t.Context(), data, sealed.classification); err != nil {
			return
		}
		canonical, err := canonicalGuardJSON(data)
		if err != nil {
			t.Fatal(err)
		}
		wanted, err := canonicalGuardJSON(sealed.batch.data)
		if err != nil || !bytes.Equal(canonical, wanted) {
			t.Fatal("deny-only seal admitted a lease, omission or extra operation")
		}
	})
}
