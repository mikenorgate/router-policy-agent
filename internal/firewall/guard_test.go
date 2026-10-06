package firewall

import (
	"bytes"
	"context"
	"encoding/json"
	"net/netip"
	"strconv"
	"strings"
	"testing"
	"time"
)

func TestGuardLayoutOwnedGeometryAndCancellation(t *testing.T) {
	t.Parallel()
	_, _, baseline, _ := renderFixture(t)
	layout, err := newGuardLayout(baseline)
	if err != nil {
		t.Fatal(err)
	}
	baseline.Zones[0].Interfaces[0] = "mutated"
	program, err := layout.program(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(program, []byte("mutated")) || !bytes.Contains(program, []byte(`device "lan10"`)) {
		t.Fatal("guard configuration retained caller-owned interface storage")
	}
	for _, fragment := range []string{
		"hook forward priority -150", "hook forward priority 150", "chain permit_flow", "hook egress",
		"ip saddr @" + classified4Set + " drop", "ip6 daddr @" + classified6Set + " drop",
		"ether saddr @" + cohortSet + " drop", "ether daddr @" + cohortSet + " drop",
		"meta mark set meta mark & " + guardMarkKeep,
	} {
		if !bytes.Contains(program, []byte(fragment)) {
			t.Fatalf("fixed guard contract missing %s", fragment)
		}
	}
	if strings.Count(string(program), "flags timeout") != 3*len(grantSets) {
		t.Fatal("guard did not define every fixed lease mirror")
	}
	mask, err := strconv.ParseUint(guardMarkMask, 0, 32)
	if err != nil {
		t.Fatal(err)
	}
	keep, err := strconv.ParseUint(guardMarkKeep, 0, 32)
	if err != nil || mask&keep != 0 || mask|keep != 0xffffffff {
		t.Fatal("mark reservation overlaps preserved bits or leaves unreset authorization bits")
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if _, err := layout.program(ctx); err == nil {
		t.Fatal("canceled guard generation succeeded")
	}
	//nolint:staticcheck // Intentionally invalid context tests the rejection boundary.
	if _, err := layout.program(nil); err == nil {
		t.Fatal("nil context accepted")
	}
	if _, err := (*guardLayout)(nil).program(t.Context()); err == nil {
		t.Fatal("nil layout accepted")
	}
	baseline.Zones[0].Interfaces[0] = `lan10"; accept`
	if _, err := newGuardLayout(baseline); err == nil {
		t.Fatal("unvalidated interface entered image rules")
	}
}

func TestGuardBridgeUsesOnlyFixedProvisionalTags(t *testing.T) {
	t.Parallel()
	expected := []string{
		"meta mark & 0xff000000 == 0xa1000000 accept",
		"meta mark & 0xff000000 == 0xa2000000 accept",
		"meta mark & 0xff000000 == 0xa3000000 accept",
		"meta mark & 0xff000000 == 0xa4000000 accept",
	}
	if strings.Join(guardBridgeRules(), "\n") != strings.Join(expected, "\n") {
		t.Fatal("bridge widened the fixed provisional mark contract")
	}
	mutated := guardBridgeRules()
	mutated[0] = "accept"
	if guardBridgeRules()[0] != expected[0] {
		t.Fatal("bridge retained caller-owned rule storage")
	}
}

func TestGuardBatchMirrorsAndOriginalPreparationFence(t *testing.T) {
	t.Parallel()
	renderer, input, _, _ := renderFixture(t)
	logical, err := renderer.prepare(t.Context(), input)
	if err != nil {
		t.Fatal(err)
	}
	original := bytes.Clone(logical.data)
	guarded, err := prepareGuards(t.Context(), logical)
	if err != nil {
		t.Fatal(err)
	}
	if err := validateGuardBatch(t.Context(), guarded.batch.data); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(logical.data, original) || guarded.batch.startedAt != logical.startedAt ||
		guarded.batch.preparedAt != logical.preparedAt || guarded.batch.startBefore != logical.startBefore {
		t.Fatal("mirror expansion altered the original authorization preparation fence")
	}
	if err := validateBatch(guarded.batch.data); err == nil {
		t.Fatal("set-only executor admitted the new guarded schema without its own inventory verifier")
	}
	counts := renderedCounts(t, guarded.batch.data)
	for name, expected := range map[string]int{
		"lease_to6_tcp": 1, "inbound_lease_to6_tcp": 1, "egress_lease_to6_tcp": 1,
		classified6Set: 1, cohortSet: 1,
	} {
		if counts[name] != expected {
			t.Fatalf("guarded %s count=%d, want %d", name, counts[name], expected)
		}
	}
	var decoded guardChanges
	if err := json.Unmarshal(guarded.batch.data, &decoded); err != nil {
		t.Fatal(err)
	}
	flushes := 0
	for _, command := range decoded.Commands {
		if command.Flush != nil {
			flushes++
		}
	}
	if flushes != 3*len(grantSets) {
		t.Fatal("incomplete atomic mirror replacement")
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if _, err := prepareGuards(ctx, logical); err == nil {
		t.Fatal("canceled mirror preparation succeeded")
	}
	if _, err := prepareGuards(t.Context(), nil); err == nil {
		t.Fatal("nil batch accepted")
	}
	//nolint:staticcheck // Intentionally invalid context tests the rejection boundary.
	if _, err := prepareGuards(nil, logical); err == nil {
		t.Fatal("nil preparation context accepted")
	}
}

func TestGuardBatchProjectionDeduplicatesWithoutDroppingIdentities(t *testing.T) {
	t.Parallel()
	commands := make([]change, 0)
	for _, name := range grantSets {
		commands = append(commands, change{Flush: &setChange{Set: ownedRef(name)}})
	}
	values := make([]json.RawMessage, 0)
	for index, mac := range []string{"02:00:00:00:00:01", "02:00:00:00:00:02"} {
		value, err := renderTuple(tupleKey{
			interfaceName: "lan13", mac: mac, device: netip.MustParseAddr("10.240.3.10"),
			peer: netip.MustParseAddr("10.240.0.10"), port: 6053,
		}, time.Duration(30+index*10)*time.Second)
		if err != nil {
			t.Fatal(err)
		}
		values = append(values, value)
	}
	commands = append(commands, addElements("lease_to4_tcp", values))
	logical, err := json.Marshal(guardChanges{Commands: commands})
	if err != nil {
		t.Fatal(err)
	}
	guarded, err := prepareGuards(t.Context(), &preparedBatch{data: logical})
	if err != nil {
		t.Fatal(err)
	}
	if err := validateGuardBatch(t.Context(), guarded.batch.data); err != nil {
		t.Fatal(err)
	}
	counts := renderedCounts(t, guarded.batch.data)
	if counts["lease_to4_tcp"] != 2 || counts["egress_lease_to4_tcp"] != 2 ||
		counts["inbound_lease_to4_tcp"] != 1 || counts[classified4Set] != 1 {
		t.Fatal("projection duplicates either changed exact MAC scope or duplicated IP classification")
	}
	var decoded guardChanges
	if err := json.Unmarshal(guarded.batch.data, &decoded); err != nil {
		t.Fatal(err)
	}
	for _, command := range decoded.Commands {
		if command.Add != nil && command.Add.Element.Name == "inbound_lease_to4_tcp" {
			if !bytes.Contains(command.Add.Element.Values[0], []byte(`"timeout":35`)) {
				t.Fatal("projection did not retain the maximum still-valid contributor lifetime")
			}
		}
	}
}

func TestGuardBatchRejectsPrivilegeAndMirrorChanges(t *testing.T) {
	t.Parallel()
	renderer, input, _, _ := renderFixture(t)
	logical, err := renderer.prepare(t.Context(), input)
	if err != nil {
		t.Fatal(err)
	}
	guarded, err := prepareGuards(t.Context(), logical)
	if err != nil {
		t.Fatal(err)
	}
	valid := string(guarded.batch.data)
	replace := func(name, before, after string) string {
		return replaceGuardAddition(t, guarded.batch.data, guardEdit{name: name, before: before, after: after})
	}
	for _, test := range []struct{ name, input string }{
		{name: "wrong table", input: strings.Replace(valid, ownedTable, "unrelated", 1)},
		{name: "wrong mirror name", input: strings.Replace(valid, "egress_lease_to6_tcp", "egress_lease_to6_udp", 1)},
		{name: "classification removal", input: strings.Replace(valid, "lease_from4_tcp", cohortSet, 1)},
		{name: "case folded operation", input: strings.Replace(valid, `"flush"`, `"FLUSH"`, 1)},
		{name: "case folded reference", input: strings.Replace(valid, `"family"`, `"FAMILY"`, 1)},
		{name: "null transaction", input: `{"nftables":null}`},
		{name: "rule operation", input: `{"nftables":[{"add":{"rule":{"family":"inet","table":"router_policy_agent","chain":"permit_flow","expr":[{"accept":null}]}}}]}`},
		{name: "trailing program", input: valid + `{"nftables":[]}`},
		{name: "projection timeout changed", input: replace("inbound_lease_to6_tcp", `"timeout":85`, `"timeout":86`)},
		{name: "mirror port changed", input: replace("egress_lease_to6_tcp", "6053", "6054")},
		{name: "mirror mac changed", input: replace("egress_lease_to6_tcp", "02:00:00:00:00:01", "02:00:00:00:00:02")},
		{name: "classification widened", input: replace(classified6Set, "fdca:1a2b:3::10", "fdca:1a2b:3::11")},
		{name: "cohort mirror changed", input: replace(cohortSet, "02:00:00:00:00:01", "02:00:00:00:00:02")},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			if err := validateGuardBatch(t.Context(), []byte(test.input)); err == nil {
				t.Fatal("unowned operation or inconsistent guarded mirror accepted")
			}
		})
	}
	//nolint:staticcheck // Intentionally invalid context tests the rejection boundary.
	if err := validateGuardBatch(nil, guarded.batch.data); err == nil {
		t.Fatal("nil validation context accepted")
	}
}

type guardEdit struct{ name, before, after string }

func replaceGuardAddition(t *testing.T, data []byte, edit guardEdit) string {
	t.Helper()
	var decoded guardChanges
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatal(err)
	}
	for index := range decoded.Commands {
		command := &decoded.Commands[index]
		if command.Add == nil || command.Add.Element.Name != edit.name {
			continue
		}
		raw, err := json.Marshal(command.Add.Element.Values)
		if err != nil {
			t.Fatal(err)
		}
		replaced := bytes.Replace(raw, []byte(edit.before), []byte(edit.after), 1)
		if bytes.Equal(replaced, raw) {
			t.Fatal("synthetic rejection fixture did not change its target")
		}
		if err := json.Unmarshal(replaced, &command.Add.Element.Values); err != nil {
			t.Fatal(err)
		}
		break
	}
	mutated, err := json.Marshal(decoded)
	if err != nil {
		t.Fatal(err)
	}
	return string(mutated)
}
