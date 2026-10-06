package firewall

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"maps"
	"net/netip"
	"os"
	"slices"
	"strings"
	"testing"

	"github.com/mikenorgate/router-policy-agent/internal/policy"
)

// Unit listings are synthetic selected-version fixtures. The separate kernel
// test compares the schema with listings of the actual textual guard program.
func guardListingFixture(t testing.TB, populated bool) (*guardLayout, guardListings) {
	t.Helper()
	data, err := os.ReadFile("../../examples/baseline.json")
	if err != nil {
		t.Fatal(err)
	}
	baseline, err := policy.DecodeBaseline(data)
	if err != nil {
		t.Fatal(err)
	}
	layout, err := newGuardLayout(baseline)
	if err != nil {
		t.Fatal(err)
	}
	source := clearBatch(t)
	if populated {
		source = leasedBatch(t)
	}
	guarded, err := prepareGuards(t.Context(), &preparedBatch{data: source})
	if err != nil {
		t.Fatal(err)
	}
	changes, err := decodeGuardChanges(guarded.batch.data)
	if err != nil {
		t.Fatal(err)
	}
	values := map[objectReference][]json.RawMessage{}
	for _, command := range changes.Commands {
		if command.Add != nil {
			value := command.Add.Element
			values[objectReference{Family: value.Family, Table: value.Table, Name: value.Name}] = value.Values
		}
	}
	listings := guardListings{}
	for _, family := range []string{"inet", "netdev"} {
		schema, err := layout.schema(family)
		if err != nil {
			t.Fatal(err)
		}
		objects := []map[string]any{
			{"metainfo": map[string]any{"version": "1.1.3", "release_name": "Commodore Bullmoose #4", "json_schema_version": 1}},
			{"table": map[string]any{"family": family, "name": ownedTable, "handle": 1}},
		}
		handle := 1
		for _, name := range slices.Sorted(maps.Keys(schema.chains)) {
			header := maps.Clone(schema.chains[name])
			header["handle"] = handle
			handle++
			objects = append(objects, map[string]any{"chain": header})
		}
		for _, name := range slices.Sorted(maps.Keys(schema.sets)) {
			header := maps.Clone(schema.sets[name])
			header["handle"] = handle
			handle++
			elements := make([]json.RawMessage, 0)
			for _, value := range values[objectReference{Family: family, Table: ownedTable, Name: name}] {
				if name == cohortSet || name == classified4Set || name == classified6Set {
					elements = append(elements, value)
					continue
				}
				var wrapper struct {
					Element map[string]json.RawMessage `json:"elem"`
				}
				if err := json.Unmarshal(value, &wrapper); err != nil {
					t.Fatal(err)
				}
				wrapper.Element["expires"] = json.RawMessage("1")
				encoded, err := json.Marshal(wrapper)
				if err != nil {
					t.Fatal(err)
				}
				elements = append(elements, encoded)
			}
			if len(elements) != 0 {
				header["elem"] = elements
			}
			objects = append(objects, map[string]any{"set": header})
		}
		for _, chain := range slices.Sorted(maps.Keys(schema.rules)) {
			for _, expressions := range schema.rules[chain] {
				objects = append(objects, map[string]any{"rule": map[string]any{
					"family": family, "table": ownedTable, "chain": chain, "handle": handle, "expr": expressions,
				}})
				handle++
			}
		}
		encoded := listingFixture(t, objects)
		if family == "inet" {
			listings.inet = encoded
			continue
		}
		listings.netdev = encoded
	}
	return layout, listings
}

func TestGuardInspectionAcceptsOwnedGraphAndPermanentHistory(t *testing.T) {
	t.Parallel()
	for _, populated := range []bool{false, true} {
		name := "empty guard layout"
		if populated {
			name = "complete leased layout"
		}
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			layout, listings := guardListingFixture(t, populated)
			// Two separately observed tables can straddle a rounded expiry second.
			listings.netdev = bytes.ReplaceAll(listings.netdev, []byte(`"expires":1`), []byte(`"expires":0`))
			inventory, err := layout.inspect(t.Context(), listings)
			if err != nil {
				t.Fatal(err)
			}
			expected := 0
			if populated {
				expected = 1
			}
			if inventory.leases != expected || len(inventory.cohort) != expected || len(inventory.addresses6) != expected {
				t.Fatal("verified guard inventory lost exact classification or lease count")
			}
			if _, err := verifySetInventory(t.Context(), listings.inet); err == nil {
				t.Fatal("set-only verifier accepted a guarded table")
			}
			if populated {
				listings.inet = bytes.ReplaceAll(listings.inet,
					[]byte(`"elem":["fdca:1a2b:3::10"]`),
					[]byte(`"elem":["fdca:1a2b:3::11","fdca:1a2b:3::10"]`))
				inventory, err = layout.inspect(t.Context(), listings)
				if err != nil || len(inventory.addresses6) != 2 {
					t.Fatalf("historical permanent address classification was rejected: %v", err)
				}
			}
		})
	}
}

func TestGuardInspectionRejectsSchemaRuleAndLeaseDrift(t *testing.T) {
	t.Parallel()
	layout, original := guardListingFixture(t, true)
	cases := []struct {
		name, old, replacement string
		netdev                 bool
	}{
		{name: "unqualified library", old: `"version":"1.1.3"`, replacement: `"version":"1.1.4"`},
		{name: "table flags", old: `"handle":1,"name":"router_policy_agent"`,
			replacement: `"flags":["dormant"],"handle":1,"name":"router_policy_agent"`},
		{name: "foreign table", old: `"table":"router_policy_agent"`, replacement: `"table":"baseline"`},
		{name: "zero handles", old: `"handle":1`, replacement: `"handle":0`},
		{name: "case folded handle", old: `"handle":1`, replacement: `"Handle":1`},
		{name: "wrong forward hook", old: `"hook":"forward"`, replacement: `"hook":"prerouting"`},
		{name: "wrong forward priority", old: `"prio":-150`, replacement: `"prio":150`},
		{name: "wrong confirmation priority", old: `"prio":150`, replacement: `"prio":149`},
		{name: "changed confirmation caller", old: `"target":"permit_flow"`, replacement: `"target":"guard_forward"`},
		{name: "changed confirmation tag", old: `2701131776`, replacement: `2701131777`},
		{name: "changed regular chain", old: `"name":"permit_flow"`,
			replacement: `"name":"permit_flow","hook":"forward","type":"filter","prio":0,"policy":"accept"`},
		{name: "changed mark reservation", old: `16711680`, replacement: `0`},
		{name: "changed conntrack direction", old: `"right":"original"`, replacement: `"right":"reply"`},
		{name: "changed listener field", old: `"key":"proto-dst"`, replacement: `"key":"proto-src"`},
		{name: "changed verdict", old: `"return":null`, replacement: `"accept":null`},
		{name: "changed rule match", old: `"op":"=="`, replacement: `"op":"!="`},
		{name: "duplicate expression key", old: `"op":"=="`, replacement: `"op":"==","op":"=="`},
		{name: "unknown protocol", old: `"right":"tcp"`, replacement: `"right":"icmp"`},
		{name: "lease datatype", old: `"inet_service"`, replacement: `"mark"`},
		{name: "lease bounds", old: `"timeout":90`, replacement: `"timeout":91`},
		{name: "traffic refreshed lease", old: `"flags":["timeout"]`,
			replacement: `"flags":["timeout","dynamic"]`},
		{name: "cohort expiry", old: `"size":4096`, replacement: `"size":4096,"timeout":90`},
		{name: "cohort mismatch", netdev: true, old: `"elem":["02:00:00:00:00:01"]`, replacement: `"elem":[]`},
		{name: "unclassified address", old: `"elem":["fdca:1a2b:3::10"]`, replacement: `"elem":[]`},
		{name: "duplicate classified address", old: `"elem":["fdca:1a2b:3::10"]`,
			replacement: `"elem":["fdca:1a2b:3::10","fdca:1a2b:3::10"]`},
		{name: "invalid classified address", old: `"elem":["fdca:1a2b:3::10"]`, replacement: `"elem":["::1"]`},
		{name: "wrong classified family", old: `"elem":["fdca:1a2b:3::10"]`, replacement: `"elem":["10.240.3.10"]`},
		{name: "mirror timeout mismatch", netdev: true, old: `"timeout":2`, replacement: `"timeout":3`},
		{name: "projection listener mismatch", old: `["lan13","fdca:1a2b:3::10","fdca:1a2b::10",6053]`,
			replacement: `["lan13","fdca:1a2b:3::10","fdca:1a2b::10",6054]`},
		{name: "mirror listener mismatch", netdev: true, old: `6053`, replacement: `6054`},
		{name: "mirror mac mismatch", netdev: true, old: `"02:00:00:00:00:01","fdca:1a2b:3::10"`,
			replacement: `"02:00:00:00:00:02","fdca:1a2b:3::10"`},
		{name: "excess lease expiry", old: `"expires":1`, replacement: `"expires":3`},
		{name: "null lease expiry", old: `"expires":1`, replacement: `"expires":null`},
		{name: "unreserved egress device", netdev: true, old: `"dev":"lan13"`, replacement: `"dev":"other"`},
		{name: "late egress hook", netdev: true, old: `"prio":0`, replacement: `"prio":1`},
		{name: "wrong mark datatype", netdev: true, old: `"mark"]`, replacement: `"inet_service"]`},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			listings := original
			target := &listings.inet
			if test.netdev {
				target = &listings.netdev
			}
			if !bytes.Contains(*target, []byte(test.old)) {
				t.Fatal("rejection test does not mutate its fixture")
			}
			*target = []byte(strings.ReplaceAll(string(*target), test.old, test.replacement))
			if inventory, err := layout.inspect(t.Context(), listings); err == nil || inventory != nil {
				t.Fatal("guard drift produced trusted or partial inventory")
			}
		})
	}
}

func TestGuardInspectionRejectsMissingExtraAndReorderedObjects(t *testing.T) {
	t.Parallel()
	for _, name := range []string{
		"missing rule", "extra rule", "unknown object", "duplicate handle",
		"rule order", "missing mirror", "null objects", "trailing input", "missing confirmation chain",
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			layout, listings := guardListingFixture(t, true)
			var listing struct {
				Objects []json.RawMessage `json:"nftables"`
			}
			if err := json.Unmarshal(listings.inet, &listing); err != nil {
				t.Fatal(err)
			}
			switch name {
			case "missing rule":
				listing.Objects = listing.Objects[:len(listing.Objects)-1]
			case "missing confirmation chain":
				removed := false
				for index, object := range listing.Objects {
					if bytes.Contains(object, []byte(`"name":"guard_confirm"`)) {
						listing.Objects = slices.Delete(listing.Objects, index, index+1)
						removed = true
						break
					}
				}
				if !removed {
					t.Fatal("confirmation-chain rejection fixture did not change")
				}
			case "extra rule":
				listing.Objects = append(listing.Objects, listing.Objects[len(listing.Objects)-1])
			case "unknown object":
				listing.Objects[2] = json.RawMessage(`{"counter":{"name":"unowned"}}`)
			case "duplicate handle":
				listing.Objects[3] = bytes.ReplaceAll(listing.Objects[3], []byte(`"handle":2`), []byte(`"handle":1`))
			case "rule order":
				last := len(listing.Objects) - 1
				listing.Objects[last], listing.Objects[last-1] = listing.Objects[last-1], listing.Objects[last]
			case "missing mirror":
				listings.netdev = bytes.ReplaceAll(listings.netdev,
					[]byte(`"elem":[{"elem":{"expires":1,"timeout":2,"val":{"concat":`+
						`["lan13","02:00:00:00:00:01","fdca:1a2b:3::10","fdca:1a2b::10",6053]}}}]`),
					[]byte(`"elem":[]`))
			case "null objects":
				listing.Objects = nil
			}
			encoded, err := json.Marshal(listing)
			if err != nil {
				t.Fatal(err)
			}
			listings.inet = encoded
			if name == "trailing input" {
				listings.inet = append(listings.inet, []byte(`{}`)...)
			}
			if inventory, err := layout.inspect(t.Context(), listings); err == nil || inventory != nil {
				t.Fatal("incomplete or reordered guard objects were accepted")
			}
		})
	}
}

func TestGuardReplacementKeepsClassificationAndChecksCapacity(t *testing.T) {
	t.Parallel()
	layout, listings := guardListingFixture(t, true)
	inventory, err := layout.inspect(t.Context(), listings)
	if err != nil {
		t.Fatal(err)
	}
	for _, source := range [][]byte{clearBatch(t), leasedBatch(t)} {
		guarded, err := prepareGuards(t.Context(), &preparedBatch{data: source})
		if err != nil {
			t.Fatal(err)
		}
		if err := inventory.checkReplacement(t.Context(), guarded.batch.data); err != nil {
			t.Fatal(err)
		}
	}
	if len(inventory.cohort) != 1 || len(inventory.addresses6) != 1 || inventory.leases != 1 {
		t.Fatal("checking a replacement changed observed permanent state")
	}
	wrongInterface := bytes.ReplaceAll(leasedBatch(t), []byte(`"lan13"`), []byte(`"lan10"`))
	guarded, err := prepareGuards(t.Context(), &preparedBatch{data: wrongInterface})
	if err != nil {
		t.Fatal(err)
	}
	if err := inventory.checkReplacement(t.Context(), guarded.batch.data); err == nil {
		t.Fatal("guarded replacement admitted a different role's interface")
	}
	var logical guardChanges
	if err := json.Unmarshal(leasedBatch(t), &logical); err != nil {
		t.Fatal(err)
	}
	for index := range logical.Commands {
		command := &logical.Commands[index]
		if command.Add != nil && command.Add.Element.Name == "lease_to6_tcp" {
			command.Add.Element.Name = "lease_to4_tcp"
		}
	}
	v4, err := json.Marshal(logical)
	if err != nil {
		t.Fatal(err)
	}
	v4 = bytes.ReplaceAll(v4, []byte("fdca:1a2b:3::10"), []byte("10.240.3.10"))
	v4 = bytes.ReplaceAll(v4, []byte("fdca:1a2b::10"), []byte("10.240.0.10"))
	guarded, err = prepareGuards(t.Context(), &preparedBatch{data: v4})
	if err != nil {
		t.Fatal(err)
	}
	full := *inventory
	full.addresses4 = make([]netip.Addr, 0, maximumTupleCount)
	for index := range maximumTupleCount {
		// Bounds are fixed below 2^16; these casts only split the synthetic index.
		full.addresses4 = append(full.addresses4, netip.AddrFrom4([4]byte{10, 242, byte(index >> 8), byte(index & 255)}))
	}
	if err := full.checkReplacement(t.Context(), guarded.batch.data); err == nil {
		t.Fatal("replacement exceeded cumulative permanent address capacity")
	}
}

func TestGuardInspectionAndReplacementRespectCancellation(t *testing.T) {
	t.Parallel()
	layout, listings := guardListingFixture(t, false)
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if _, err := layout.inspect(ctx, listings); !errors.Is(err, context.Canceled) {
		t.Fatal("guard inspection discarded cancellation")
	}
	if _, err := (*guardLayout)(nil).inspect(t.Context(), listings); err == nil {
		t.Fatal("guard inspection accepted a missing layout")
	}
	//nolint:staticcheck // Intentionally invalid context tests the rejection boundary.
	if _, err := layout.inspect(nil, listings); err == nil {
		t.Fatal("guard inspection accepted a missing context")
	}
	inventory, err := layout.inspect(t.Context(), listings)
	if err != nil {
		t.Fatal(err)
	}
	if err := inventory.checkReplacement(ctx, nil); !errors.Is(err, context.Canceled) {
		t.Fatal("guard replacement discarded cancellation")
	}
	if err := (*guardInventory)(nil).checkReplacement(t.Context(), nil); err == nil {
		t.Fatal("guard replacement accepted a missing inventory")
	}
	if err := inventory.checkReplacement(t.Context(), []byte(`{"nftables":[]}`)); err == nil {
		t.Fatal("guard replacement accepted an incomplete transaction")
	}
}

func FuzzGuardInspection(f *testing.F) {
	layout, valid := guardListingFixture(f, true)
	f.Add(valid.inet, valid.netdev)
	f.Add([]byte(`{"nftables":[]}`), []byte(`{"nftables":null}`))
	f.Fuzz(func(t *testing.T, inet, netdev []byte) {
		inventory, err := layout.inspect(t.Context(), guardListings{inet: inet, netdev: netdev})
		if err != nil && inventory != nil {
			t.Fatal("invalid guard listing produced partial inventory")
		}
	})
}
