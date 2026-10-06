package firewall

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"
	"testing"
)

// This is synthetic selected-version output, never a router capture. Handles
// deliberately overlap between table and set namespaces, as the kernel permits.
func listingFixtureObjects() []map[string]any {
	objects := []map[string]any{
		{"metainfo": map[string]any{
			"version": "1.1.3", "release_name": "Commodore Bullmoose #4", "json_schema_version": 1,
		}},
		{"table": map[string]any{"family": "inet", "name": ownedTable, "handle": 1}},
		{"set": map[string]any{
			"family": "inet", "table": ownedTable, "name": cohortSet, "handle": 1,
			"type": "ether_addr", "size": 4096, "elem": []any{"02:00:00:00:00:01"},
		}},
	}
	for index, name := range grantSets {
		addressType := "ipv6_addr"
		if ipv4Set(name) {
			addressType = "ipv4_addr"
		}
		objects = append(objects, map[string]any{"set": map[string]any{
			"family": "inet", "table": ownedTable, "name": name, "handle": index + 2,
			"type": []string{"ifname", "ether_addr", addressType, addressType, "inet_service"},
			"size": 16384, "flags": []string{"timeout"}, "timeout": 90,
		}})
	}
	objects[len(objects)-2]["set"] = map[string]any{
		"family": "inet", "table": ownedTable, "name": "lease_to6_tcp", "handle": 8,
		"type": []string{"ifname", "ether_addr", "ipv6_addr", "ipv6_addr", "inet_service"},
		"size": 16384, "flags": []string{"timeout"}, "timeout": 90,
		"elem": []any{map[string]any{"elem": map[string]any{
			"val": map[string]any{"concat": []any{
				"lan13", "02:00:00:00:00:01", "fdca:1a2b:3::10", "fdca:1a2b::10", 6053,
			}}, "timeout": 85, "expires": 84,
		}}},
	}
	return objects
}

func listingFixture(t testing.TB, objects []map[string]any) []byte {
	t.Helper()
	data, err := json.Marshal(map[string]any{"nftables": objects})
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func TestInventoryAcceptsCompleteSelectedSchema(t *testing.T) {
	t.Parallel()
	objects := listingFixtureObjects()
	// The cohort can appear after lease sets; listing order is not authorization.
	objects[2], objects[len(objects)-1] = objects[len(objects)-1], objects[2]
	cohort, ok := objects[len(objects)-1]["set"].(map[string]any)
	if !ok {
		t.Fatal("invalid synthetic cohort fixture")
	}
	cohort["elem"] = []any{"02:00:00:00:00:02", "02:00:00:00:00:01"}
	data := listingFixture(t, objects)
	inventory, err := verifySetInventory(t.Context(), data)
	if err != nil {
		t.Fatal(err)
	}
	expected := []string{"02:00:00:00:00:01", "02:00:00:00:00:02"}
	if inventory.leases != 1 || !slices.Equal(inventory.cohort, expected) {
		t.Fatal("complete inventory lost classification or lease count")
	}
	// Expiry is rounded down to JSON seconds. Zero does not restore or renew it.
	data = bytes.ReplaceAll(data, []byte(`"expires":84`), []byte(`"expires":0`))
	if _, err := verifySetInventory(t.Context(), data); err != nil {
		t.Fatalf("near-expiry observation was rejected: %v", err)
	}
	// A completely empty permit/cohort observation is valid bootstrap structure.
	objects = listingFixtureObjects()
	for _, object := range objects[2:] {
		set, ok := object["set"].(map[string]any)
		if !ok {
			t.Fatal("invalid synthetic set fixture")
		}
		delete(set, "elem")
	}
	if inventory, err := verifySetInventory(t.Context(), listingFixture(t, objects)); err != nil ||
		len(inventory.cohort) != 0 || inventory.leases != 0 {
		t.Fatalf("empty bootstrap structure rejected: %v", err)
	}
}

func TestInventoryRejectsSchemaDriftAndInvalidLeases(t *testing.T) {
	t.Parallel()
	valid := string(listingFixture(t, listingFixtureObjects()))
	cases := []struct {
		name string
		old  string
		new  string
	}{
		{name: "library version", old: `"1.1.3"`, new: `"1.1.4"`},
		{name: "release identity", old: `"Commodore Bullmoose #4"`, new: `"other"`},
		{name: "json schema", old: `"json_schema_version":1`, new: `"json_schema_version":2`},
		{name: "other family", old: `"inet"`, new: `"ip6"`},
		{name: "other table", old: `"router_policy_agent"`, new: `"baseline"`},
		{name: "zero handle", old: `"handle":8`, new: `"handle":0`},
		{name: "duplicate set handle", old: `"handle":8`, new: `"handle":2`},
		{name: "fractional handle", old: `"handle":8`, new: `"handle":8.5`},
		{name: "negative handle", old: `"handle":8`, new: `"handle":-1`},
		{name: "handle overflow", old: `"handle":8`, new: `"handle":18446744073709551616`},
		{name: "case folded key", old: `"handle":8`, new: `"Handle":8`},
		{name: "unknown set", old: `"lease_to6_tcp"`, new: `"baseline_allow"`},
		{name: "lease as map", old: `"set":`, new: `"map":`},
		{name: "cohort timeout", old: `"size":4096`, new: `"size":4096,"timeout":90`},
		{name: "cohort interval", old: `"size":4096`, new: `"size":4096,"flags":["interval"]`},
		{name: "cohort datatype", old: `"type":"ether_addr"`, new: `"type":"ipv4_addr"`},
		{name: "noncanonical identity", old: `"02:00:00:00:00:01"`, new: `"020000000001"`},
		{name: "cohort capacity", old: `"size":4096`, new: `"size":4097`},
		{name: "cohort null", old: `"size":4096`, new: `"size":4096,"elem":null`},
		{name: "cohort duplicate", old: `"elem":["02:00:00:00:00:01"]`,
			new: `"elem":["02:00:00:00:00:01","02:00:00:00:00:01"]`},
		{name: "unclassified lease", old: `"elem":["02:00:00:00:00:01"]`, new: `"elem":[]`},
		{name: "tuple datatype", old: `"inet_service"`, new: `"integer"`},
		{name: "tuple datatype order", old: `"ifname","ether_addr"`, new: `"ether_addr","ifname"`},
		{name: "wrong address datatype", old: `"ipv6_addr"`, new: `"ipv4_addr"`},
		{name: "lease capacity", old: `"size":16384`, new: `"size":1`},
		{name: "default timeout", old: `"timeout":90`, new: `"timeout":91`},
		{name: "missing timeout flag", old: `"flags":["timeout"]`, new: `"flags":[]`},
		{name: "traffic refreshed timeout", old: `"flags":["timeout"]`, new: `"flags":["timeout","dynamic"]`},
		{name: "unknown set policy", old: `"size":16384`, new: `"size":16384,"policy":"memory"`},
		{name: "unbounded element", old: `"timeout":85`, new: `"timeout":90`},
		{name: "negative element expiry", old: `"expires":84`, new: `"expires":-1`},
		{name: "excess element expiry", old: `"expires":84`, new: `"expires":86`},
		{name: "null expiry", old: `"expires":84`, new: `"expires":null`},
		{name: "fractional expiry", old: `"expires":84`, new: `"expires":0.5`},
		{name: "duplicate expiry", old: `"expires":84`, new: `"expires":84,"expires":1`},
		{name: "unknown element field", old: `"expires":84`, new: `"expires":84,"comment":"other"`},
		{name: "invalid tuple peer", old: `"fdca:1a2b::10"`, new: `"::1"`},
		{name: "invalid tuple port", old: `6053`, new: `0`},
		{name: "unknown table flag", old: `"handle":1,"name":"router_policy_agent"`,
			new: `"handle":1,"name":"router_policy_agent","flags":["dormant"]`},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			if !strings.Contains(valid, test.old) {
				t.Fatal("test mutation does not exercise the fixture")
			}
			data := []byte(strings.ReplaceAll(valid, test.old, test.new))
			if inventory, err := verifySetInventory(t.Context(), data); err == nil || inventory != nil {
				t.Fatal("schema drift yielded partial or trusted inventory")
			}
		})
	}
}

func TestReplacementRequiresCurrentOrAtomicClassification(t *testing.T) {
	t.Parallel()
	inventory, err := verifySetInventory(t.Context(), listingFixture(t, listingFixtureObjects()))
	if err != nil {
		t.Fatal(err)
	}
	var batch struct {
		Commands []change `json:"nftables"`
	}
	if err := json.Unmarshal(leasedBatch(t), &batch); err != nil {
		t.Fatal(err)
	}
	batch.Commands = append(batch.Commands[:len(grantSets)], batch.Commands[len(grantSets)+1:]...)
	withoutAppend, err := json.Marshal(batch)
	if err != nil {
		t.Fatal(err)
	}
	if err := inventory.checkReplacement(t.Context(), withoutAppend); err != nil {
		t.Fatalf("existing permanent classification was not retained: %v", err)
	}
	unknown := bytes.ReplaceAll(withoutAppend, []byte("02:00:00:00:00:01"), []byte("02:01:00:00:00:01"))
	if err := inventory.checkReplacement(t.Context(), unknown); err == nil {
		t.Fatal("unclassified replacement identity was accepted")
	}
	atomic := bytes.ReplaceAll(leasedBatch(t), []byte("02:00:00:00:00:01"), []byte("02:01:00:00:00:01"))
	if err := inventory.checkReplacement(t.Context(), atomic); err != nil {
		t.Fatalf("atomic classification and lease append rejected: %v", err)
	}
	if err := inventory.checkReplacement(t.Context(), []byte(`{"nftables":[]}`)); err == nil {
		t.Fatal("replacement checker accepted an incomplete transaction")
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if err := inventory.checkReplacement(ctx, atomic); !errors.Is(err, context.Canceled) {
		t.Fatal("replacement checker discarded cancellation")
	}
	var absent *setInventory
	if err := absent.checkReplacement(t.Context(), atomic); err == nil {
		t.Fatal("replacement accepted missing inventory")
	}
}

func TestInventoryAndReplacementRespectPermanentCapacity(t *testing.T) {
	t.Parallel()
	objects := listingFixtureObjects()
	cohort, ok := objects[2]["set"].(map[string]any)
	if !ok {
		t.Fatal("invalid synthetic cohort fixture")
	}
	identities := make([]any, 0, maximumCohortSize+1)
	for index := range maximumCohortSize {
		identities = append(identities, fmt.Sprintf("02:00:00:00:%02x:%02x", index/256, index%256))
	}
	cohort["elem"] = identities
	inventory, err := verifySetInventory(t.Context(), listingFixture(t, objects))
	if err != nil || len(inventory.cohort) != maximumCohortSize {
		t.Fatalf("full valid permanent cohort rejected: %v", err)
	}
	appendOne := bytes.ReplaceAll(leasedBatch(t), []byte("02:00:00:00:00:01"), []byte("02:01:00:00:00:01"))
	if err := inventory.checkReplacement(t.Context(), appendOne); err == nil {
		t.Fatal("atomic append exceeded existing permanent capacity")
	}
	cohort["elem"] = append(identities, "02:01:00:00:00:01")
	if inventory, err := verifySetInventory(t.Context(), listingFixture(t, objects)); err == nil || inventory != nil {
		t.Fatal("oversized cohort produced a partial inventory")
	}
}

func TestInventoryRejectsIncompleteAndUnexpectedObjects(t *testing.T) {
	t.Parallel()
	for _, name := range []string{"missing set", "duplicate set", "unexpected chain", "swapped header"} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			objects := listingFixtureObjects()
			switch name {
			case "missing set":
				objects = objects[:len(objects)-1]
			case "duplicate set":
				objects[3] = objects[4]
			case "unexpected chain":
				objects[3] = map[string]any{"chain": map[string]any{
					"family": "inet", "table": ownedTable, "name": "allow", "handle": 20,
				}}
			case "swapped header":
				objects[0], objects[1] = objects[1], objects[0]
			}
			if inventory, err := verifySetInventory(t.Context(), listingFixture(t, objects)); err == nil || inventory != nil {
				t.Fatal("unverified objects yielded an inventory")
			}
		})
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	inventory, err := verifySetInventory(ctx, listingFixture(t, listingFixtureObjects()))
	if !errors.Is(err, context.Canceled) || inventory != nil {
		t.Fatal("canceled inspection produced a usable inventory")
	}
	//nolint:staticcheck // Deliberately missing context tests the rejection boundary.
	if inventory, err := verifySetInventory(nil, nil); err == nil || inventory != nil {
		t.Fatal("missing context was accepted")
	}
}

func FuzzInventory(f *testing.F) {
	f.Add(listingFixture(f, listingFixtureObjects()))
	f.Add([]byte(`{"nftables":[]}`))
	f.Fuzz(func(t *testing.T, data []byte) {
		inventory, err := verifySetInventory(t.Context(), data)
		if err != nil {
			if inventory != nil {
				t.Fatal("rejected listing yielded partial classification")
			}
			return
		}
		if inventory == nil {
			t.Fatal("accepted listing did not yield an inventory")
		}
		if len(inventory.cohort) > maximumCohortSize || inventory.leases > maximumTupleCount {
			t.Fatal("accepted inventory exceeded its authority bounds")
		}
		if !slices.IsSorted(inventory.cohort) {
			t.Fatal("accepted inventory was not canonical")
		}
	})
}
