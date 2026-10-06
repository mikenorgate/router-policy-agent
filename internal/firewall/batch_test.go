package firewall

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
)

func clearBatch(t testing.TB) []byte {
	t.Helper()
	commands := make([]any, 0, len(grantSets))
	for _, name := range grantSets {
		commands = append(commands, map[string]any{"flush": map[string]any{"set": objectReference{
			Family: "inet", Table: ownedTable, Name: name,
		}}})
	}
	data, err := json.Marshal(map[string]any{"nftables": commands})
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func leasedBatch(t testing.TB) []byte {
	t.Helper()
	var batch struct {
		Commands []any `json:"nftables"`
	}
	if err := json.Unmarshal(clearBatch(t), &batch); err != nil {
		t.Fatal(err)
	}
	cohort := map[string]any{"add": map[string]any{"element": map[string]any{
		"family": "inet", "table": ownedTable, "name": cohortSet, "elem": []string{"02:00:00:00:00:01"},
	}}}
	grant := map[string]any{"add": map[string]any{"element": map[string]any{
		"family": "inet", "table": ownedTable, "name": "lease_to6_tcp", "elem": []any{map[string]any{
			"elem": map[string]any{"timeout": 2, "val": map[string]any{"concat": []any{
				"lan13", "02:00:00:00:00:01", "fdca:1a2b:3::10", "fdca:1a2b::10", 6053,
			}}},
		}},
	}}}
	batch.Commands = append(batch.Commands, cohort, grant)
	data, err := json.Marshal(batch)
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func TestBatchAuthority(t *testing.T) {
	t.Parallel()
	valid := string(leasedBatch(t))
	cases := []struct {
		name string
		raw  string
	}{
		{name: "other table", raw: strings.ReplaceAll(valid, ownedTable, "baseline")},
		{name: "other family", raw: strings.ReplaceAll(valid, `"inet"`, `"ip6"`)},
		{name: "cohort flush", raw: strings.Replace(valid, `"lease_from4_tcp"`, `"managed_macs"`, 1)},
		{name: "arbitrary set", raw: strings.ReplaceAll(valid, "lease_to6_tcp", "admin_allow")},
		{name: "delete", raw: strings.Replace(valid, `"flush"`, `"delete"`, 1)},
		{name: "include", raw: `{"nftables":[{"include":"/tmp/program"}]}`},
		{name: "ruleset flush", raw: `{"nftables":[{"flush":{"ruleset":null}}]}`},
		{name: "unknown key", raw: strings.Replace(valid, `"nftables":`, `"commands":`, 1)},
		{name: "duplicate key", raw: `{"nftables":[],` + valid[1:]},
		{name: "partial replacement", raw: `{"nftables":[{"flush":{"set":{
			"family":"inet","table":"router_policy_agent","name":"lease_to6"}}}]}`},
		{name: "long lease", raw: strings.ReplaceAll(valid, `"timeout":2`, `"timeout":89`)},
		{name: "unreserved execution cleanup", raw: strings.ReplaceAll(valid, `"timeout":2`, `"timeout":88`)},
		{name: "zero lease", raw: strings.ReplaceAll(valid, `"timeout":2`, `"timeout":0`)},
		{name: "expired lease", raw: strings.ReplaceAll(valid, `"timeout":2`, `"timeout":-1`)},
		{name: "unknown expiry override", raw: strings.ReplaceAll(valid, `"timeout":2`, `"timeout":2,"expires":90`)},
		{name: "wrong family", raw: strings.ReplaceAll(valid, "fdca:1a2b:3::10", "10.240.3.10")},
		{name: "unsafe interface", raw: strings.ReplaceAll(valid, "lan13", `lan13; flush ruleset`)},
		{name: "subnet", raw: strings.ReplaceAll(valid, "fdca:1a2b::10", "fdca:1a2b::/64")},
		{name: "unknown protocol", raw: strings.ReplaceAll(valid, `_tcp`, `_icmpv6`)},
		{name: "zero port", raw: strings.ReplaceAll(valid, "6053", "0")},
		{name: "range", raw: strings.ReplaceAll(valid, "6053", `{"range":[1,65535]}`)},
		{name: "verdict", raw: strings.ReplaceAll(valid, `"lan13"`, `{"accept":null}`)},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			if err := validateBatch([]byte(test.raw)); err == nil {
				t.Fatal("accepted operation outside the fixed privilege boundary")
			}
		})
	}
	for _, data := range [][]byte{clearBatch(t), leasedBatch(t)} {
		if err := validateBatch(data); err != nil {
			t.Fatalf("rejected valid owned transaction: %v", err)
		}
	}
}

func TestBoundedOutputDrainsWithoutRetainingBeyondQuota(t *testing.T) {
	t.Parallel()
	output := boundedOutput{maximum: 16}
	for range 100 {
		data := bytes.Repeat([]byte{'x'}, 1024)
		n, err := output.Write(data)
		if err != nil || n != len(data) {
			t.Fatalf("output stopped draining: %d, %v", n, err)
		}
	}
	if !output.exceeded || output.buffer.Len() != 16 {
		t.Fatal("output retention exceeded its quota")
	}
}

func TestBatchRejectsDuplicateTupleAndLateCohort(t *testing.T) {
	t.Parallel()
	for _, name := range []string{"duplicate tuple", "cohort after grant", "flush after grant"} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			var batch struct {
				Commands []change `json:"nftables"`
			}
			if err := json.Unmarshal(leasedBatch(t), &batch); err != nil {
				t.Fatal(err)
			}
			switch name {
			case "duplicate tuple":
				grant := &batch.Commands[len(grantSets)+1].Add.Element
				duplicate := bytes.ReplaceAll(grant.Values[0], []byte(`"timeout":2`), []byte(`"timeout":3`))
				grant.Values = append(grant.Values, duplicate)
			case "cohort after grant":
				batch.Commands[len(grantSets)], batch.Commands[len(grantSets)+1] =
					batch.Commands[len(grantSets)+1], batch.Commands[len(grantSets)]
			case "flush after grant":
				batch.Commands = append(batch.Commands, batch.Commands[0])
			}
			data, err := json.Marshal(batch)
			if err != nil {
				t.Fatal(err)
			}
			if err := validateBatch(data); err == nil {
				t.Fatal("accepted a non-atomic or ambiguous owned replacement")
			}
		})
	}
}

func FuzzBatch(f *testing.F) {
	f.Add(clearBatch(f))
	f.Add(leasedBatch(f))
	f.Add([]byte(`{"nftables":[{"flush":{"ruleset":null}}]}`))
	f.Fuzz(func(t *testing.T, data []byte) {
		if err := validateBatch(data); err != nil {
			return
		}
		if len(data) == 0 || len(data) > maximumBatch {
			t.Fatal("accepted batch outside its byte quota")
		}
		var batch struct {
			Commands []change `json:"nftables"`
		}
		if err := json.Unmarshal(data, &batch); err != nil {
			t.Fatal("accepted batch cannot be decoded independently")
		}
		for _, command := range batch.Commands {
			switch {
			case command.Flush != nil && command.Add == nil:
				ref := command.Flush.Set
				if !ownedReference(ref) || !isGrantSet(ref.Name) {
					t.Fatal("accepted flush outside the owned grant sets")
				}
			case command.Add != nil && command.Flush == nil:
				values := command.Add.Element
				ref := objectReference{Family: values.Family, Table: values.Table, Name: values.Name}
				if !ownedReference(ref) || (ref.Name != cohortSet && !isGrantSet(ref.Name)) {
					t.Fatal("accepted addition outside the owned sets")
				}
			default:
				t.Fatal("accepted an operation outside the fixed privilege boundary")
			}
		}
	})
}
