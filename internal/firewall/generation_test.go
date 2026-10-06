package firewall

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"strings"
	"testing"
)

func writerGenerationFixture() writerGeneration {
	floor := sha256.Sum256([]byte("synthetic-protected-floor"))
	mapping := sha256.Sum256([]byte("synthetic-translator-mappings"))
	return writerGeneration{
		SchemaVersion: 1, Sequence: 1, FloorHash: hex.EncodeToString(floor[:]),
		MappingHash: hex.EncodeToString(mapping[:]), Ready: true,
	}
}

func TestWriterGenerationStrictSchemaAndExactVector(t *testing.T) {
	t.Parallel()
	expected := writerGenerationFixture()
	valid, err := json.Marshal(expected)
	if err != nil {
		t.Fatal(err)
	}
	actual, err := decodeWriterGeneration(valid)
	if err != nil || actual != expected || actual.check(expected) != nil {
		t.Fatal("valid complete coordination metadata was rejected")
	}
	for _, name := range []string{"schema", "sequence", "floor", "mapping", "closed", "closed expectation"} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			changed, want := expected, expected
			switch name {
			case "schema":
				changed.SchemaVersion = 2
			case "sequence":
				changed.Sequence++
			case "floor":
				changed.FloorHash = changed.MappingHash
			case "mapping":
				changed.MappingHash = changed.FloorHash
			case "closed":
				changed.Ready = false
			case "closed expectation":
				want.Ready = false
			}
			if changed.check(want) == nil {
				t.Fatal("a closed or different coordination generation matched")
			}
		})
	}
	for _, test := range []struct{ name, data string }{
		{name: "zero sequence", data: strings.Replace(string(valid), `"sequence":1`, `"sequence":0`, 1)},
		{name: "negative sequence", data: strings.Replace(string(valid), `"sequence":1`, `"sequence":-1`, 1)},
		{name: "overflow sequence", data: strings.Replace(string(valid), `"sequence":1`, `"sequence":18446744073709551616`, 1)},
		{name: "null ready", data: strings.Replace(string(valid), `"ready":true`, `"ready":null`, 1)},
		{name: "numeric ready", data: strings.Replace(string(valid), `"ready":true`, `"ready":1`, 1)},
		{name: "missing ready", data: strings.Replace(string(valid), `,"ready":true`, "", 1)},
		{name: "unknown field", data: `{"commands":[],` + string(valid)[1:]},
		{name: "duplicate field", data: `{"sequence":2,` + string(valid)[1:]},
		{name: "case folded field", data: strings.Replace(string(valid), `"floor_hash"`, `"Floor_Hash"`, 1)},
		{name: "short hash", data: strings.Replace(string(valid), expected.FloorHash, "abcd", 1)},
		{name: "nonhex hash", data: strings.Replace(string(valid), expected.FloorHash, strings.Repeat("x", 64), 1)},
		{name: "uppercase hash", data: strings.Replace(string(valid), expected.FloorHash, strings.ToUpper(expected.FloorHash), 1)},
		{name: "trailing program", data: string(valid) + `{}`},
		{name: "oversized metadata", data: string(valid) + strings.Repeat(" ", maximumGenerationSize)},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			if test.data == string(valid) {
				t.Fatal("rejection fixture did not change its input")
			}
			if result, err := decodeWriterGeneration([]byte(test.data)); err == nil || result != (writerGeneration{}) {
				t.Fatal("invalid metadata produced a partial or successful generation")
			}
		})
	}
}

func FuzzWriterGeneration(f *testing.F) {
	valid, err := json.Marshal(writerGenerationFixture())
	if err != nil {
		f.Fatal(err)
	}
	f.Add(valid)
	f.Add([]byte(`{"schema_version":1,"ready":false}`))
	f.Fuzz(func(t *testing.T, data []byte) {
		value, err := decodeWriterGeneration(data)
		if err != nil {
			if value != (writerGeneration{}) {
				t.Fatal("invalid input produced partial coordination state")
			}
			return
		}
		encoded, err := json.Marshal(value)
		if err != nil {
			t.Fatal(err)
		}
		roundTrip, err := decodeWriterGeneration(encoded)
		if err != nil || value != roundTrip {
			t.Fatal("accepted coordination state did not round-trip")
		}
		if (value.check(value) == nil) != value.Ready {
			t.Fatal("closed metadata was treated as a ready expectation")
		}
	})
}
