package strictjson_test

import (
	"strings"
	"testing"

	"github.com/mikenorgate/router-policy-agent/internal/strictjson"
)

func TestDecode(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name  string
		input string
		valid bool
	}{
		{name: "valid", input: `{"value":1}`, valid: true},
		{name: "duplicate", input: `{"value":1,"value":2}`},
		{name: "escaped duplicate", input: `{"value":1,"v\u0061lue":2}`},
		{name: "nested duplicate", input: `{"value":{"a":1,"a":2}}`},
		{name: "unknown field", input: `{"extra":1}`},
		{name: "trailing value", input: `{"value":1} {}`},
		{name: "wrong type", input: `{"value":"1"}`},
		{name: "truncated", input: `{"value":`},
		{name: "invalid utf8", input: "{\"value\":\"\xff\"}"},
		{name: "excessive nesting", input: strings.Repeat("[", 40) + "0" + strings.Repeat("]", 40)},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			var value struct {
				Value int `json:"value"`
			}
			err := strictjson.Decode([]byte(test.input), &value, 4096)
			if (err == nil) != test.valid {
				t.Fatalf("valid=%v, error=%v", test.valid, err)
			}
		})
	}
}

func TestObject(t *testing.T) {
	t.Parallel()
	for _, input := range []string{
		`null`, `[]`, `{}`, `{"value":null}`, `{"Value":1}`, `{"value":1,"other":0}`,
	} {
		t.Run(input, func(t *testing.T) {
			t.Parallel()
			if err := strictjson.Object([]byte(input), []string{"value"}, nil, 4096); err == nil {
				t.Fatal("invalid exact object accepted")
			}
		})
	}
	if err := strictjson.Object([]byte(`{"value":1}`), []string{"value"}, nil, 4096); err != nil {
		t.Fatal(err)
	}
}

func FuzzDecode(f *testing.F) {
	f.Add([]byte(`{"value":1}`))
	f.Add([]byte(`{"value":1,"value":2}`))
	f.Fuzz(func(_ *testing.T, data []byte) {
		var value struct {
			Value int `json:"value"`
		}
		// Arbitrary input is expected to be rejected. This robustness property
		// checks that bounded parsing does not panic or hang.
		if err := strictjson.Decode(data, &value, 16384); err != nil {
			return
		}
	})
}
