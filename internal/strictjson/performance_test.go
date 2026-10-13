package strictjson_test

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"reflect"
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/mikenorgate/router-policy-agent/internal/strictjson"
)

func TestDecodeStructuralBoundaries(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name  string
		input string
		valid bool
	}{
		{name: "empty object", input: `{}`, valid: true},
		{name: "empty array", input: `[]`, valid: true},
		{name: "scalar at depth limit", input: strings.Repeat("[", 32) + "0" + strings.Repeat("]", 32), valid: true},
		{name: "scalar beyond depth limit", input: strings.Repeat("[", 33) + "0" + strings.Repeat("]", 33)},
		{name: "empty container at depth limit", input: strings.Repeat("[", 33) + strings.Repeat("]", 33), valid: true},
		{name: "empty container beyond depth limit", input: strings.Repeat("[", 34) + strings.Repeat("]", 34)},
		{name: "escaped quote and backslash", input: `{"a\"b\\c":"} [ \" \\"}`, valid: true},
		{name: "object scopes independent", input: `[{"a":1},{"a":2}]`, valid: true},
		{name: "case sensitive keys", input: `{"a":1,"A":2}`, valid: true},
		{name: "escaped slash duplicate", input: `{"a/b":1,"a\/b":2}`},
		{name: "escaped control duplicate", input: `{"a\nb":1,"a\u000ab":2}`},
		{name: "surrogate pair duplicate", input: `{"𝄞":1,"\ud834\udd1e":2}`},
		{name: "unpaired surrogate duplicate", input: `{"�":1,"\ud800":2}`},
		{name: "different unpaired surrogates duplicate", input: `{"\ud800":1,"\udfff":2}`},
		{name: "no unicode normalization", input: `{"é":1,"e\u0301":2}`, valid: true},
		{name: "keys inside string ignored", input: `{"x":"{\"a\":1,\"a\":2}"}`, valid: true},
		{name: "trailing whitespace", input: "{\"a\":1}\n\t\r ", valid: true},
		{name: "trailing scalar", input: `{} 0`},
		{name: "trailing punctuation", input: `{} ,`},
		{name: "invalid escape", input: `{"a":"\x"}`},
		{name: "invalid number", input: `{"a":01}`},
		{name: "float overflow", input: `1e1000`},
		{name: "invalid literal", input: `tru`},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			var value any
			err := strictjson.Decode([]byte(test.input), &value, 4096)
			if (err == nil) != test.valid {
				t.Fatalf("valid=%v, error=%v", test.valid, err)
			}
		})
	}
}

func TestDecodeSizeAndPrivateErrors(t *testing.T) {
	t.Parallel()
	for _, limit := range []int{-1, 0, 1} {
		var value any
		if err := strictjson.Decode([]byte(`{}`), &value, limit); err == nil {
			t.Fatalf("accepted input with limit %d", limit)
		}
	}
	var value any
	if err := strictjson.Decode([]byte(`{}`), &value, 2); err != nil {
		t.Fatal(err)
	}
	if err := strictjson.Decode(nil, &value, 2); err == nil {
		t.Fatal("accepted empty input")
	}
	for _, data := range []string{
		`{"private-marker":1,"private-marker":2}`,
		`{"private-marker":1,`,
	} {
		err := strictjson.Decode([]byte(data), &value, 4096)
		if err == nil || strings.Contains(err.Error(), "private-marker") {
			t.Fatalf("expected a redacted rejection, got %v", err)
		}
	}
	var schema struct {
		Value int `json:"value"`
	}
	err := strictjson.Decode([]byte(`{"private-marker":1}`), &schema, 4096)
	if err == nil || strings.Contains(err.Error(), "private-marker") {
		t.Fatalf("expected redacted unknown-field rejection, got %v", err)
	}
}

func FuzzDecodeMatchesTokenReference(f *testing.F) {
	for _, seed := range []string{
		`{"value":1}`, `{"value":1,"v\u0061lue":2}`, `null`, `true`, `""`, `[]`,
		`[{"a":1},{"a":2}]`, `{"�":1,"\ud800":2}`, `{"a\"b":"\\"}`, `{} 0`,
		strings.Repeat("[", 33) + "0" + strings.Repeat("]", 33),
		strings.Repeat("[", 33) + strings.Repeat("]", 33),
	} {
		f.Add([]byte(seed))
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		const limit = 16 * 1024
		var got, want any
		gotErr := strictjson.Decode(data, &got, limit)
		wantErr := tokenReferenceDecode(data, &want, limit)
		if (gotErr == nil) != (wantErr == nil) {
			t.Fatalf("acceptance differs: optimized=%v, reference=%v", gotErr, wantErr)
		}
		if gotErr == nil && !reflect.DeepEqual(got, want) {
			t.Fatal("decoded values differ")
		}
	})
}

func BenchmarkDecode(b *testing.B) {
	for _, test := range []struct {
		name    string
		objects int
	}{
		{name: "small", objects: 1},
		{name: "large", objects: 8192},
	} {
		b.Run(test.name, func(b *testing.B) {
			// Synthetic firewall-shaped data: nested arrays and many small objects.
			entry := `{"source":"192.0.2.1","destination":"198.51.100.0/24","protocol":"tcp","ports":[1,65535]}`
			data := []byte("[" + strings.Repeat(entry+",", test.objects-1) + entry + "]")
			b.SetBytes(int64(len(data)))
			b.ReportAllocs()
			for b.Loop() {
				var value json.RawMessage
				if err := strictjson.Decode(data, &value, len(data)); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

// tokenReferenceDecode preserves the pre-optimization implementation for
// differential fuzzing. Keep it independent of the optimized structural scan.
func tokenReferenceDecode(data []byte, target any, limit int) error {
	if len(data) == 0 || len(data) > limit || limit <= 0 || !utf8.Valid(data) {
		return errors.New("invalid input")
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.UseNumber()
	if err := tokenReferenceScan(decoder, 0); err != nil {
		return err
	}
	if _, err := decoder.Token(); !errors.Is(err, io.EOF) {
		return errors.New("trailing input")
	}
	decoder = json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	return decoder.Decode(target)
}

func tokenReferenceScan(decoder *json.Decoder, depth int) error {
	if depth > 32 {
		return errors.New("nesting limit exceeded")
	}
	token, err := decoder.Token()
	if err != nil {
		return errors.New("invalid token")
	}
	delimiter, ok := token.(json.Delim)
	if !ok {
		return nil
	}
	switch delimiter {
	case '{':
		seen := map[string]bool{}
		for decoder.More() {
			keyToken, err := decoder.Token()
			if err != nil {
				return errors.New("invalid object key")
			}
			key, ok := keyToken.(string)
			if !ok || seen[key] {
				return errors.New("duplicate or invalid object key")
			}
			seen[key] = true
			if err := tokenReferenceScan(decoder, depth+1); err != nil {
				return err
			}
		}
	case '[':
		for decoder.More() {
			if err := tokenReferenceScan(decoder, depth+1); err != nil {
				return err
			}
		}
	default:
		return errors.New("unexpected delimiter")
	}
	closing, err := decoder.Token()
	if err != nil {
		return errors.New("invalid closing delimiter")
	}
	isObjectEnd := delimiter == '{' && closing == json.Delim('}')
	isArrayEnd := delimiter == '[' && closing == json.Delim(']')
	if !isObjectEnd && !isArrayEnd {
		return errors.New("unmatched delimiter")
	}
	return nil
}
