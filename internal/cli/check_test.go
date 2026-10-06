package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"strings"
	"testing"

	"github.com/mikenorgate/router-policy-agent/internal/policy"
)

func exampleArgs() []string {
	return []string{"-baseline", "../../examples/baseline.json", "-directory", "../../examples/directory.json",
		"-bindings", "../../examples/bindings.json", "-at", "2026-01-01T12:00:00Z"}
}

func TestRunCheckExamples(t *testing.T) {
	t.Parallel()
	var out, diagnostics bytes.Buffer
	code := RunCheck(t.Context(), exampleArgs(), CheckIO{Out: &out, Err: &diagnostics})
	if code != 0 || diagnostics.Len() != 0 {
		t.Fatalf("exit %d: %s", code, &diagnostics)
	}
	var candidate policy.Candidate
	if err := json.Unmarshal(out.Bytes(), &candidate); err != nil {
		t.Fatal(err)
	}
	if len(candidate.Grants) != 1 || len(candidate.Denials) != 0 || candidate.Grants[0].Port != 6053 {
		t.Fatalf("wrong example result: %+v", candidate)
	}
}

func TestRunCheckUsage(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name   string
		args   []string
		code   int
		output string
	}{
		{name: "help", args: []string{"-help"}, code: 0, output: "Compile shadow decisions only"},
		{name: "version", args: []string{"-version"}, code: 0, output: Version},
		{name: "missing flags", args: []string{}, code: 2},
		{name: "unknown flag", args: []string{"-unknown"}, code: 2},
		{name: "positional", args: []string{"unexpected"}, code: 2},
		{name: "bad time", args: append(exampleArgs(), "-at", "yesterday"), code: 2},
		{name: "non UTC", args: append(exampleArgs(), "-at", "2026-01-01T12:00:00+00:00"), code: 2},
		{name: "bad file", args: append(exampleArgs(), "-bindings", "does-not-exist.json"), code: 1},
		{name: "wrong schema", args: append(exampleArgs(), "-bindings", "../../examples/directory.json"), code: 1},
		{name: "bad ledger", args: append(exampleArgs(), "-ledger", "../../examples/directory.json"), code: 1},
		{name: "directory not regular", args: append(exampleArgs(), "-baseline", "../../examples"), code: 1},
		{name: "stale input", args: append(exampleArgs(), "-at", "2026-01-01T12:01:30Z"), code: 1},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			var out, diagnostics bytes.Buffer
			code := RunCheck(t.Context(), test.args, CheckIO{Out: &out, Err: &diagnostics})
			if code != test.code || test.output != "" && !strings.Contains(out.String(), test.output) {
				t.Fatalf("code %d; stdout=%s stderr=%s", code, &out, &diagnostics)
			}
			if test.code != 0 && out.Len() != 0 {
				t.Fatal("diagnostic output corrupted stdout")
			}
		})
	}
}

type failedWriter struct{}

func (failedWriter) Write([]byte) (int, error) { return 0, errors.New("test output failure") }

func TestRunCheckCancellationAndOutputFailure(t *testing.T) {
	t.Parallel()
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if RunCheck(ctx, exampleArgs(), CheckIO{Out: io.Discard, Err: io.Discard}) != 1 {
		t.Fatal("cancel ignored")
	}
	for _, args := range [][]string{exampleArgs(), {"-help"}, {"-version"}} {
		if RunCheck(t.Context(), args, CheckIO{Out: failedWriter{}, Err: io.Discard}) != 1 {
			t.Fatal("output failure ignored")
		}
	}
}
