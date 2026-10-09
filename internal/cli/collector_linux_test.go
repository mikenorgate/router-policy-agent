package cli

import (
	"bytes"
	"context"
	"errors"
	"io"
	"strings"
	"testing"

	"github.com/mikenorgate/router-policy-agent/internal/radius"
)

func TestCollectorCommandArgumentsAndRedaction(t *testing.T) {
	t.Parallel()
	for _, test := range []struct {
		name   string
		args   []string
		code   int
		called bool
	}{
		{"help", []string{"-help"}, 0, false}, {"version", []string{"-version"}, 0, false},
		{"missing", []string{}, 2, false}, {"relative", []string{"-config-directory", "private"}, 2, false},
		{"root", []string{"-config-directory", "/"}, 2, false},
		{"enforce flag", []string{"-enforce", "synthetic-private"}, 2, false},
		{"positional", []string{"synthetic-private"}, 2, false},
		{"runtime", []string{"-config-directory", "/synthetic/private"}, 1, true},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			var out, diagnostics bytes.Buffer
			called := false
			collect := func(context.Context, string) (radius.Collection, error) {
				called = true
				return radius.Collection{}, errors.New("synthetic-private upstream payload")
			}
			code := runCollector(t.Context(), test.args, CheckIO{Out: &out, Err: &diagnostics}, collect)
			if code != test.code || called != test.called {
				t.Fatal("unexpected command result")
			}
			if strings.Contains(out.String()+diagnostics.String(), "synthetic-private") {
				t.Fatal("private payload exposed")
			}
		})
	}
}

func TestCollectorCommandCountOnlyOutputAndBrokenWriter(t *testing.T) {
	t.Parallel()
	collect := func(context.Context, string) (radius.Collection, error) {
		return radius.Collection{Generation: "private-generation", Candidates: []radius.IPv4Candidate{{}}, Withheld: 2}, nil
	}
	args := []string{"-config-directory", "/synthetic/private"}
	var out bytes.Buffer
	if runCollector(t.Context(), args, CheckIO{Out: &out, Err: io.Discard}, collect) != 0 {
		t.Fatal("success failed")
	}
	if out.String() != "{\"mode\":\"shadow\",\"complete\":true,\"enforcement_ready\":false,\"candidates\":1,\"withheld\":2}\n" {
		t.Fatal("count-only shadow output changed")
	}
	if runCollector(t.Context(), args, CheckIO{Out: failedWriter{}, Err: io.Discard}, collect) != 1 {
		t.Fatal("broken stdout ignored")
	}
	if runCollector(t.Context(), []string{}, CheckIO{Out: io.Discard, Err: failedWriter{}}, collect) != 1 {
		t.Fatal("broken diagnostics ignored")
	}
	if RunCollector(t.Context(), []string{"-config-directory", "/synthetic/absent"}, CheckIO{Out: io.Discard, Err: io.Discard}) != 1 {
		t.Fatal("actual runtime accepted absent config")
	}
}
