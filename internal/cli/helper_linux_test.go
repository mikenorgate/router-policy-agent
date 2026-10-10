package cli

import (
	"bytes"
	"context"
	"errors"
	"io"
	"strings"
	"testing"
)

func TestRunHelperArgumentsAndRedaction(t *testing.T) {
	t.Parallel()
	for _, test := range []struct {
		name, output            string
		args                    []string
		code, serve, initialize int
	}{
		{name: "help", args: []string{"-help"}, output: "Run the checked root helper", code: 0},
		{name: "version", args: []string{"-version"}, output: Version, code: 0},
		{name: "missing directories", code: 2},
		{name: "missing bindings", args: []string{"-config-directory", "/synthetic/config"}, code: 2},
		{name: "root directory", args: []string{"-config-directory", "/", "-initialize-state"}, code: 2},
		{name: "relative directory", args: []string{"-config-directory", "config", "-initialize-state"}, code: 2},
		{name: "unclean directory", args: []string{"-config-directory", "/synthetic/../config", "-initialize-state"}, code: 2},
		{name: "initialization with bindings", args: []string{"-config-directory", "/synthetic/config", "-binding-directory", "/synthetic/bindings", "-initialize-state"}, code: 2},
		{name: "unknown flag", args: []string{"-token", "synthetic-private-value"}, code: 2},
		{name: "positional argument", args: []string{"synthetic-private-value"}, code: 2},
		{name: "runtime failure", args: []string{"-config-directory", "/synthetic/config", "-binding-directory", "/synthetic/bindings"}, code: 1, serve: 1},
		{name: "initialization failure", args: []string{"-config-directory", "/synthetic/config", "-initialize-state"}, code: 1, initialize: 1},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			var out, diagnostics bytes.Buffer
			var served, initialized int
			serve := func(ctx context.Context, directory, bindings string) error {
				served++
				if ctx != t.Context() || directory != "/synthetic/config" || bindings != "/synthetic/bindings" {
					t.Error("helper changed the runtime context or paths")
				}
				return errors.New("synthetic-private-value")
			}
			initialize := func(ctx context.Context, directory string) error {
				initialized++
				if _, ok := ctx.Deadline(); !ok || directory != "/synthetic/config" {
					t.Error("initialization has no deadline or changed its path")
				}
				return errors.New("synthetic-private-value")
			}
			code := runHelper(t.Context(), test.args, CheckIO{Out: &out, Err: &diagnostics}, serve, initialize)
			if code != test.code || served != test.serve || initialized != test.initialize ||
				test.output != "" && !strings.Contains(out.String(), test.output) {
				t.Fatal("unexpected helper outcome")
			}
			if strings.Contains(diagnostics.String(), "synthetic-private-value") || code != 0 && out.Len() != 0 {
				t.Fatal("helper exposed upstream diagnostics or wrote them to stdout")
			}
		})
	}
}

func TestRunHelperCancellationAndInitialization(t *testing.T) {
	t.Parallel()
	args := []string{"-config-directory", "/synthetic/config", "-binding-directory", "/synthetic/bindings"}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	serve := func(ctx context.Context, _, _ string) error { return ctx.Err() }
	initialize := func(context.Context, string) error { return nil }
	streams := CheckIO{Out: io.Discard, Err: io.Discard}
	if runHelper(ctx, args, streams, serve, initialize) != 0 {
		t.Fatal("orderly shutdown failed")
	}
	serve = func(context.Context, string, string) error { return context.Canceled }
	if runHelper(t.Context(), args, streams, serve, initialize) != 1 {
		t.Fatal("internal cancellation hid a runtime failure")
	}
	if runHelper(t.Context(), []string{"-config-directory", "/synthetic/config", "-initialize-state"},
		streams, serve, initialize) != 0 {
		t.Fatal("explicit initialization failed")
	}
	for _, args := range [][]string{{"-help"}, {"-version"}} {
		if runHelper(t.Context(), args, CheckIO{Out: failedWriter{}, Err: io.Discard}, serve, initialize) != 1 {
			t.Fatal("failed stdout ignored")
		}
	}
	if runHelper(t.Context(), nil, CheckIO{Out: io.Discard, Err: failedWriter{}}, serve, initialize) != 1 {
		t.Fatal("failed diagnostic output ignored")
	}
	var missingContext context.Context
	if runHelper(missingContext, args, streams, serve, initialize) != 2 ||
		runHelper(t.Context(), args, CheckIO{}, serve, initialize) != 2 ||
		runHelper(t.Context(), args, streams, nil, initialize) != 2 ||
		runHelper(t.Context(), args, streams, serve, nil) != 2 {
		t.Fatal("missing helper dependency accepted")
	}
	if RunHelper(t.Context(), args, streams) != 1 {
		t.Fatal("actual helper accepted absent configuration")
	}
}
