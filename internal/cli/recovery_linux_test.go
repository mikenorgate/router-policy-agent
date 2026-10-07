package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"strings"
	"testing"
	"time"
)

func TestRunRecoverUsesOnlyItsBoundedDenialOperation(t *testing.T) {
	t.Parallel()
	var out, diagnostics bytes.Buffer
	var calls int
	var operationDone <-chan struct{}
	code := runRecover(
		t.Context(),
		[]string{"-config-directory", "/synthetic/config", "-timeout", "3s"},
		CheckIO{Out: &out, Err: &diagnostics},
		func(ctx context.Context, directory string) error {
			calls++
			operationDone = ctx.Done()
			deadline, exists := ctx.Deadline()
			if directory != "/synthetic/config" || !exists || time.Until(deadline) > 3*time.Second {
				t.Fatal("recovery did not receive its exact path and bounded context")
			}
			return nil
		},
	)
	if code != 0 || calls != 1 || diagnostics.Len() != 0 {
		t.Fatal("recovery did not make exactly one fixed operation")
	}
	select {
	case <-operationDone:
	default:
		t.Fatal("command did not cancel its owned operation context")
	}
	expected := map[string]any{
		"schema_version": float64(1), "scope": "owned_application_grants", "permit_state": "sealed",
		"history_state": "retained", "floor_state": "unverified",
	}
	actual := map[string]any{}
	if err := json.Unmarshal(out.Bytes(), &actual); err != nil || len(actual) != len(expected) {
		t.Fatal("recovery did not produce a bounded credential-free report")
	}
	for key, value := range expected {
		if actual[key] != value {
			t.Fatal("recovery report overstated its verified scope")
		}
	}
}

func TestRunRecoverUsageAndRedaction(t *testing.T) {
	t.Parallel()
	for _, test := range []struct {
		name, output string
		args         []string
		code, calls  int
	}{
		{name: "help", args: []string{"-help"}, output: "Revoke agent-owned", code: 0},
		{name: "version", args: []string{"-version"}, output: Version, code: 0},
		{name: "missing configuration", code: 2},
		{name: "unknown flag", args: []string{"-program", "synthetic-secret"}, code: 2},
		{name: "positionals", args: []string{"synthetic-secret"}, code: 2},
		{name: "version positionals", args: []string{"-version", "synthetic-secret"}, code: 2},
		{name: "relative directory", args: []string{"-config-directory", "relative"}, code: 2},
		{name: "root directory", args: []string{"-config-directory", "/"}, code: 2},
		{name: "unclean directory", args: []string{"-config-directory", "/synthetic/../config"}, code: 2},
		{name: "control character", args: []string{"-config-directory", "/synthetic/\nconfig"}, code: 2},
		{name: "long directory", args: []string{"-config-directory", "/" + strings.Repeat("x", 4096)}, code: 2},
		{name: "zero timeout", args: []string{"-config-directory", "/synthetic/config", "-timeout", "0s"}, code: 2},
		{name: "negative timeout", args: []string{"-config-directory", "/synthetic/config", "-timeout", "-1s"}, code: 2},
		{name: "excess timeout", args: []string{"-config-directory", "/synthetic/config", "-timeout", "11s"}, code: 2},
		{name: "invalid timeout", args: []string{"-timeout", "synthetic-secret"}, code: 2},
		{name: "backend failure", args: []string{"-config-directory", "/synthetic/config"}, code: 1, calls: 1},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			var out, diagnostics bytes.Buffer
			var calls int
			code := runRecover(
				t.Context(),
				test.args,
				CheckIO{Out: &out, Err: &diagnostics},
				func(context.Context, string) error {
					calls++
					return errors.New("synthetic-secret in /private/config and upstream diagnostic")
				},
			)
			if code != test.code || calls != test.calls || test.output != "" && !strings.Contains(out.String(), test.output) {
				t.Fatal("unexpected recovery command outcome")
			}
			if strings.Contains(diagnostics.String(), "synthetic-secret") || test.code != 0 && out.Len() != 0 {
				t.Fatal("raw private input escaped or failure printed a success report")
			}
		})
	}
}

func TestRunRecoverCancellationAndOutputFailure(t *testing.T) {
	t.Parallel()
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	operation := func(context.Context, string) error {
		t.Fatal("canceled command changed router state")
		return nil
	}
	if runRecover(
		ctx,
		[]string{"-config-directory", "/synthetic/config"},
		CheckIO{Out: io.Discard, Err: io.Discard},
		operation,
	) != 1 {
		t.Fatal("pre-canceled recovery succeeded")
	}
	for _, args := range [][]string{{"-help"}, {"-version"}, {"-config-directory", "/synthetic/config"}} {
		if runRecover(
			t.Context(),
			args,
			CheckIO{Out: failedWriter{}, Err: io.Discard},
			func(context.Context, string) error { return nil },
		) != 1 {
			t.Fatal("recovery ignored stdout failure")
		}
	}
	if runRecover(
		t.Context(),
		[]string{},
		CheckIO{Out: io.Discard, Err: failedWriter{}},
		operation,
	) != 1 {
		t.Fatal("recovery ignored diagnostic failure")
	}
	var missingContext context.Context
	if runRecover(
		missingContext,
		[]string{},
		CheckIO{Out: io.Discard, Err: io.Discard},
		operation,
	) != 2 {
		t.Fatal("nil command context accepted")
	}
	for _, streams := range []CheckIO{{}, {Out: io.Discard}, {Err: io.Discard}} {
		if runRecover(
			t.Context(),
			[]string{},
			streams,
			operation,
		) != 2 {
			t.Fatal("missing command streams accepted")
		}
	}
	if runRecover(
		t.Context(),
		[]string{},
		CheckIO{Out: io.Discard, Err: io.Discard},
		nil,
	) != 2 {
		t.Fatal("missing recovery operation accepted")
	}
	if RunRecover(
		t.Context(),
		[]string{"-config-directory", "/synthetic/nonexistent"},
		CheckIO{Out: io.Discard, Err: io.Discard},
	) != 1 {
		t.Fatal("real recovery accepted unavailable private configuration")
	}
}

func TestRunRecoverDoesNotClaimSuccessAfterCallerCancellation(t *testing.T) {
	t.Parallel()
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	var out, diagnostics bytes.Buffer
	code := runRecover(
		ctx,
		[]string{"-config-directory", "/synthetic/config"},
		CheckIO{Out: &out, Err: &diagnostics},
		func(context.Context, string) error {
			cancel()
			return nil
		},
	)
	if code != 1 || out.Len() != 0 || !strings.Contains(diagnostics.String(), "recovery not verified") {
		t.Fatal("canceled recovery reported verified sealing")
	}
}
