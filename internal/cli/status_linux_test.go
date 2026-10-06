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

	"github.com/mikenorgate/router-policy-agent/internal/ipc"
)

func statusFixture() ipc.Report {
	return ipc.Report{SchemaVersion: 1, Mode: "enforce", HelperState: "ready", PermitState: "sealed",
		BaselineHash: strings.Repeat("a", 64), BaselineGeneration: "synthetic-v1", ClockState: "usable",
		FloorState: "unverified", Rules: []ipc.RuleReference{}, DenialCodes: []string{}}
}

func TestRunStatusUsesOnlyItsReadOperation(t *testing.T) {
	t.Parallel()
	var out, diagnostics bytes.Buffer
	var calls int
	read := func(ctx context.Context, options ipc.ClientOptions) (ipc.Report, error) {
		calls++
		if ctx != t.Context() || options.Socket != "/synthetic/status.sock" || options.ServerUID != 1234 ||
			options.Timeout != 3*time.Second {
			t.Fatal("operator arguments or context were not preserved")
		}
		return statusFixture(), nil
	}
	code := runStatus(
		t.Context(),
		[]string{"-socket", "/synthetic/status.sock", "-server-uid", "1234", "-timeout", "3s"},
		CheckIO{Out: &out, Err: &diagnostics},
		read,
	)
	if code != 0 || diagnostics.Len() != 0 || calls != 1 {
		t.Fatal("status did not make exactly one read")
	}
	var report ipc.Report
	if err := json.Unmarshal(out.Bytes(), &report); err != nil || ipc.ValidateReport(report) != nil {
		t.Fatal("status stdout was not a valid report")
	}
}

func TestRunStatusUsageAndRedaction(t *testing.T) {
	t.Parallel()
	for _, test := range []struct {
		name, output string
		args         []string
		code, calls  int
		badReport    bool
	}{
		{name: "help", args: []string{"-help"}, output: "Read bounded helper status", code: 0},
		{name: "version", args: []string{"-version"}, output: Version, code: 0},
		{name: "missing socket", code: 2},
		{name: "unknown flag", args: []string{"-unknown", "synthetic-secret"}, code: 2},
		{name: "positionals", args: []string{"unexpected"}, code: 2},
		{name: "relative socket", args: []string{"-socket", "status.sock"}, code: 2},
		{name: "unclean socket", args: []string{"-socket", "/synthetic/../status.sock"}, code: 2},
		{name: "uid overflow", args: []string{"-socket", "/synthetic/status.sock", "-server-uid", "4294967296"}, code: 2},
		{name: "zero timeout", args: []string{"-socket", "/synthetic/status.sock", "-timeout", "0s"}, code: 2},
		{name: "excess timeout", args: []string{"-socket", "/synthetic/status.sock", "-timeout", "11s"}, code: 2},
		{name: "read failure redacted", args: []string{"-socket", "/synthetic/status.sock"}, code: 1, calls: 1},
		{
			name: "invalid report redacted", args: []string{"-socket", "/synthetic/status.sock"},
			code: 1, calls: 1, badReport: true,
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			var out, diagnostics bytes.Buffer
			var calls int
			read := func(context.Context, ipc.ClientOptions) (ipc.Report, error) {
				calls++
				if test.badReport {
					return ipc.Report{}, nil
				}
				return ipc.Report{}, errors.New("synthetic-secret in private backend diagnostic")
			}
			code := runStatus(
				t.Context(),
				test.args,
				CheckIO{Out: &out, Err: &diagnostics},
				read,
			)
			if code != test.code || calls != test.calls || test.output != "" && !strings.Contains(out.String(), test.output) {
				t.Fatal("unexpected status command outcome")
			}
			if strings.Contains(diagnostics.String(), "synthetic-secret") || test.code != 0 && out.Len() != 0 {
				t.Fatal("raw private diagnostics escaped or corrupted stdout")
			}
		})
	}
}

func TestRunStatusCancellationAndOutputFailure(t *testing.T) {
	t.Parallel()
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	read := func(ctx context.Context, _ ipc.ClientOptions) (ipc.Report, error) { return statusFixture(), ctx.Err() }
	if runStatus(
		ctx,
		[]string{"-socket", "/synthetic/status.sock"},
		CheckIO{Out: io.Discard, Err: io.Discard},
		read,
	) != 1 {
		t.Fatal("canceled status succeeded")
	}
	for _, args := range [][]string{{"-help"}, {"-version"}, {"-socket", "/synthetic/status.sock"}} {
		if runStatus(
			t.Context(),
			args,
			CheckIO{Out: failedWriter{}, Err: io.Discard},
			read,
		) != 1 {
			t.Fatal("failed stdout ignored")
		}
	}
	if runStatus(
		t.Context(),
		[]string{},
		CheckIO{Out: io.Discard, Err: failedWriter{}},
		read,
	) != 1 {
		t.Fatal("failed diagnostic write ignored")
	}
	var missingContext context.Context
	for _, ctx := range []context.Context{missingContext, t.Context()} {
		if runStatus(
			ctx,
			[]string{},
			CheckIO{},
			read,
		) != 2 {
			t.Fatal("invalid command dependencies accepted")
		}
	}
	if runStatus(
		t.Context(),
		[]string{},
		CheckIO{Out: io.Discard, Err: io.Discard},
		nil,
	) != 2 {
		t.Fatal("missing status reader accepted")
	}
	if RunStatus(t.Context(), []string{"-socket", "/synthetic/nonexistent.sock"},
		CheckIO{Out: io.Discard, Err: io.Discard}) != 1 {
		t.Fatal("actual client ignored unavailable socket")
	}
}
