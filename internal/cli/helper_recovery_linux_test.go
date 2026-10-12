package cli

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"testing"
)

func TestHelperRecoveryIsSeparateBoundedAndDenialOnly(t *testing.T) {
	t.Parallel()
	for _, test := range []struct {
		name  string
		args  []string
		fail  bool
		code  int
		calls int
	}{
		{name: "restore", args: []string{"-config-directory", "/synthetic/config", "-restore-deny-state"}, calls: 1},
		{name: "restore failure", args: []string{"-config-directory", "/synthetic/config", "-restore-deny-state"}, fail: true, code: 1, calls: 1},
		{name: "missing directory", args: []string{"-restore-deny-state"}, code: 2},
		{name: "initialization forbidden", args: []string{"-config-directory", "/synthetic/config", "-restore-deny-state", "-initialize-state"}, code: 2},
		{name: "bindings forbidden", args: []string{"-config-directory", "/synthetic/config", "-restore-deny-state", "-binding-directory", "/synthetic/bindings"}, code: 2},
		{name: "render forbidden", args: []string{"-restore-deny-state", "-render-image-guards", "-baseline", "../../examples/baseline.json"}, code: 2},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			var output, diagnostics bytes.Buffer
			calls := 0
			operations := helperOperations{
				serve:      func(context.Context, string, string) error { t.Fatal("recovery started runtime"); return nil },
				initialize: func(context.Context, string) error { t.Fatal("recovery initialized state"); return nil },
				recoverOwned: func(ctx context.Context, path string) error {
					calls++
					if _, ok := ctx.Deadline(); !ok || path != "/synthetic/config" {
						t.Fatal("recovery lost bounded context or checked path")
					}
					if test.fail {
						return errors.New("synthetic-private-diagnostic")
					}
					return nil
				},
			}
			code := runHelperOperations(t.Context(), test.args, CheckIO{Out: &output, Err: &diagnostics}, operations)
			if code != test.code || calls != test.calls {
				t.Fatalf("code=%d calls=%d", code, calls)
			}
			if strings.Contains(diagnostics.String(), "synthetic-private-diagnostic") {
				t.Fatal("recovery disclosed private failure")
			}
			if code == 0 && !strings.Contains(output.String(), `"permit_state":"sealed"`) {
				t.Fatal("recovery did not report its denial scope")
			}
		})
	}
}
