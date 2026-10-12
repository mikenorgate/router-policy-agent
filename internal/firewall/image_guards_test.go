package firewall

import (
	"bytes"
	"context"
	"errors"
	"os"
	"testing"

	"github.com/mikenorgate/router-policy-agent/internal/policy"
)

func TestRenderImageGuardsUsesTheRuntimeLayout(t *testing.T) {
	t.Parallel()
	data, err := os.ReadFile("../../examples/baseline.json")
	if err != nil {
		t.Fatal(err)
	}
	baseline, err := policy.DecodeBaseline(data)
	if err != nil {
		t.Fatal(err)
	}
	layout, err := newGuardLayout(baseline)
	if err != nil {
		t.Fatal(err)
	}
	expected, err := layout.program(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	actual, err := RenderImageGuards(t.Context(), data)
	if err != nil || !bytes.Equal(actual, expected) {
		t.Fatal("image output differs from the runtime-owned guard layout")
	}
	if bytes.Contains(actual, []byte("flush ruleset")) || !bytes.Contains(actual, []byte("table netdev ")) {
		t.Fatal("image output is not the additive early/late/final guard program")
	}
}

func TestRenderImageGuardsRejectsInvalidInputsAndCancellation(t *testing.T) {
	t.Parallel()
	data, err := os.ReadFile("../../examples/baseline.json")
	if err != nil {
		t.Fatal(err)
	}
	for _, invalid := range [][]byte{nil, []byte("{}"), []byte("null"), bytes.Repeat([]byte(" "), 2*1024*1024+1)} {
		if output, err := RenderImageGuards(t.Context(), invalid); err == nil || output != nil {
			t.Fatal("invalid baseline produced guard output")
		}
	}
	var missing context.Context
	if output, err := RenderImageGuards(missing, data); err == nil || output != nil {
		t.Fatal("missing context accepted")
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if output, err := RenderImageGuards(ctx, data); !errors.Is(err, context.Canceled) || output != nil {
		t.Fatal("cancelled render produced output")
	}
}
