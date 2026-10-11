package firewall

import (
	"bytes"
	"fmt"
	"strings"
	"testing"
)

func TestGuardStampAvoidsVariableBitwiseOperands(t *testing.T) {
	t.Parallel()
	_, _, baseline, _ := renderFixture(t)
	layout, err := newGuardLayout(baseline)
	if err != nil {
		t.Fatal(err)
	}
	program, err := layout.program(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(program, []byte("| ct original proto-dst")) {
		t.Fatal("guard requires variable bitwise operands unsupported by Linux 6.12")
	}
}

func TestGuardStampCoversEveryPreservedByte(t *testing.T) {
	t.Parallel()
	program := strings.Join(guardStampProgram(), "\n")
	schema := &guardTableSchema{chains: map[string]map[string]any{}, rules: map[string][][]any{}}
	schema.addStampChains()
	if len(schema.rules[guardListenerChain]) != 256 || len(schema.chains) != 13 {
		t.Fatal("fixed stamping graph does not cover exactly eight preserved bits and six direction tags")
	}
	for value := uint64(0); value < 256; value++ {
		keep := value << 16
		want := fmt.Sprintf("meta mark & 0x00ff0000 == 0x%08x meta mark set ct original proto-dst "+
			"meta mark set meta mark | 0x%08x return", keep, keep)
		if strings.Count(program, want) != 1 {
			t.Fatalf("preserved byte %02x is not restored exactly once", value)
		}
	}
	for _, tag := range []string{fromOriginalTag, fromReplyTag, toOriginalTag, toReplyTag,
		translatedOriginalTag, translatedReplyTag} {
		for _, verdict := range []string{"return", "accept"} {
			name := guardStampChain(tag, verdict)
			if len(schema.rules[name]) != 2 || !strings.Contains(program,
				"chain "+name+" {\njump stamp_listener\nmeta mark set meta mark | "+tag+" "+verdict+"\n}") {
				t.Fatalf("fixed stamp %s lost its tail-call verdict", name)
			}
		}
	}
}
