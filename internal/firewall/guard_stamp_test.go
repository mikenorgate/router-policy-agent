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

func TestGuardStampUsesBoundedBitDispatch(t *testing.T) {
	t.Parallel()
	program := strings.Join(guardStampProgram(), "\n")
	schema := &guardTableSchema{chains: map[string]map[string]any{}, rules: map[string][][]any{}}
	schema.addStampChains()
	if len(schema.chains) != 21 {
		t.Fatal("fixed stamping graph does not contain exactly nine bit chains and twelve direction chains")
	}
	for index := range 8 {
		bit := uint64(1) << (16 + index)
		next := guardStampBitChain(index + 1)
		want := fmt.Sprintf("chain %s {\nmeta mark & 0x%08x == 0 goto %s\njump %s\n"+
			"meta mark set meta mark | 0x%08x return\n}", guardStampBitChain(index), bit, next, next, bit)
		if strings.Count(program, want) != 1 || len(schema.rules[guardStampBitChain(index)]) != 3 {
			t.Fatalf("preserved bit %08x does not have one bounded restore branch", bit)
		}
	}
	if !strings.Contains(program, "chain stamp_listener_8 {\nmeta mark set ct original proto-dst return\n}") ||
		len(schema.rules[guardStampBitChain(8)]) != 1 {
		t.Fatal("listener copy does not terminate the eight-bit dispatch")
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
