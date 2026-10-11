package firewall

import (
	"fmt"
	"strings"
)

const guardListenerChain = "stamp_listener"

func guardStampChain(tag, verdict string) string {
	return "stamp_" + strings.TrimPrefix(tag, "0x") + "_" + verdict
}

// Linux 6.12 cannot OR two variable registers. Dispatch the eight preserved
// mark bits to fixed constants instead: copy the original listener, restore
// those bits, then stamp the fixed direction tag. No caller chooses this graph.
func guardStampProgram() []string {
	lines := []string{"chain " + guardListenerChain + " {"}
	for value := uint64(0); value < 256; value++ {
		keep := value << 16
		lines = append(lines, fmt.Sprintf(
			"meta mark & %s == 0x%08x meta mark set ct original proto-dst "+
				"meta mark set meta mark | 0x%08x return", guardMarkKeep, keep, keep))
	}
	lines = append(lines, "}")
	for _, tag := range guardStampTags() {
		for _, verdict := range []string{"return", "accept"} {
			lines = append(lines, "chain "+guardStampChain(tag.text, verdict)+" {",
				"jump "+guardListenerChain,
				"meta mark set meta mark | "+tag.text+" "+verdict, "}")
		}
	}
	return lines
}

func (schema *guardTableSchema) addStampChains() {
	schema.chains[guardListenerChain] = guardStampHeader(guardListenerChain)
	for value := uint64(0); value < 256; value++ {
		keep := value << 16
		restored := guardBinary("|", guardMeta("mark"), keep)
		if keep == 0 {
			// nft folds the identity OR into a plain mark copy in its listing.
			restored = guardMeta("mark")
		}
		schema.rules[guardListenerChain] = append(schema.rules[guardListenerChain], []any{
			guardMatch(guardBinary("&", guardMeta("mark"), uint64(0x00ff0000)), keep),
			guardMark(guardListener()), guardMark(restored),
			map[string]any{"return": nil},
		})
	}
	for _, tag := range guardStampTags() {
		for _, verdict := range []string{"return", "accept"} {
			name := guardStampChain(tag.text, verdict)
			schema.chains[name] = guardStampHeader(name)
			schema.rules[name] = [][]any{
				{map[string]any{"jump": map[string]any{"target": guardListenerChain}}},
				{guardMark(guardBinary("|", guardMeta("mark"), tag.value)), map[string]any{verdict: nil}},
			}
		}
	}
}

func guardStampHeader(name string) map[string]any {
	return map[string]any{"family": "inet", "table": ownedTable, "name": name}
}

func guardStampGoto(tag, verdict string) any {
	return map[string]any{"goto": map[string]any{"target": guardStampChain(tag, verdict)}}
}

func guardStampTags() []struct {
	text  string
	value uint64
} {
	return []struct {
		text  string
		value uint64
	}{
		{text: fromOriginalTag, value: 0xa1000000}, {text: fromReplyTag, value: 0xa2000000},
		{text: toOriginalTag, value: 0xa3000000}, {text: toReplyTag, value: 0xa4000000},
		{text: translatedOriginalTag, value: 0xc1000000}, {text: translatedReplyTag, value: 0xc2000000},
	}
}
