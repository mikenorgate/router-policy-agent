package firewall

import (
	"fmt"
	"strings"
)

const guardListenerChain = "stamp_listener"

func guardStampChain(tag, verdict string) string {
	return "stamp_" + strings.TrimPrefix(tag, "0x") + "_" + verdict
}

// Linux 6.12 cannot OR two variable registers. Each set router-owned bit adds
// one fixed restore operation to the call stack before the listener is copied.
// Eight bits require at most eight nested jumps, below nft's stack limit even
// with the permit and tag chains. No caller chooses this bounded graph.
func guardStampProgram() []string {
	lines := []string{}
	for index := range 8 {
		bit := uint64(1) << (16 + index)
		next := guardStampBitChain(index + 1)
		lines = append(lines, "chain "+guardStampBitChain(index)+" {",
			fmt.Sprintf("meta mark & 0x%08x == 0 goto %s", bit, next),
			"jump "+next, fmt.Sprintf("meta mark set meta mark | 0x%08x return", bit), "}")
	}
	lines = append(lines, "chain "+guardStampBitChain(8)+" {", "meta mark set ct original proto-dst return", "}")
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
	for index := range 8 {
		bit := uint64(1) << (16 + index)
		name, next := guardStampBitChain(index), guardStampBitChain(index+1)
		schema.chains[name] = guardStampHeader(name)
		schema.rules[name] = [][]any{
			{guardMatch(guardBinary("&", guardMeta("mark"), bit), uint64(0)),
				map[string]any{"goto": map[string]any{"target": next}}},
			{map[string]any{"jump": map[string]any{"target": next}}},
			{guardMark(guardBinary("|", guardMeta("mark"), bit)), map[string]any{"return": nil}},
		}
	}
	leaf := guardStampBitChain(8)
	schema.chains[leaf] = guardStampHeader(leaf)
	schema.rules[leaf] = [][]any{{guardMark(guardListener()), map[string]any{"return": nil}}}
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

func guardStampBitChain(index int) string {
	if index == 0 {
		return guardListenerChain
	}
	return fmt.Sprintf("stamp_listener_%d", index)
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
