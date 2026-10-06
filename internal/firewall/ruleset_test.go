package firewall

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"
)

// This fixture is independently authored, not exported from a live firewall.
// Its minimal ordering exercises comparison only; it is not a P01-P10 profile.
const reviewedArtifactFixture = `{
 "schema_version":1,
 "objects":[
  {"table":{"family":"inet","name":"reviewed_floor"}},
  {"chain":{"family":"inet","table":"reviewed_floor","name":"input","type":"filter","hook":"input","prio":0,"policy":"drop"}},
  {"chain":{"family":"inet","table":"reviewed_floor","name":"output","type":"filter","hook":"output","prio":0,"policy":"drop"}},
  {"chain":{"family":"inet","table":"reviewed_floor","name":"forward","type":"filter","hook":"forward","prio":0,"policy":"drop"}},
  {"chain":{"family":"inet","table":"reviewed_floor","name":"safety"}},
  {"chain":{"family":"inet","table":"reviewed_floor","name":"stateful"}},
  {"set":{"family":"inet","table":"reviewed_floor","name":"reserved_peers","type":"ipv4_addr","size":16,"flags":["interval"],"elem":["10.240.2.254",{"prefix":{"addr":"10.241.0.0","len":24}}]}},
  {"map":{"family":"inet","table":"reviewed_floor","name":"peer_map","type":"ipv4_addr","map":"ipv6_addr","size":16,"elem":[["10.250.0.20","fdca:1a2b:2::20"]]}},
  {"counter":{"family":"inet","table":"reviewed_floor","name":"flow_hits"}},
  {"rule":{"family":"inet","table":"reviewed_floor","chain":"forward","expr":[{"jump":{"target":"safety"}}]}},
  {"rule":{"family":"inet","table":"reviewed_floor","chain":"forward","expr":[{"jump":{"target":"stateful"}}]}},
  {"rule":{"family":"inet","table":"reviewed_floor","chain":"forward","expr":[{"counter":{}},{"drop":null}]}},
  {"rule":{"family":"inet","table":"reviewed_floor","chain":"safety","expr":[{"match":{"op":"in","left":{"ct":{"key":"state"}},"right":"invalid"}},{"drop":null}]}},
  {"rule":{"family":"inet","table":"reviewed_floor","chain":"safety","expr":[{"match":{"op":"==","left":{"payload":{"protocol":"ip","field":"daddr"}},"right":"@reserved_peers"}},{"drop":null}]}},
  {"rule":{"family":"inet","table":"reviewed_floor","chain":"safety","expr":[{"return":null}]}},
  {"rule":{"family":"inet","table":"reviewed_floor","chain":"stateful","expr":[{"match":{"op":"in","left":{"ct":{"key":"state"}},"right":"established"}},{"counter":"flow_hits"},{"accept":null}]}}
 ]
}`

func reviewedRulesetFixture(t testing.TB) *reviewedRuleset {
	t.Helper()
	contract, err := decodeReviewedRuleset(t.Context(), []byte(reviewedArtifactFixture))
	if err != nil {
		t.Fatal(err)
	}
	return contract
}

func reviewedNativeObjects(t testing.TB) []map[string]any {
	t.Helper()
	var artifact struct {
		Objects []map[string]map[string]any `json:"objects"`
	}
	if err := json.Unmarshal([]byte(reviewedArtifactFixture), &artifact); err != nil {
		t.Fatal(err)
	}
	objects := make([]map[string]any, 0, len(artifact.Objects))
	for index, object := range artifact.Objects {
		for kind, fields := range object {
			fields["handle"] = index + 1
			if kind == "counter" {
				fields["packets"], fields["bytes"] = uint64(18446744073709551615), uint64(18446744073709551614)
			}
			if kind == "rule" {
				expressions, ok := fields["expr"].([]any)
				if !ok {
					t.Fatal("fixture expression array missing")
				}
				for _, raw := range expressions {
					expression, ok := raw.(map[string]any)
					if !ok {
						t.Fatal("fixture statement missing")
					}
					if _, isCounter := expression["counter"].(map[string]any); isCounter {
						expression["counter"] = map[string]any{"packets": 7, "bytes": 512}
					}
				}
			}
			objects = append(objects, map[string]any{kind: fields})
		}
	}
	return objects
}

func fullRulesetFixture(t testing.TB) (*guardLayout, []byte) {
	t.Helper()
	layout, guards := guardListingFixture(t, true)
	var inet, netdev struct {
		Objects []json.RawMessage `json:"nftables"`
	}
	if err := json.Unmarshal(guards.inet, &inet); err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(guards.netdev, &netdev); err != nil {
		t.Fatal(err)
	}
	objects := []json.RawMessage{inet.Objects[0]}
	for _, object := range reviewedNativeObjects(t) {
		encoded, err := json.Marshal(object)
		if err != nil {
			t.Fatal(err)
		}
		objects = append(objects, encoded)
	}
	objects = append(objects, inet.Objects[1:]...)
	objects = append(objects, netdev.Objects[1:]...)
	encoded, err := json.Marshal(struct {
		Objects []json.RawMessage `json:"nftables"`
	}{Objects: objects})
	if err != nil {
		t.Fatal(err)
	}
	return layout, encoded
}

func TestReviewedRulesetMatchesCompleteListing(t *testing.T) {
	t.Parallel()
	contract := reviewedRulesetFixture(t)
	layout, listing := fullRulesetFixture(t)
	observation, err := contract.inspect(t.Context(), layout, listing)
	if err != nil {
		t.Fatal(err)
	}
	if observation.digest != contract.digest || len(observation.digest) != 64 || observation.guards.leases != 1 {
		t.Fatal("complete verification lost program identity or guarded leases")
	}
	// Counter changes and declaration order do not change policy. Rule order,
	// expressions and set/map contents do. No float rounding is used for counts.
	listing = bytes.ReplaceAll(listing, []byte(`18446744073709551615`), []byte(`0`))
	listing = bytes.ReplaceAll(listing, []byte(`18446744073709551614`), []byte(`1`))
	listing = bytes.ReplaceAll(listing, []byte(`"bytes":512,"packets":7`), []byte(`"bytes":1024,"packets":8`))
	elements := []byte(`["10.240.2.254",{"prefix":{"addr":"10.241.0.0","len":24}}]`)
	if !bytes.Contains(listing, elements) {
		t.Fatal("element-order test did not mutate its fixture")
	}
	listing = bytes.ReplaceAll(listing, elements,
		[]byte(`[{"prefix":{"addr":"10.241.0.0","len":24}},"10.240.2.254"]`))
	var value struct {
		Objects []json.RawMessage `json:"nftables"`
	}
	if err := json.Unmarshal(listing, &value); err != nil {
		t.Fatal(err)
	}
	value.Objects[2], value.Objects[3] = value.Objects[3], value.Objects[2]
	data, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	if updated, err := contract.inspect(t.Context(), layout, data); err != nil || updated.digest != observation.digest {
		t.Fatalf("volatile counters or declaration order changed the reviewed program: %v", err)
	}
	// Keep the independently created artifact immutable after decoding.
	artifact := []byte(reviewedArtifactFixture)
	decoded, err := decodeReviewedRuleset(t.Context(), artifact)
	if err != nil {
		t.Fatal(err)
	}
	clear(artifact)
	if _, err := decoded.inspect(t.Context(), layout, data); err != nil {
		t.Fatal("decoded contract retained caller-owned mutable input")
	}
}

func TestReviewedRulesetRejectsInstalledDrift(t *testing.T) {
	t.Parallel()
	contract := reviewedRulesetFixture(t)
	layout, original := fullRulesetFixture(t)
	cases := []struct {
		name, old, replacement string
	}{
		{name: "unqualified format", old: `"version":"1.1.3"`, replacement: `"version":"1.1.4"`},
		{name: "rule action", old: `"accept":null`, replacement: `"drop":null`},
		{name: "drop weakened", old: `"policy":"drop"`, replacement: `"policy":"accept"`},
		{name: "hook moved", old: `"hook":"output"`, replacement: `"hook":"prerouting"`},
		{name: "priority changed", old: `"prio":0`, replacement: `"prio":1`},
		{name: "protected target changed", old: `"10.240.2.254"`, replacement: `"10.240.2.253"`},
		{name: "map target changed", old: `"fdca:1a2b:2::20"`, replacement: `"fdca:1a2b:2::21"`},
		{name: "jump retargeted", old: `"target":"safety"`, replacement: `"target":"stateful"`},
		{name: "counter alias", old: `"counter":"flow_hits"`, replacement: `"counter":"other_hits"`},
		{name: "unknown counter field", old: `"bytes":512,"packets":7`, replacement: `"bytes":512,"packets":7,"hidden":1`},
		{name: "counter overflow", old: `"bytes":512,"packets":7`, replacement: `"bytes":512,"packets":18446744073709551616`},
		{name: "counter fractional", old: `"bytes":512,"packets":7`, replacement: `"bytes":512,"packets":7.5`},
		{name: "counter null", old: `"bytes":512,"packets":7`, replacement: `"bytes":512,"packets":null`},
		{name: "counter signed", old: `"bytes":512,"packets":7`, replacement: `"bytes":512,"packets":-1`},
		{name: "counter missing", old: `"bytes":512,"packets":7`, replacement: `"bytes":512`},
		{name: "helper guard changed", old: `"prio":-150`, replacement: `"prio":-149`},
		{name: "unknown field", old: `"name":"reserved_peers"`, replacement: `"name":"reserved_peers","future":true`},
		{name: "dynamic set", old: `"flags":["interval"]`, replacement: `"flags":["interval","dynamic"]`},
		{name: "unqualified verdict map", old: `"map":"ipv6_addr"`, replacement: `"map":"verdict"`},
		{name: "duplicate keys", old: `"target":"safety"`, replacement: `"target":"safety","target":"stateful"`},
		{name: "zero handle", old: `"handle":16`, replacement: `"handle":0`},
		{name: "duplicate handle", old: `"handle":16`, replacement: `"handle":15`},
		{name: "helper family collision", old: `"family":"netdev"`, replacement: `"family":"bridge"`},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			if !bytes.Contains(original, []byte(test.old)) {
				t.Fatal("drift test did not mutate its fixture")
			}
			data := []byte(strings.ReplaceAll(string(original), test.old, test.replacement))
			if observation, err := contract.inspect(t.Context(), layout, data); err == nil || observation != nil {
				t.Fatal("changed complete ruleset produced trusted or partial observation")
			}
		})
	}
}

func TestReviewedRulesetRejectsReorderedMissingAndExtraRules(t *testing.T) {
	t.Parallel()
	for _, name := range []string{"reordered rules", "missing table", "missing rule", "extra rule", "unreviewed table", "flowtable", "missing guard", "duplicate metadata"} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			contract := reviewedRulesetFixture(t)
			layout, data := fullRulesetFixture(t)
			var listing struct {
				Objects []json.RawMessage `json:"nftables"`
			}
			if err := json.Unmarshal(data, &listing); err != nil {
				t.Fatal(err)
			}
			switch name {
			case "reordered rules":
				listing.Objects[10], listing.Objects[11] = listing.Objects[11], listing.Objects[10]
			case "missing table":
				listing.Objects = append(listing.Objects[:1], listing.Objects[2:]...)
			case "missing rule":
				listing.Objects = append(listing.Objects[:10], listing.Objects[11:]...)
			case "extra rule":
				listing.Objects = append(listing.Objects, bytes.ReplaceAll(listing.Objects[10], []byte(`"handle":10`), []byte(`"handle":999`)))
			case "unreviewed table":
				listing.Objects = append(listing.Objects, json.RawMessage(`{"table":{"family":"ip","name":"unreviewed","handle":9}}`))
			case "flowtable":
				listing.Objects = append(listing.Objects, json.RawMessage(`{"flowtable":{"family":"inet","table":"reviewed_floor","name":"offload","handle":999}}`))
			case "missing guard":
				listing.Objects = listing.Objects[:17]
			case "duplicate metadata":
				listing.Objects = append(listing.Objects, listing.Objects[0])
			}
			encoded, err := json.Marshal(listing)
			if err != nil {
				t.Fatal(err)
			}
			if observation, err := contract.inspect(t.Context(), layout, encoded); err == nil || observation != nil {
				t.Fatal("incomplete, extra or reordered program was trusted")
			}
		})
	}
}

func TestReviewedArtifactRejectsUnqualifiedPrograms(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name, old, replacement string
	}{
		{name: "schema", old: `"schema_version":1`, replacement: `"schema_version":2`},
		{name: "live header", old: `"schema_version":1,`, replacement: `"nftables":[],`},
		{name: "runtime handle", old: `"name":"reviewed_floor"`, replacement: `"name":"reviewed_floor","handle":1`},
		{name: "counter statistics", old: `"counter":{}`, replacement: `"counter":{"packets":0,"bytes":0}`},
		{name: "helper ownership", old: `reviewed_floor`, replacement: `router_policy_agent`},
		{name: "missing required hook", old: `"hook":"output"`, replacement: `"hook":"postrouting"`},
		{name: "unexpected family", old: `"family":"inet"`, replacement: `"family":"unknown"`},
		{name: "dangling target", old: `"target":"safety"`, replacement: `"target":"missing"`},
		{name: "base-chain target", old: `"target":"safety"`, replacement: `"target":"input"`},
		{name: "cyclic target", old: `"return":null`, replacement: `"jump":{"target":"safety"}`},
		{name: "offload statement", old: `"accept":null`, replacement: `"flow":{"op":"add","flowtable":"offload"}`},
		{name: "unknown statement", old: `"accept":null`, replacement: `"xt":{"type":"target"}`},
		{name: "dormant table", old: `"name":"reviewed_floor"`, replacement: `"name":"reviewed_floor","flags":["dormant"]`},
		{name: "duplicate declarations", old: `"name":"stateful"`, replacement: `"name":"safety"`},
		{name: "shared collection namespace", old: `"name":"peer_map"`, replacement: `"name":"reserved_peers"`},
		{name: "unbounded identifier", old: `reviewed_floor`, replacement: strings.Repeat("a", 129)},
		{name: "unsafe identifier", old: `reviewed_floor`, replacement: `other/table`},
		{name: "partial base chain", old: `"prio":0,`, replacement: ``},
		{name: "priority overflow", old: `"prio":0`, replacement: `"prio":2147483648`},
		{name: "duplicate elements", old: `"10.240.2.254",`, replacement: `"10.240.2.254","10.240.2.254",`},
		{name: "timeout collection", old: `"flags":["interval"]`, replacement: `"flags":["timeout"]`},
		{name: "verdict indirection", old: `"map":"ipv6_addr"`, replacement: `"map":"verdict"`},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			if !strings.Contains(reviewedArtifactFixture, test.old) {
				t.Fatal("artifact test did not mutate its fixture")
			}
			data := []byte(strings.ReplaceAll(reviewedArtifactFixture, test.old, test.replacement))
			if contract, err := decodeReviewedRuleset(t.Context(), data); err == nil || contract != nil {
				t.Fatal("unqualified artifact produced a trusted or partial program")
			}
		})
	}
}

func TestReviewedRulesetPrecisionAndCancellation(t *testing.T) {
	t.Parallel()
	artifact := strings.ReplaceAll(reviewedArtifactFixture, `"right":"invalid"`, `"right":9007199254740992`)
	contract, err := decodeReviewedRuleset(t.Context(), []byte(artifact))
	if err != nil {
		t.Fatal(err)
	}
	layout, data := fullRulesetFixture(t)
	data = bytes.ReplaceAll(data, []byte(`"right":"invalid"`), []byte(`"right":9007199254740993`))
	if observation, err := contract.inspect(t.Context(), layout, data); err == nil || observation != nil {
		t.Fatal("integer rounding erased a policy difference")
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if _, err := contract.inspect(ctx, layout, data); !errors.Is(err, context.Canceled) {
		t.Fatal("ruleset inspection lost cancellation")
	}
	if _, err := decodeReviewedRuleset(ctx, []byte(artifact)); !errors.Is(err, context.Canceled) {
		t.Fatal("artifact validation lost cancellation")
	}
	for _, name := range []string{"nil context", "nil contract", "empty contract", "nil layout", "empty data", "trailing data", "null objects", "oversize artifact"} {
		t.Run(name, func(t *testing.T) {
			ctx, value, geometry, input := t.Context(), contract, layout, data
			switch name {
			case "nil context":
				ctx = nil
			case "nil contract":
				value = nil
			case "empty contract":
				value = &reviewedRuleset{}
			case "nil layout":
				geometry = nil
			case "empty data":
				input = nil
			case "trailing data":
				input = append(bytes.Clone(data), []byte(`{}`)...)
			case "null objects":
				input = []byte(`{"nftables":null}`)
			case "oversize artifact":
				if _, err := decodeReviewedRuleset(t.Context(), bytes.Repeat([]byte(" "), maximumReviewedRuleset+1)); err == nil {
					t.Fatal("oversize reviewed artifact accepted")
				}
				return
			}
			if observation, err := value.inspect(ctx, geometry, input); err == nil || observation != nil {
				t.Fatal("invalid dependencies or input produced a trusted observation")
			}
		})
	}
}

func TestReviewedRulesetGraphDepthAndHookCollisions(t *testing.T) {
	t.Parallel()
	for _, name := range []string{"deep graph", "same-family priority", "cross-family priority", "helper priority"} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			var artifact struct {
				Schema  int               `json:"schema_version"`
				Objects []json.RawMessage `json:"objects"`
			}
			if err := json.Unmarshal([]byte(reviewedArtifactFixture), &artifact); err != nil {
				t.Fatal(err)
			}
			switch name {
			case "deep graph":
				for index := range maximumChainDepth + 1 {
					artifact.Objects = append(artifact.Objects, json.RawMessage(fmt.Sprintf(
						`{"chain":{"family":"inet","table":"reviewed_floor","name":"deep%d"}}`, index)))
					if index > 0 {
						artifact.Objects = append(artifact.Objects, json.RawMessage(fmt.Sprintf(
							`{"rule":{"family":"inet","table":"reviewed_floor","chain":"deep%d","expr":[{"goto":{"target":"deep%d"}}]}}`,
							index-1, index)))
					}
				}
			case "same-family priority":
				artifact.Objects = append(artifact.Objects, json.RawMessage(`{"chain":{"family":"inet","table":"reviewed_floor","name":"competing","type":"filter","hook":"forward","prio":0,"policy":"accept"}}`))
			case "cross-family priority":
				artifact.Objects = append(artifact.Objects,
					json.RawMessage(`{"table":{"family":"ip","name":"other"}}`),
					json.RawMessage(`{"chain":{"family":"ip","table":"other","name":"competing","type":"filter","hook":"forward","prio":0,"policy":"accept"}}`))
			case "helper priority":
				artifact.Objects[3] = bytes.ReplaceAll(artifact.Objects[3], []byte(`"prio":0`), []byte(`"prio":-150`))
			}
			data, err := json.Marshal(artifact)
			if err != nil {
				t.Fatal(err)
			}
			contract, err := decodeReviewedRuleset(t.Context(), data)
			if name != "helper priority" {
				if err == nil || contract != nil {
					t.Fatal("cyclic, excessive or unordered root contract accepted")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			layout, listing := fullRulesetFixture(t)
			var installed struct {
				Objects []json.RawMessage `json:"nftables"`
			}
			if err := json.Unmarshal(listing, &installed); err != nil {
				t.Fatal(err)
			}
			installed.Objects[4] = bytes.ReplaceAll(installed.Objects[4], []byte(`"prio":0`), []byte(`"prio":-150`))
			listing, err = json.Marshal(installed)
			if err != nil {
				t.Fatal(err)
			}
			observation, err := contract.inspect(t.Context(), layout, listing)
			if err == nil || observation != nil || !strings.Contains(err.Error(), "ambiguous ruleset hook ordering") {
				t.Fatal("reviewed chain competing with the fixed helper hook was accepted")
			}
		})
	}
}

func FuzzReviewedRuleset(f *testing.F) {
	f.Add([]byte(reviewedArtifactFixture))
	f.Add([]byte(`{"schema_version":1,"objects":[]}`))
	f.Add([]byte(`{"nftables":[]}`))
	f.Fuzz(func(t *testing.T, data []byte) {
		contract, err := decodeReviewedRuleset(t.Context(), data)
		if err != nil {
			if contract != nil {
				t.Fatal("rejected artifact returned a partial contract")
			}
			return
		}
		if len(contract.program) == 0 || len(contract.digest) != 64 {
			t.Fatal("accepted artifact has no complete program identity")
		}
		again, err := decodeReviewedRuleset(t.Context(), data)
		if err != nil || contract.digest != again.digest || !bytes.Equal(contract.program, again.program) {
			t.Fatal("reviewed artifact normalization is not deterministic")
		}
		layout, listing := fullRulesetFixture(t)
		observation, err := contract.inspect(t.Context(), layout, listing)
		if err != nil && observation != nil {
			t.Fatal("rejected actual listing returned partial evidence")
		}
		if err == nil && observation.digest != contract.digest {
			t.Fatal("verified listing lost the reviewed program identity")
		}
	})
}
