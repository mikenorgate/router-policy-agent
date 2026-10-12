package firewall

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/mikenorgate/router-policy-agent/internal/policy"
)

func TestRendererScopesAndGuardMirrors(t *testing.T) {
	t.Parallel()
	renderer, replacement, _, input := renderFixture(t)
	raw := strings.Replace(*input.Directory.Groups[1].Policy, `"schema_version":1`, `"schema_version":2`, 1)
	raw = strings.Replace(raw, "fdca:1a2b::10/128", "fdca:1a2b::/64", 1)
	raw = strings.Replace(raw, `"destination_ports":[6053]`, `"destination_port_ranges":[{"first":6053,"last":6060}]`, 1)
	input.Directory.Groups[1].Policy = &raw
	authorization, err := renderer.compiler.CompileAuthorization(t.Context(), input, policy.CaptureAge())
	if err != nil {
		t.Fatal(err)
	}
	candidate, err := authorization.Snapshot(t.Context())
	if err != nil || len(candidate.Denials) != 0 || len(candidate.Grants) == 0 || candidate.Grants[0].PeerScope == nil {
		t.Fatalf("fixture did not exercise a real scope: %v %+v", err, candidate.Denials)
	}
	replacement.authorization = authorization
	batch, err := renderer.prepare(t.Context(), replacement)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(batch.data, []byte(`"prefix":{"addr":"fdca:1a2b::","len":64}`)) ||
		!bytes.Contains(batch.data, []byte(`"range":[6053,6060]`)) {
		t.Fatalf("scope was omitted, enumerated or widened: %s", batch.data)
	}
	prepared, err := prepareGuards(t.Context(), batch)
	if err != nil {
		t.Fatal(err)
	}
	if err := validateGuardBatch(t.Context(), prepared.batch.data); err != nil {
		t.Fatal(err)
	}
	var changes guardChanges
	if err := json.Unmarshal(prepared.batch.data, &changes); err != nil {
		t.Fatal(err)
	}
	count := 0
	for _, command := range changes.Commands {
		if command.Add == nil || !strings.Contains(command.Add.Element.Name, "lease_to6_tcp") {
			continue
		}
		for _, value := range command.Add.Element.Values {
			if !bytes.Contains(value, []byte(`"prefix":{"addr":"fdca:1a2b::","len":64}`)) ||
				!bytes.Contains(value, []byte(`"range":[6053,6060]`)) {
				t.Fatalf("guard mirror changed the interval: %s", value)
			}
			count++
		}
	}
	if count != 3 {
		t.Fatalf("expected logical, inbound and final-MAC mirrors; got %d", count)
	}
}

func TestRendererAllPortsKeepsBootstrapSeparate(t *testing.T) {
	t.Parallel()
	for _, protocol := range []string{"tcp", "udp"} {
		t.Run(protocol, func(t *testing.T) {
			t.Parallel()
			renderer, replacement, _, input := renderFixture(t)
			raw := strings.Replace(*input.Directory.Groups[1].Policy, `"schema_version":1`, `"schema_version":2`, 1)
			raw = strings.Replace(raw, "fdca:1a2b::10/128", "fdca:1a2b::/64", 1)
			raw = strings.Replace(raw, `"destination_ports":[6053]`, `"all_destination_ports":true`, 1)
			raw = strings.Replace(raw, `"protocol":"tcp"`, `"protocol":"`+protocol+`"`, 1)
			input.Directory.Groups[1].Policy = &raw
			authorization, err := renderer.compiler.CompileAuthorization(t.Context(), input, policy.CaptureAge())
			if err != nil {
				t.Fatal(err)
			}
			replacement.authorization = authorization
			batch, err := renderer.prepare(t.Context(), replacement)
			if err != nil {
				t.Fatal(err)
			}
			var changes guardChanges
			if err := json.Unmarshal(batch.data, &changes); err != nil {
				t.Fatal(err)
			}
			var spans []listenerSpan
			for _, command := range changes.Commands {
				if command.Add == nil || command.Add.Element.Name != "lease_to6_"+protocol {
					continue
				}
				for _, value := range command.Add.Element.Values {
					key, err := validateLeasedTuple(value, false)
					if err != nil {
						t.Fatal(err)
					}
					spans = append(spans, listenerSpan{key.port, key.lastPort()})
				}
			}
			for _, port := range []uint16{1, 52, 53, 54, 80, 123, 443, 65535} {
				covered := false
				for _, span := range spans {
					covered = covered || span.first <= port && port <= span.last
				}
				want := port != 53 && (protocol != "udp" || port != 123)
				if covered != want {
					t.Fatalf("all-port application coverage for %d=%t, want %t", port, covered, want)
				}
			}
			if len(spans) > 3 {
				t.Fatalf("all-port scope was enumerated: %d entries", len(spans))
			}
		})
	}
}
