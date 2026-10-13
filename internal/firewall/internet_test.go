package firewall

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/mikenorgate/router-policy-agent/internal/policy"
)

func internetRenderFixture(t *testing.T) (*renderer, replacement, policy.Baseline) {
	t.Helper()
	renderer, replacement, baseline, input := renderFixture(t)
	input.Directory.Groups = input.Directory.Groups[:1]
	input.Directory.Devices[0].GroupIDs = []string{input.Directory.Groups[0].ID}
	for _, protocol := range []string{"tcp", "udp"} {
		group := rendererAccessGroup(t, "internet-"+protocol, false, policy.Rule{
			ID: "internet", Direction: policy.FromDevice, Peer: policy.Peer{Internet: true},
			Protocol: protocol, AllDestinationPorts: true, Reason: "Synthetic public Internet access",
		})
		raw := strings.Replace(*group.Policy, `"schema_version":1`, `"schema_version":2`, 1)
		group.Policy = &raw
		input.Directory.Groups = append(input.Directory.Groups, group)
		input.Directory.Devices[0].GroupIDs = append(input.Directory.Devices[0].GroupIDs, group.ID)
	}
	authorization, err := renderer.compiler.CompileAuthorization(t.Context(), input, policy.CaptureAge())
	if err != nil {
		t.Fatal(err)
	}
	replacement.authorization = authorization
	return renderer, replacement, baseline
}

func TestInternetRenderingHasConstantSize(t *testing.T) {
	t.Parallel()
	renderer, replacement, baseline := internetRenderFixture(t)
	candidate, err := replacement.authorization.Snapshot(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if len(candidate.Grants) != 5 {
		t.Fatalf("Internet should have two TCP and three UDP spans, got %d grants", len(candidate.Grants))
	}
	logical, err := renderer.prepare(t.Context(), replacement)
	if err != nil {
		t.Fatal(err)
	}
	layout, err := newGuardLayout(baseline)
	if err != nil {
		t.Fatal(err)
	}
	prepared, err := prepareMappedGuards(t.Context(), logical, nil, layout.translationPaths)
	if err != nil {
		t.Fatal(err)
	}
	if err := validatePreparedGuardBatch(t.Context(), prepared); err != nil {
		t.Fatal(err)
	}
	if len(logical.data) > 8000 || len(prepared.batch.data) > 24000 {
		t.Fatalf("Internet expanded into public subnets: logical=%d mirrored=%d", len(logical.data), len(prepared.batch.data))
	}
	var changes guardChanges
	if err := json.Unmarshal(logical.data, &changes); err != nil {
		t.Fatal(err)
	}
	for _, command := range changes.Commands {
		if command.Add == nil || command.Add.Element.Name == cohortSet {
			continue
		}
		if !strings.HasPrefix(command.Add.Element.Name, "internet_from") {
			t.Fatalf("Internet grant used unfiltered generic set %s", command.Add.Element.Name)
		}
	}
}

func TestGenericTuplesCannotUseInternetWildcard(t *testing.T) {
	t.Parallel()
	renderer, replacement, _ := internetRenderFixture(t)
	logical, err := renderer.prepare(t.Context(), replacement)
	if err != nil {
		t.Fatal(err)
	}
	corrupt := strings.ReplaceAll(string(logical.data), "internet_from", "lease_from")
	if err := validateBatch([]byte(corrupt)); err == nil {
		t.Fatal("Internet wildcard was accepted by unfiltered generic grant sets")
	}
}
