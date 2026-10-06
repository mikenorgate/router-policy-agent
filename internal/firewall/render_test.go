package firewall

import (
	"bytes"
	"context"
	"encoding/json"
	"net/netip"
	"os"
	"strings"
	"testing"
	"testing/synctest"
	"time"

	"github.com/mikenorgate/router-policy-agent/internal/binding"
	"github.com/mikenorgate/router-policy-agent/internal/policy"
)

func renderFixture(t *testing.T) (*renderer, replacement, policy.Baseline, policy.Input) {
	t.Helper()
	// Public examples are explicitly synthetic, never captured deployment data.
	baselineData, err := os.ReadFile("../../examples/baseline.json")
	if err != nil {
		t.Fatal(err)
	}
	baseline, err := policy.DecodeBaseline(baselineData)
	if err != nil {
		t.Fatal(err)
	}
	directoryData, err := os.ReadFile("../../examples/directory.json")
	if err != nil {
		t.Fatal(err)
	}
	bindingsData, err := os.ReadFile("../../examples/bindings.json")
	if err != nil {
		t.Fatal(err)
	}
	var directory policy.DirectorySnapshot
	var bindings binding.Snapshot
	if err := json.Unmarshal(directoryData, &directory); err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(bindingsData, &bindings); err != nil {
		t.Fatal(err)
	}
	compiler, err := policy.New(baseline)
	if err != nil {
		t.Fatal(err)
	}
	input := policy.Input{Directory: directory, Bindings: bindings, Now: directory.ObservedAt}
	authorization, err := compiler.CompileAuthorization(t.Context(), input, policy.CaptureAge())
	if err != nil {
		t.Fatal(err)
	}
	candidate, err := authorization.Snapshot(t.Context())
	if err != nil || len(candidate.Grants) != 1 {
		t.Fatalf("synthetic fixture did not compile: %v", err)
	}
	renderer, err := newRenderer(baseline)
	if err != nil {
		t.Fatal(err)
	}
	return renderer, replacement{
		authorization: authorization, cohort: []string{"02:00:00:00:00:01"}, now: input.Now,
	}, baseline, input
}

func TestRendererLifetimeAndCohort(t *testing.T) {
	t.Parallel()
	renderer, input, _, _ := renderFixture(t)
	// A later application must subtract elapsed time, never start a new lease.
	input.now = input.now.Add(20 * time.Second)
	input.existingCohort = []string{"02:00:00:00:00:01"}
	input.cohort = []string{}
	batch, err := renderer.prepare(t.Context(), input)
	if err != nil {
		t.Fatal(err)
	}
	if batch.preparedAt != input.now || batch.startBefore != input.now.Add(preparationBudget) {
		t.Fatal("renderer did not bound the preparation window")
	}
	// 70s remaining minus 2s preparation and 2.25s execution, rounded down.
	if !bytes.Contains(batch.data, []byte(`"timeout":65`)) {
		t.Fatal("rendered timeout restarted or exceeded the absolute lease")
	}
	if bytes.Contains(batch.data, []byte(cohortSet)) {
		t.Fatal("existing permanent classification was replaced or re-added")
	}
	repeated, err := renderer.prepare(t.Context(), input)
	if err != nil || !bytes.Equal(batch.data, repeated.data) {
		t.Fatal("rendering is not deterministic")
	}
}

func TestRendererRetainsAllCompatibleCounterpartsAndProtocols(t *testing.T) {
	t.Parallel()
	renderer, replacement, _, input := renderFixture(t)
	policyJSON := strings.ReplaceAll(*input.Directory.Groups[1].Policy, "fdca:1a2b::10", "fdca:1a2b:2::20")
	input.Directory.Groups[1].Policy = &policyJSON
	input.Bindings.Records[0].Addresses = append(input.Bindings.Records[0].Addresses, binding.Address{
		IP: netip.MustParseAddr("10.240.3.10"), Source: "kea_dhcp4", OwnershipID: "synthetic-v4-ownership",
		ObservedAt: input.Now, ValidUntil: input.Now.Add(time.Hour),
	})
	input.Directory.Groups = append(input.Directory.Groups, rendererAccessGroup(t, "udp-access", false, policy.Rule{
		ID: "device-datagrams", Direction: policy.FromDevice,
		Peer: policy.Peer{Addresses: []string{"fdca:1a2b:2::20/128"}}, Protocol: "udp",
		DestinationPorts: []uint16{6053}, Reason: "Synthetic datagram listener",
	}))
	input.Directory.Devices[0].GroupIDs = append(input.Directory.Devices[0].GroupIDs, "udp-access")
	authorization, err := renderer.compiler.CompileAuthorization(t.Context(), input, policy.CaptureAge())
	if err != nil {
		t.Fatal(err)
	}
	candidate, err := authorization.Snapshot(t.Context())
	if err != nil || len(candidate.Grants) != 4 {
		t.Fatalf("counterpart fixture did not compile: %v", err)
	}
	replacement.authorization = authorization
	batch, err := renderer.prepare(t.Context(), replacement)
	if err != nil {
		t.Fatal(err)
	}
	counts := renderedCounts(t, batch.data)
	for name, expected := range map[string]int{
		"lease_to4_tcp": 1, "lease_to6_tcp": 4, "lease_from4_udp": 1, "lease_from6_udp": 4, cohortSet: 1,
	} {
		if counts[name] != expected {
			t.Fatalf(
				"representation count for %s=%d, want %d",
				name,
				counts[name],
				expected,
			)
		}
	}
}

func TestRendererDuplicateGrantUnion(t *testing.T) {
	t.Parallel()
	synctest.Test(t, func(t *testing.T) {
		renderer, replacement, _, input := renderFixture(t)
		expiry := input.Now.Add(40 * time.Second)
		input.Directory.Groups = append(input.Directory.Groups, rendererAccessGroup(t, "another-group", true, policy.Rule{
			ID: "another-rule", Direction: policy.ToDevice,
			Peer: policy.Peer{Addresses: []string{"fdca:1a2b::10/128"}}, Protocol: "tcp",
			DestinationPorts: []uint16{6053}, Reason: "Synthetic overlapping permission", ExpiresAt: &expiry,
		}))
		input.Directory.Devices[0].GroupIDs = append(input.Directory.Devices[0].GroupIDs, "another-group")
		authorization, err := renderer.compiler.CompileAuthorization(t.Context(), input, policy.CaptureAge())
		if err != nil {
			t.Fatal(err)
		}
		candidate, err := authorization.Snapshot(t.Context())
		if err != nil || len(candidate.Grants) != 1 || len(candidate.Grants[0].Contributors) != 2 {
			t.Fatalf("overlapping raw policies did not retain both contributors: %v", err)
		}
		replacement.authorization = authorization
		batch, err := renderer.prepare(t.Context(), replacement)
		if err != nil || renderedCounts(t, batch.data)["lease_to6_tcp"] != 1 {
			t.Fatalf("overlapping grants were not deduplicated: %v", err)
		}
		if !bytes.Contains(batch.data, []byte(`"timeout":85`)) {
			t.Fatal("shorter contributor erased another still-valid permission")
		}
		time.Sleep(45 * time.Second)
		replacement.now = input.Now.Add(20 * time.Second)
		batch, err = renderer.prepare(t.Context(), replacement)
		if err != nil || !bytes.Contains(batch.data, []byte(`"timeout":40`)) {
			t.Fatalf("expired contributor erased or rejuvenated the union: %v", err)
		}
	})
}

func TestRendererPreservesOriginalElapsedDeadline(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name    string
		elapsed time.Duration
		utc     time.Duration
		timeout string
		wantErr bool
	}{
		{name: "queued with frozen utc", elapsed: 30 * time.Second, timeout: `"timeout":55`},
		{name: "queued with rolled back utc", elapsed: 45 * time.Second, utc: 20 * time.Second,
			timeout: `"timeout":40`},
		{name: "elapsed expiry with fresh utc", elapsed: 91 * time.Second, utc: 20 * time.Second, wantErr: true},
		{name: "elapsed life too short for preparation", elapsed: 86 * time.Second, wantErr: true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			synctest.Test(t, func(t *testing.T) {
				renderer, input, _, _ := renderFixture(t)
				time.Sleep(test.elapsed)
				input.now = input.now.Add(test.utc)
				batch, err := renderer.prepare(t.Context(), input)
				if test.wantErr {
					if err == nil || batch != nil {
						t.Fatal("expired authorization produced a partial replacement")
					}
					return
				}
				if err != nil || batch == nil || !bytes.Contains(batch.data, []byte(test.timeout)) {
					t.Fatalf("queued result renewed its lifetime: %v", err)
				}
			})
		})
	}
}

func TestRendererCannotApplyEditedDiagnosticSnapshot(t *testing.T) {
	t.Parallel()
	synctest.Test(t, func(t *testing.T) {
		renderer, input, _, _ := renderFixture(t)
		before, err := renderer.prepare(t.Context(), input)
		if err != nil {
			t.Fatal(err)
		}
		snapshot, err := input.authorization.Snapshot(t.Context())
		if err != nil {
			t.Fatal(err)
		}
		snapshot.BaselineHash = "other"
		snapshot.Grants[0].Peer.Variants = append(snapshot.Grants[0].Peer.Variants, netip.MustParseAddr("10.241.0.10"))
		snapshot.Grants[0].Contributors[0].ExpiresAt = snapshot.CompiledAt.Add(time.Hour)
		snapshot.Grants[0].Port = 22
		after, err := renderer.prepare(t.Context(), input)
		if err != nil || !bytes.Equal(before.data, after.data) {
			t.Fatalf("editable snapshot changed an enforced tuple or expiry: %v", err)
		}
	})
}

func TestRendererRejectsUnsafeReplacement(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name   string
		change func(*replacement)
	}{
		{name: "missing authorization", change: func(r *replacement) { r.authorization = policy.Authorization{} }},
		{name: "future compilation", change: func(r *replacement) { r.now = r.now.Add(-time.Second) }},
		{name: "expired observation", change: func(r *replacement) { r.now = r.now.Add(90 * time.Second) }},
		{name: "short remaining lease", change: func(r *replacement) { r.now = r.now.Add(86 * time.Second) }},
		{name: "missing cohort", change: func(r *replacement) { r.cohort = []string{} }},
		{name: "noncanonical cohort", change: func(r *replacement) { r.cohort = []string{"020000000001"} }},
		{name: "duplicate cohort", change: func(r *replacement) { r.cohort = append(r.cohort, r.cohort[0]) }},
		{name: "bad existing cohort", change: func(r *replacement) { r.existingCohort = []string{"unknown"} }},
		{name: "excess cohort", change: func(r *replacement) { r.cohort = make([]string, 4097) }},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			renderer, input, _, _ := renderFixture(t)
			test.change(&input)
			if batch, err := renderer.prepare(t.Context(), input); err == nil || batch != nil {
				t.Fatal("unsafe replacement produced a partial transaction")
			}
		})
	}
	_, input, baseline, original := renderFixture(t)
	baseline.MaximumDevices = 1
	renderer, err := newRenderer(baseline)
	if err != nil {
		t.Fatal(err)
	}
	if batch, err := renderer.prepare(t.Context(), input); err == nil || batch != nil {
		t.Fatal("authorization for another baseline produced a transaction")
	}
	input.authorization, err = renderer.compiler.CompileAuthorization(t.Context(), original, policy.CaptureAge())
	if err != nil {
		t.Fatal(err)
	}
	input.existingCohort = []string{"02:00:00:00:00:02"}
	if batch, err := renderer.prepare(t.Context(), input); err == nil || batch != nil {
		t.Fatal("combined permanent cohort exceeded the configured quota")
	}
}

func rendererAccessGroup(t *testing.T, id string, temporary bool, rules ...policy.Rule) policy.Group {
	t.Helper()
	data, err := json.Marshal(map[string]any{
		"schema_version": 1, "kind": "access", "vlan_role": "untrusted", "temporary": temporary, "rules": rules,
	})
	if err != nil {
		t.Fatal(err)
	}
	raw := string(data)
	return policy.Group{ID: id, Name: "synthetic " + id, IsNetwork: true, Policy: &raw}
}

func TestRendererRejectsMissingOrCanceledDependencies(t *testing.T) {
	t.Parallel()
	var missing *renderer
	renderer, input, baseline, _ := renderFixture(t)
	if batch, err := missing.prepare(t.Context(), input); err == nil || batch != nil {
		t.Fatal("missing renderer produced a transaction")
	}
	//nolint:staticcheck // Deliberately corrupt context tests the rejection boundary.
	if batch, err := renderer.prepare(nil, input); err == nil || batch != nil {
		t.Fatal("missing context produced a transaction")
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if batch, err := renderer.prepare(ctx, input); err == nil || batch != nil {
		t.Fatal("canceled rendering produced a transaction")
	}
	baseline.LeaseSeconds = 0
	if renderer, err := newRenderer(baseline); err == nil || renderer != nil {
		t.Fatal("invalid baseline created a renderer")
	}
}

func renderedCounts(t *testing.T, data []byte) map[string]int {
	t.Helper()
	var batch struct {
		Commands []change `json:"nftables"`
	}
	if err := json.Unmarshal(data, &batch); err != nil {
		t.Fatal(err)
	}
	counts := map[string]int{}
	for _, command := range batch.Commands {
		if command.Add != nil {
			counts[command.Add.Element.Name] = len(command.Add.Element.Values)
		}
	}
	return counts
}
