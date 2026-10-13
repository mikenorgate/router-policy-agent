package agent

import (
	"encoding/json"
	"github.com/mikenorgate/router-policy-agent/internal/ipc"
	"github.com/mikenorgate/router-policy-agent/internal/policy"
	"slices"
	"strings"
	"testing"
)

func TestProvenancePreservesCompactScopeAndListenerInterval(t *testing.T) {
	t.Parallel()
	for _, test := range []struct {
		name string
		peer policy.Peer
	}{
		{name: "Internet", peer: policy.Peer{Internet: true}},
		{name: "CIDR", peer: policy.Peer{Addresses: []string{"fdca:1a2b::/64"}}},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			f := newFixture(t)
			document := policy.Document{
				SchemaVersion: 2, Kind: "access", VLANRole: policy.Untrusted,
				Rules: []policy.Rule{{
					ID: "interval", Direction: policy.FromDevice, Protocol: "tcp", Peer: test.peer,
					DestinationPortRanges: []policy.PortRange{{First: 8000, Last: 8010}}, Reason: "Synthetic observation",
				}},
			}
			encoded, err := json.Marshal(document)
			if err != nil {
				t.Fatal(err)
			}
			// Access attributes require an explicit false value; Document's
			// omitempty tag is intended for placement documents too.
			raw := strings.Replace(string(encoded), `"kind":"access"`, `"kind":"access","temporary":false`, 1)
			f.directory.Groups[1].Policy = &raw
			engine := f.engine(t, f.options(Enforce))
			if receipt, err := engine.Process(t.Context(), f.directory); err != nil || receipt.GrantCount == 0 {
				t.Fatalf("compile scope: %v, receipt=%+v, denials=%+v", err, receipt, f.firewall.candidates)
			}
			request := ipc.ObservationRequest{SchemaVersion: 1, Operation: "observations"}
			report, err := engine.Observations(t.Context(), request)
			if err != nil || report.Snapshot == nil || !report.Snapshot.Complete || len(report.Snapshot.Grants) != 1 {
				t.Fatalf("scope provenance unavailable: %v %+v", err, report)
			}
			grant := report.Snapshot.Grants[0]
			if grant.PeerAddress != "" || grant.Port != 8000 || grant.PortEnd != 8010 || grant.Internet != test.peer.Internet {
				t.Fatalf("scope or listener range lost: %+v", grant)
			}
			if test.peer.Internet {
				if grant.PeerNetwork != "" || len(grant.PeerNetworkVariants) != 0 {
					t.Fatal("Internet selector was expanded in observations")
				}
				return
			}
			if grant.PeerNetwork != test.peer.Addresses[0] || len(grant.PeerNetworkVariants) != 1 {
				t.Fatalf("CIDR variants lost: %+v", grant)
			}
			report.Snapshot.Grants[0].PeerNetworkVariants[0] = "mutated"
			again, err := engine.Observations(t.Context(), request)
			if err != nil || again.Snapshot.Grants[0].PeerNetworkVariants[0] == "mutated" {
				t.Fatal("scope provenance is mutable")
			}
		})
	}
}

func TestProvenanceCannotRenewOrBlockEnforcement(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	engine := f.engine(t, f.options(Enforce))
	if _, err := engine.Process(t.Context(), f.directory); err != nil {
		t.Fatal(err)
	}
	before := slices.Clone(f.events)
	clock := engine.clock
	// Occupy the engine transaction gate. Observation queries must still return.
	engine.gate <- struct{}{}
	defer func() { <-engine.gate }()
	request := ipc.ObservationRequest{SchemaVersion: 1, Operation: "observations"}
	first, err := engine.Observations(t.Context(), request)
	if err != nil || first.Snapshot == nil || len(first.Snapshot.Grants) != 1 || len(first.Snapshot.Grants[0].Contributors) != 1 {
		t.Fatal(first, err)
	}
	expiry := first.Snapshot.Grants[0].Contributors[0].ExpiresAt
	first.Snapshot.Grants[0].Contributors[0].GroupID = "mutated"
	again, err := engine.Observations(t.Context(), request)
	if err != nil || again.Snapshot.Grants[0].Contributors[0].GroupID == "mutated" || !again.Snapshot.Grants[0].Contributors[0].ExpiresAt.Equal(expiry) {
		t.Fatal("mutable snapshot or refreshed deadline")
	}
	if !slices.Equal(before, f.events) || engine.clock != clock {
		t.Fatal("observations changed persistence, bindings, firewall or clock")
	}
	body, _ := json.Marshal(again)
	if strings.Contains(string(body), "reason") || strings.Contains(string(body), "network_policy_v1") {
		t.Fatal("raw directory text retained")
	}
	request.Generation = "other"
	changed, err := engine.Observations(t.Context(), request)
	if err != nil || changed.Code != "generation_changed" {
		t.Fatal(changed, err)
	}
}
