//go:build integration && kernel && linux

package firewall

import (
	"bytes"
	"context"
	"testing"
	"time"
)

// Independently authored text and artifact must agree through the selected
// libnftables/kernel, rather than defining an expectation from the live listing.
// This small fixture is not the deployment's protected-policy qualification.
const reviewedKernelFixture = `
table inet reviewed_floor {
 set reserved_peers {
  type ipv4_addr; flags interval; size 16;
  elements = { 10.240.2.254, 10.241.0.0/24 }
 }
 map peer_map {
  type ipv4_addr : ipv6_addr; size 16;
  elements = { 10.250.0.20 : fdca:1a2b:2::20 }
 }
 counter flow_hits { }
 chain input { type filter hook input priority 0; policy drop; }
 chain output { type filter hook output priority 0; policy drop; }
 chain forward {
  type filter hook forward priority 0; policy drop;
  jump safety
  jump stateful
  counter drop
 }
 chain safety {
  ct state invalid drop
  ip daddr @reserved_peers drop
  return
 }
 chain stateful {
  ct state established counter name flow_hits accept
 }
}
`

func TestKernelReviewedRulesetInspection(t *testing.T) {
	requireKernelIsolation(t)
	t.Cleanup(func() { requireKernelIsolation(t) })
	ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
	defer cancel()
	contract := reviewedRulesetFixture(t)
	_, _, baseline, _ := renderFixture(t)
	layout, err := newGuardLayout(baseline)
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range layout.interfaces {
		packetIP(ctx, t, "link", "add", name, "type", "dummy")
		t.Cleanup(func() {
			cleanup, cancel := context.WithTimeout(context.WithoutCancel(t.Context()), 2*time.Second)
			defer cancel()
			packetIP(cleanup, t, "link", "delete", name)
		})
	}
	program, err := layout.program(ctx)
	if err != nil {
		t.Fatal(err)
	}
	packetNft(ctx, t, string(program)+reviewedKernelFixture)
	t.Cleanup(func() {
		cleanup, cancel := context.WithTimeout(context.WithoutCancel(t.Context()), 2*time.Second)
		defer cancel()
		packetNft(cleanup, t, "delete table inet reviewed_floor; delete table inet "+ownedTable+"; delete table netdev "+ownedTable)
	})
	process, err := openProcess(ctx, "/usr/sbin/nft")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := process.close(); err != nil {
			t.Error(err)
		}
	})
	observation, err := process.inspectRuleset(ctx, contract, layout)
	if err != nil {
		t.Fatalf("independently reviewed actual ruleset did not match: %v", err)
	}
	if observation.digest != contract.digest || observation.guards.leases != 0 {
		t.Fatal("actual empty guard and reviewed program identities differ")
	}
	before, err := process.execute(ctx, inspectWholeRuleset, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := process.inspectRuleset(ctx, contract, layout); err != nil {
		t.Fatal(err)
	}
	after, err := process.execute(ctx, inspectWholeRuleset, nil)
	if err != nil || !bytes.Equal(before, after) {
		t.Fatal("read-only complete inspection modified the actual ruleset")
	}
	for _, test := range []struct {
		name, mutation string
	}{
		{name: "early accept", mutation: "insert rule inet reviewed_floor forward accept"},
		{name: "protected set changed", mutation: "flush set inet reviewed_floor reserved_peers"},
		{name: "translator map changed", mutation: "delete element inet reviewed_floor peer_map { 10.250.0.20 }; add element inet reviewed_floor peer_map { 10.250.0.20 : fdca:1a2b:2::21 }"},
		{name: "order changed", mutation: "flush chain inet reviewed_floor forward; add rule inet reviewed_floor forward jump stateful; add rule inet reviewed_floor forward jump safety; add rule inet reviewed_floor forward counter drop"},
		{name: "hook changed", mutation: "delete chain inet reviewed_floor output; add chain inet reviewed_floor output { type filter hook output priority 1; policy drop; }"},
	} {
		t.Run(test.name, func(t *testing.T) {
			packetNft(ctx, t, test.mutation)
			if observation, err := process.inspectRuleset(ctx, contract, layout); err == nil || observation != nil {
				t.Fatal("actual protected-rule drift produced successful evidence")
			}
			packetNft(ctx, t, "delete table inet reviewed_floor; "+reviewedKernelFixture)
			if _, err := process.inspectRuleset(ctx, contract, layout); err != nil {
				t.Fatalf("explicit fixture restoration did not restore the reviewed program: %v", err)
			}
		})
	}
	packetNft(ctx, t, "add table inet unrelated_fixture")
	t.Cleanup(func() {
		cleanup, cancel := context.WithTimeout(context.WithoutCancel(t.Context()), 2*time.Second)
		defer cancel()
		packetNft(cleanup, t, "delete table inet unrelated_fixture")
	})
	before, err = process.execute(ctx, inspectWholeRuleset, nil)
	if err != nil {
		t.Fatal(err)
	}
	if observation, err := process.inspectRuleset(ctx, contract, layout); err == nil || observation != nil {
		t.Fatal("unreviewed actual table was silently ignored")
	}
	after, err = process.execute(ctx, inspectWholeRuleset, nil)
	if err != nil || !bytes.Equal(before, after) {
		t.Fatal("failed inspection changed unrelated or reviewed objects")
	}
}
