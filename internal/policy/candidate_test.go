package policy

import (
	"context"
	"net/netip"
	"testing"
	"time"
)

func TestCheckCandidate(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name   string
		change func(*Candidate)
	}{
		{name: "different baseline", change: func(c *Candidate) { c.BaselineHash = "different" }},
		{name: "missing binding generation", change: func(c *Candidate) { c.BindingGeneration = "" }},
		{name: "missing compilation time", change: func(c *Candidate) { c.CompiledAt = time.Time{} }},
		{name: "noncanonical mac", change: func(c *Candidate) { c.Grants[0].MAC = "020000000001" }},
		{name: "invalid device identity", change: func(c *Candidate) { c.Grants[0].DeviceID = "../device" }},
		{name: "invalid protocol", change: func(c *Candidate) { c.Grants[0].Protocol = "icmp" }},
		{name: "invalid direction", change: func(c *Candidate) { c.Grants[0].Direction = "reply" }},
		{name: "zero port", change: func(c *Candidate) { c.Grants[0].Port = 0 }},
		{name: "wrong vlan", change: func(c *Candidate) { c.Grants[0].VLAN = 14 }},
		{name: "wrong interface", change: func(c *Candidate) { c.Grants[0].Interface = "lan14" }},
		{name: "missing counterparts", change: func(c *Candidate) { c.Grants[0].Device.Variants = nil }},
		{name: "unexpected counterpart", change: func(c *Candidate) {
			c.Grants[0].Peer.Variants = append(c.Grants[0].Peer.Variants, netip.MustParseAddr("fdca:1a2b::20"))
		}},
		{name: "security peer", change: func(c *Candidate) {
			peer := netip.MustParseAddr("fdca:1a2b:4::10")
			c.Grants[0].Peer = Endpoint{Real: peer, Variants: []netip.Addr{peer}}
		}},
		{name: "isolated peer", change: func(c *Candidate) {
			peer := netip.MustParseAddr("10.241.0.10")
			c.Grants[0].Peer = Endpoint{Real: peer, Variants: []netip.Addr{
				peer, netip.MustParseAddr("fdca:1a2b:64::af1:a"),
			}}
		}},
		{name: "resolver bypass", change: func(c *Candidate) { c.Grants[0].Port = 53 }},
		{name: "missing contributors", change: func(c *Candidate) { c.Grants[0].Contributors = nil }},
		{name: "excess contributors", change: func(c *Candidate) {
			c.Grants[0].Contributors = make([]Contributor, 513)
		}},
		{name: "invalid contributor", change: func(c *Candidate) {
			c.Grants[0].Contributors[0].GroupID = ""
		}},
		{name: "expired contributor", change: func(c *Candidate) {
			c.Grants[0].Contributors[0].ExpiresAt = testNow
		}},
		{name: "extended deadline", change: func(c *Candidate) {
			c.Grants[0].Contributors[0].ExpiresAt = testNow.Add(91 * time.Second)
		}},
		{name: "excess grants", change: func(c *Candidate) { c.Grants = make([]Grant, 16385) }},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			compiler := testCompiler(t, testBaseline())
			candidate, err := compiler.CompileContext(t.Context(), testInput(t))
			if err != nil {
				t.Fatal(err)
			}
			if err := compiler.CheckCandidate(t.Context(), candidate); err != nil {
				t.Fatalf("rejected independently compiled fixture: %v", err)
			}
			test.change(&candidate)
			if err := compiler.CheckCandidate(t.Context(), candidate); err == nil {
				t.Fatal("accepted altered candidate outside the helper floor")
			}
		})
	}
}

func TestCandidateCheckContextAndFingerprint(t *testing.T) {
	t.Parallel()
	compiler := testCompiler(t, testBaseline())
	candidate, err := compiler.CompileContext(t.Context(), testInput(t))
	if err != nil || compiler.BaselineHash() != candidate.BaselineHash {
		t.Fatalf("compiler fingerprint differs: %v", err)
	}
	var missing *Compiler
	if missing.BaselineHash() != "" || missing.CheckCandidate(t.Context(), candidate) == nil {
		t.Fatal("missing compiler accepted a candidate")
	}
	//nolint:staticcheck // Deliberately corrupt context tests the rejection boundary.
	if err := compiler.CheckCandidate(nil, candidate); err == nil {
		t.Fatal("missing context accepted a candidate")
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if err := compiler.CheckCandidate(ctx, candidate); err == nil {
		t.Fatal("canceled candidate check succeeded")
	}
}
