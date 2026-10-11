package policy

import (
	"bytes"
	"encoding/json"
	"net/netip"
	"testing"
)

func controllerBaseline() Baseline {
	baseline := testBaseline()
	baseline.ControllerInitiators = []ControllerInitiator{{
		ID: "synthetic-controller", SourceInterface: "lan10",
		Addresses: []netip.Addr{netip.MustParseAddr("10.240.0.10"), netip.MustParseAddr("fdca:1a2b::10")},
	}}
	return baseline
}

func TestControllerInitiatorValidation(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name   string
		mutate func(*Baseline)
	}{
		{name: "empty id", mutate: func(b *Baseline) { b.ControllerInitiators[0].ID = "" }},
		{name: "duplicate id", mutate: func(b *Baseline) {
			b.ControllerInitiators = append(b.ControllerInitiators, b.ControllerInitiators[0])
		}},
		{name: "no addresses", mutate: func(b *Baseline) { b.ControllerInitiators[0].Addresses = []netip.Addr{} }},
		{name: "unknown interface", mutate: func(b *Baseline) { b.ControllerInitiators[0].SourceInterface = "foreign0" }},
		{name: "unsafe interface", mutate: func(b *Baseline) { b.ControllerInitiators[0].SourceInterface = "lan10;accept" }},
		{name: "wrong source zone", mutate: func(b *Baseline) { b.ControllerInitiators[0].SourceInterface = "lan12" }},
		{name: "untrusted ingress", mutate: func(b *Baseline) { b.ControllerInitiators[0].SourceInterface = "lan13" }},
		{name: "security ingress", mutate: func(b *Baseline) { b.ControllerInitiators[0].SourceInterface = "lan14" }},
		{name: "assessment ingress", mutate: func(b *Baseline) { b.ControllerInitiators[0].SourceInterface = "lan15" }},
		{name: "duplicate source", mutate: func(b *Baseline) {
			b.ControllerInitiators[0].Addresses = append(b.ControllerInitiators[0].Addresses, b.ControllerInitiators[0].Addresses[0])
		}},
		{name: "loopback", mutate: func(b *Baseline) { b.ControllerInitiators[0].Addresses[0] = netip.MustParseAddr("127.0.0.1") }},
		{name: "broadcast", mutate: func(b *Baseline) { b.ControllerInitiators[0].Addresses[0] = netip.MustParseAddr("10.240.0.255") }},
		{name: "mapped address", mutate: func(b *Baseline) { b.ControllerInitiators[0].Addresses[0] = netip.MustParseAddr("::ffff:10.240.0.10") }},
		{name: "link local", mutate: func(b *Baseline) { b.ControllerInitiators[0].Addresses[1] = netip.MustParseAddr("fe80::10") }},
		{name: "zone id", mutate: func(b *Baseline) { b.ControllerInitiators[0].Addresses[1] = netip.MustParseAddr("fdca:1a2b::10%lan10") }},
		{name: "translator target geometry", mutate: func(b *Baseline) {
			b.Zones[3].Networks = append(b.Zones[3].Networks, b.NAT64[1].Prefix)
		}},
		{name: "too many profiles", mutate: func(b *Baseline) {
			b.ControllerInitiators = make([]ControllerInitiator, 9)
		}},
		{name: "one source family without targets", mutate: func(b *Baseline) {
			b.Zones[3].Networks = []netip.Prefix{netip.MustParsePrefix("fdca:1a2b:3::/64")}
		}},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			baseline := controllerBaseline()
			test.mutate(&baseline)
			if _, err := New(baseline); err == nil {
				t.Fatal("invalid controller root configuration was accepted")
			}
		})
	}
	if _, err := New(controllerBaseline()); err != nil {
		t.Fatal(err)
	}
}

func TestControllerInitiatorWireSchema(t *testing.T) {
	t.Parallel()
	data, err := json.Marshal(controllerBaseline())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := DecodeBaseline(data); err != nil {
		t.Fatal(err)
	}
	cases := []struct{ name, old, replacement string }{
		{name: "null address list", old: `"addresses":["10.240.0.10","fdca:1a2b::10"]`, replacement: `"addresses":null`},
		{name: "noncanonical key", old: `"source_interface"`, replacement: `"Source_Interface"`},
		{name: "directory-like override", old: `"source_interface":"lan10"`, replacement: `"source_interface":"lan10","destination_role":"security"`},
		{name: "source subnet", old: `"10.240.0.10"`, replacement: `"10.240.0.0/24"`},
		{name: "icmp null", old: `"source_interface":"lan10"`, replacement: `"source_interface":"lan10","icmp_enabled":null`},
		{name: "icmp string", old: `"source_interface":"lan10"`, replacement: `"source_interface":"lan10","icmp_enabled":"true"`},
		{name: "icmp key case", old: `"source_interface":"lan10"`, replacement: `"source_interface":"lan10","ICMP_Enabled":true`},
		{name: "null profile", old: `{"id":"synthetic-controller","source_interface":"lan10","addresses":["10.240.0.10","fdca:1a2b::10"]}`, replacement: `null`},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			changed := bytes.ReplaceAll(data, []byte(test.old), []byte(test.replacement))
			if bytes.Equal(changed, data) {
				t.Fatal("schema mutation did not change the fixture")
			}
			if _, err := DecodeBaseline(changed); err == nil {
				t.Fatal("malformed controller wire schema was accepted")
			}
		})
	}
}

func TestControllerInitiatorBaselineHash(t *testing.T) {
	t.Parallel()
	baseline := testBaseline()
	plain, err := New(baseline)
	if err != nil {
		t.Fatal(err)
	}
	baseline.ControllerInitiators = []ControllerInitiator{}
	empty, err := New(baseline)
	if err != nil {
		t.Fatal(err)
	}
	if empty.BaselineHash() != plain.BaselineHash() {
		t.Fatal("disabled optional controller capability changed the baseline hash")
	}
	withControllers, err := New(controllerBaseline())
	if err != nil {
		t.Fatal(err)
	}
	if withControllers.BaselineHash() == plain.BaselineHash() {
		t.Fatal("controller geometry was omitted from the root baseline identity")
	}
}
