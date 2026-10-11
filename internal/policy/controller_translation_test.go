package policy

import (
	"bytes"
	"encoding/json"
	"net/netip"
	"testing"
)

func translatedControllerBaseline() Baseline {
	baseline := controllerBaseline()
	source := netip.MustParseAddr("10.240.3.1")
	baseline.NAT46 = append(baseline.NAT46, NAT46{
		ID: "controller-map", Alias: netip.MustParseAddr("10.250.0.10"),
		Target: netip.MustParseAddr("fdca:1a2b::10"), Ready: true,
	})
	baseline.ControllerInitiators[0].NAT64Paths = []ControllerNAT64Path{{
		TranslatorID: "private64", Interface: "nat64-test", MappingIDs: []string{"controller-map"},
		PostroutingSource: &source,
	}}
	return baseline
}

func TestControllerNAT64PathValidation(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name   string
		mutate func(*Baseline)
	}{
		{name: "unknown translator", mutate: func(b *Baseline) { b.ControllerInitiators[0].NAT64Paths[0].TranslatorID = "missing" }},
		{name: "global translator", mutate: func(b *Baseline) { b.ControllerInitiators[0].NAT64Paths[0].TranslatorID = "global64" }},
		{name: "role interface", mutate: func(b *Baseline) { b.ControllerInitiators[0].NAT64Paths[0].Interface = "lan13" }},
		{name: "unsafe interface", mutate: func(b *Baseline) { b.ControllerInitiators[0].NAT64Paths[0].Interface = "tun;accept" }},
		{name: "no mappings", mutate: func(b *Baseline) { b.ControllerInitiators[0].NAT64Paths[0].MappingIDs = []string{} }},
		{name: "unknown mapping", mutate: func(b *Baseline) { b.ControllerInitiators[0].NAT64Paths[0].MappingIDs = []string{"missing"} }},
		{name: "another controller mapping", mutate: func(b *Baseline) { b.ControllerInitiators[0].NAT64Paths[0].MappingIDs = []string{"app46"} }},
		{name: "duplicate mapping", mutate: func(b *Baseline) {
			b.ControllerInitiators[0].NAT64Paths[0].MappingIDs = []string{"controller-map", "controller-map"}
		}},
		{name: "ambiguous source mapping", mutate: func(b *Baseline) {
			other := b.NAT46[len(b.NAT46)-1]
			other.ID, other.Alias = "controller-map-other", netip.MustParseAddr("10.250.0.11")
			b.NAT46 = append(b.NAT46, other)
			b.ControllerInitiators[0].NAT64Paths[0].MappingIDs = append(b.ControllerInitiators[0].NAT64Paths[0].MappingIDs, other.ID)
		}},
		{name: "conflicting interface", mutate: func(b *Baseline) {
			other := b.ControllerInitiators[0].NAT64Paths[0]
			other.Interface = "other-tun"
			b.ControllerInitiators[0].NAT64Paths = append(b.ControllerInitiators[0].NAT64Paths, other)
		}},
		{name: "security snat", mutate: func(b *Baseline) {
			*b.ControllerInitiators[0].NAT64Paths[0].PostroutingSource = netip.MustParseAddr("10.240.4.1")
		}},
		{name: "infrastructure snat", mutate: func(b *Baseline) {
			*b.ControllerInitiators[0].NAT64Paths[0].PostroutingSource = netip.MustParseAddr("10.240.2.1")
		}},
		{name: "broadcast snat", mutate: func(b *Baseline) {
			*b.ControllerInitiators[0].NAT64Paths[0].PostroutingSource = netip.MustParseAddr("10.240.3.255")
		}},
		{name: "alias snat", mutate: func(b *Baseline) {
			*b.ControllerInitiators[0].NAT64Paths[0].PostroutingSource = netip.MustParseAddr("10.250.0.10")
		}},
		{name: "ipv6 snat", mutate: func(b *Baseline) {
			*b.ControllerInitiators[0].NAT64Paths[0].PostroutingSource = netip.MustParseAddr("fdca:1a2b:3::10")
		}},
		{name: "public mapped source", mutate: func(b *Baseline) {
			b.NAT46Pools = append(b.NAT46Pools, netip.MustParsePrefix("93.184.216.0/24"))
			b.NAT46[len(b.NAT46)-1].Alias = netip.MustParseAddr("93.184.216.10")
		}},
		{name: "too many paths", mutate: func(b *Baseline) { b.ControllerInitiators[0].NAT64Paths = make([]ControllerNAT64Path, 5) }},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			baseline := translatedControllerBaseline()
			test.mutate(&baseline)
			if _, err := New(baseline); err == nil {
				t.Fatal("invalid translated controller root geometry was accepted")
			}
		})
	}
	for _, ready := range []bool{false, true} {
		baseline := translatedControllerBaseline()
		baseline.NAT46[len(baseline.NAT46)-1].Ready = ready
		if _, err := New(baseline); err != nil {
			t.Fatal(err)
		}
	}
}

func TestControllerNAT64WireSchema(t *testing.T) {
	t.Parallel()
	data, err := json.Marshal(translatedControllerBaseline())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := DecodeBaseline(data); err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct{ name, old, replacement string }{
		{name: "null paths", old: `"nat64_paths":[{"translator_id":"private64","interface":"nat64-test","mapping_ids":["controller-map"],"postrouting_source":"10.240.3.1"}]`, replacement: `"nat64_paths":null`},
		{name: "null mapping ids", old: `"mapping_ids":["controller-map"]`, replacement: `"mapping_ids":null`},
		{name: "noncanonical key", old: `"translator_id"`, replacement: `"Translator_Id"`},
		{name: "unbounded source", old: `"postrouting_source":"10.240.3.1"`, replacement: `"postrouting_source":"10.240.3.0/24"`},
		{name: "source null", old: `"postrouting_source":"10.240.3.1"`, replacement: `"postrouting_source":null`},
		{name: "role override", old: `"interface":"nat64-test"`, replacement: `"interface":"nat64-test","destination_role":"security"`},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			changed := bytes.ReplaceAll(data, []byte(test.old), []byte(test.replacement))
			if bytes.Equal(changed, data) {
				t.Fatal("translation wire mutation did not change the fixture")
			}
			if _, err := DecodeBaseline(changed); err == nil {
				t.Fatal("malformed translation wire configuration was accepted")
			}
		})
	}
}
