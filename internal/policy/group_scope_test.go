package policy

import (
	"encoding/json"
	"strings"
	"testing"
)

func scopeGroup(t *testing.T, id string, temporary bool, rules ...Rule) Group {
	t.Helper()
	group := accessGroup(t, id, temporary, rules...)
	raw := strings.Replace(*group.Policy, `"schema_version":1`, `"schema_version":2`, 1)
	group.Policy = &raw
	return group
}

func TestScopeGroupSchema(t *testing.T) {
	t.Parallel()
	rule := testRule()
	rule.Peer = Peer{Addresses: []string{"10.240.0.0/24", "fdca:1a2b::/64"}}
	rule.DestinationPorts = nil
	rule.DestinationPortRanges = []PortRange{{First: 1000, Last: 2000}}
	valid := *scopeGroup(t, "arbitrary-group", false, rule).Policy
	cases := []struct {
		name string
		raw  string
		ok   bool
	}{
		{name: "cidr and port range", raw: valid, ok: true},
		{name: "configured zone", raw: strings.Replace(valid, `"addresses":["10.240.0.0/24","fdca:1a2b::/64"]`, `"zones":["trusted","infrastructure"]`, 1), ok: true},
		{name: "internet", raw: strings.Replace(valid, `"addresses":["10.240.0.0/24","fdca:1a2b::/64"]`, `"internet":true`, 1), ok: true},
		{name: "all ports", raw: strings.Replace(valid, `"destination_port_ranges":[{"first":1000,"last":2000}]`, `"all_destination_ports":true`, 1), ok: true},
		{name: "old version rejects range", raw: strings.Replace(valid, `"schema_version":2`, `"schema_version":1`, 1)},
		{name: "unknown version", raw: strings.Replace(valid, `"schema_version":2`, `"schema_version":3`, 1)},
		{name: "host bits set", raw: strings.Replace(valid, `10.240.0.0/24`, `10.240.0.1/24`, 1)},
		{name: "default route is not internet", raw: strings.Replace(valid, `10.240.0.0/24`, `0.0.0.0/0`, 1)},
		{name: "duplicate selector", raw: strings.Replace(valid, `"peer":{`, `"peer":{"internet":true,`, 1)},
		{name: "unknown selector", raw: strings.Replace(valid, `"peer":{`, `"peer":{"raw_nft":"accept",`, 1)},
		{name: "duplicate peer", raw: strings.Replace(valid, `fdca:1a2b::/64`, `10.240.0.0/24`, 1)},
		{name: "range reversed", raw: strings.Replace(valid, `"first":1000`, `"first":2001`, 1)},
		{name: "range port zero", raw: strings.Replace(valid, `"first":1000`, `"first":0`, 1)},
		{name: "range unknown key", raw: strings.Replace(valid, `"first":1000`, `"ignored":1,"first":1000`, 1)},
		{name: "range duplicate key", raw: strings.Replace(valid, `"first":1000`, `"first":1000,"first":1000`, 1)},
		{name: "overlapping port list", raw: strings.Replace(valid, `"destination_port_ranges":`, `"destination_ports":[1000],"destination_port_ranges":`, 1)},
		{name: "all mixed with range", raw: strings.Replace(valid, `"destination_port_ranges":`, `"all_destination_ports":true,"destination_port_ranges":`, 1)},
		{name: "false is not all ports", raw: strings.Replace(valid, `"destination_port_ranges":[{"first":1000,"last":2000}]`, `"all_destination_ports":false`, 1)},
		{name: "null is not ports", raw: strings.Replace(valid, `[{"first":1000,"last":2000}]`, `null`, 1)},
		{name: "portless protocol has no zero port escape", raw: strings.Replace(valid, `"tcp"`, `"icmp"`, 1)},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			_, err := ParseGroup(test.raw)
			if (err == nil) != test.ok {
				t.Fatalf("accepted = %v, want %v: %v", err == nil, test.ok, err)
			}
		})
	}
}

func TestScopeSelectorEmptyAndUnknownValues(t *testing.T) {
	t.Parallel()
	for _, peer := range []Peer{{}, {Zones: []Role{"other"}}, {Zones: []Role{Trusted, Trusted}}} {
		rule := testRule()
		rule.Peer = peer
		if _, err := ParseGroup(*scopeGroup(t, "group", false, rule).Policy); err == nil {
			t.Fatalf("accepted empty/unknown selector: %+v", peer)
		}
	}
	valid := *scopeGroup(t, "group", false, testRule()).Policy
	var document map[string]json.RawMessage
	if err := json.Unmarshal([]byte(valid), &document); err != nil {
		t.Fatal(err)
	}
	for _, peer := range []string{`{"internet":false}`, `{"internet":null}`, `{"zones":[]}`, `{"addresses":null}`} {
		raw := strings.Replace(valid, `{"addresses":["fdca:1a2b::10/128"]}`, peer, 1)
		if _, err := ParseGroup(raw); err == nil {
			t.Fatalf("accepted empty selector: %s", peer)
		}
	}
}
