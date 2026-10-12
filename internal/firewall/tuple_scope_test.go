package firewall

import (
	"encoding/json"
	"net/netip"
	"strings"
	"testing"
	"time"
)

func TestTupleIntervalsStrictBoundary(t *testing.T) {
	t.Parallel()
	const template = `{"concat":["lan13","02:00:00:00:00:01","fdca:1a2b:3::10",PEER,PORT]}`
	for _, test := range []struct {
		name, peer, port string
		valid            bool
	}{
		{name: "legacy host", peer: `"fdca:1a2b::10"`, port: `6053`, valid: true},
		{name: "prefix and ports", peer: `{"prefix":{"addr":"fdca:1a2b::","len":64}}`, port: `{"range":[1,65535]}`, valid: true},
		{name: "noncanonical prefix", peer: `{"prefix":{"addr":"fdca:1a2b::1","len":64}}`, port: `6053`},
		{name: "duplicate prefix key", peer: `{"prefix":{"addr":"fdca:1a2b::","len":64,"len":80}}`, port: `6053`},
		{name: "host prefix object", peer: `{"prefix":{"addr":"fdca:1a2b::10","len":128}}`, port: `6053`},
		{name: "default route prefix", peer: `{"prefix":{"addr":"::","len":0}}`, port: `6053`},
		{name: "wrong family", peer: `{"prefix":{"addr":"10.240.0.0","len":24}}`, port: `6053`},
		{name: "v4 mapped", peer: `{"prefix":{"addr":"::ffff:10.240.0.0","len":120}}`, port: `6053`},
		{name: "address range", peer: `{"range":["fdca:1a2b::10","fdca:1a2b::20"]}`, port: `6053`},
		{name: "raw nft expression", peer: `{"accept":null}`, port: `6053`},
		{name: "singleton range", peer: `"fdca:1a2b::10"`, port: `{"range":[6053,6053]}`},
		{name: "reverse range", peer: `"fdca:1a2b::10"`, port: `{"range":[6054,6053]}`},
		{name: "zero range", peer: `"fdca:1a2b::10"`, port: `{"range":[0,65535]}`},
		{name: "overflow", peer: `"fdca:1a2b::10"`, port: `{"range":[1,65536]}`},
		{name: "fraction", peer: `"fdca:1a2b::10"`, port: `{"range":[1,2.5]}`},
		{name: "extra port metadata", peer: `"fdca:1a2b::10"`, port: `{"range":[1,10],"comment":"extra"}`},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			raw := strings.ReplaceAll(strings.ReplaceAll(template, "PEER", test.peer), "PORT", test.port)
			key, err := validateTuple([]byte(raw), false)
			if (err == nil) != test.valid {
				t.Fatalf("valid=%t; got %v", test.valid, err)
			}
			if !test.valid {
				return
			}
			encoded, err := renderTuple(key, 90*time.Second)
			if err != nil {
				t.Fatal(err)
			}
			checked, err := validateLeasedTuple(encoded, false)
			if err != nil || checked != key {
				t.Fatalf("typed interval did not round-trip: %v", err)
			}
		})
	}
	for _, index := range []int{0, 1, 2} {
		var value struct {
			Concat []any `json:"concat"`
		}
		if err := json.Unmarshal([]byte(strings.ReplaceAll(strings.ReplaceAll(template, "PEER", `"fdca:1a2b::10"`), "PORT", "6053")), &value); err != nil {
			t.Fatal(err)
		}
		value.Concat[index] = map[string]any{"range": []string{"a", "z"}}
		raw, err := json.Marshal(value)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := validateTuple(raw, false); err == nil {
			t.Fatalf("identity field %d admitted an interval", index)
		}
	}
}

func TestTupleIntervalsRejectOverlapWithoutEnumeration(t *testing.T) {
	t.Parallel()
	key := tupleKey{interfaceName: "lan13", mac: "02:00:00:00:00:01",
		device: netip.MustParseAddr("fdca:1a2b:3::10"), peer: netip.MustParseAddr("fdca:1a2b::"),
		peerNetwork: netip.MustParsePrefix("fdca:1a2b::/64"), port: 6000, portEnd: 6100}
	for _, test := range []struct {
		name  string
		edit  func(*tupleKey)
		valid bool
	}{
		{name: "duplicate", edit: func(*tupleKey) {}},
		{name: "contained host", edit: func(k *tupleKey) { k.peerNetwork = netip.Prefix{}; k.peer = netip.MustParseAddr("fdca:1a2b::10") }},
		{name: "contained subnet", edit: func(k *tupleKey) { k.peerNetwork = netip.MustParsePrefix("fdca:1a2b::/80") }},
		{name: "port endpoint", edit: func(k *tupleKey) { k.port, k.portEnd = 6100, 6200 }},
		{name: "different ports", valid: true, edit: func(k *tupleKey) { k.port, k.portEnd = 6101, 6200 }},
		{name: "different network", valid: true, edit: func(k *tupleKey) {
			k.peer, k.peerNetwork = netip.MustParseAddr("fdca:1a2b:1::"), netip.MustParsePrefix("fdca:1a2b:1::/64")
		}},
		{name: "different MAC", valid: true, edit: func(k *tupleKey) { k.mac = "02:00:00:00:00:02" }},
		{name: "different device", valid: true, edit: func(k *tupleKey) { k.device = netip.MustParseAddr("fdca:1a2b:3::11") }},
		{name: "different interface", valid: true, edit: func(k *tupleKey) { k.interfaceName = "lan14" }},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			other := key
			test.edit(&other)
			for _, keys := range [][]tupleKey{{key, other}, {other, key}} {
				if err := validateDisjointTuples(keys); (err == nil) != test.valid {
					t.Fatalf("valid=%t; got %v", test.valid, err)
				}
			}
		})
	}
}

func TestInventoryIntervalsAndMirrorDrift(t *testing.T) {
	t.Parallel()
	layout, listings := guardListingFixture(t, true)
	for _, data := range []*[]byte{&listings.inet, &listings.netdev} {
		*data = []byte(strings.ReplaceAll(strings.ReplaceAll(string(*data), `"fdca:1a2b::10"`,
			`{"prefix":{"addr":"fdca:1a2b::","len":64}}`), `6053`, `{"range":[6053,6060]}`))
	}
	if _, err := layout.inspect(t.Context(), listings); err != nil {
		t.Fatal(err)
	}
	listings.netdev = []byte(strings.ReplaceAll(string(listings.netdev), `"range":[6053,6060]`, `"range":[6053,6061]`))
	if inventory, err := layout.inspect(t.Context(), listings); err == nil || inventory != nil {
		t.Fatal("final-MAC interval widening was accepted")
	}
}

func TestBatchRejectsIntervalOverlap(t *testing.T) {
	t.Parallel()
	var changes guardChanges
	if err := json.Unmarshal(leasedBatch(t), &changes); err != nil {
		t.Fatal(err)
	}
	grant := &changes.Commands[len(changes.Commands)-1].Add.Element
	grant.Values = append(grant.Values, []byte(strings.ReplaceAll(string(grant.Values[0]), `"fdca:1a2b::10"`,
		`{"prefix":{"addr":"fdca:1a2b::","len":64}}`)))
	data, err := json.Marshal(changes)
	if err != nil {
		t.Fatal(err)
	}
	if err := validateBatch(data); err == nil {
		t.Fatal("overlapping host and prefix leases were accepted")
	}
}

func FuzzScopedTuple(f *testing.F) {
	f.Add([]byte(`{"concat":["lan13","02:00:00:00:00:01","fdca:1a2b:3::10",{"prefix":{"addr":"fdca:1a2b::","len":64}},{"range":[1,65535]}]}`), false)
	f.Add([]byte(`{"concat":["lan13","02:00:00:00:00:01","10.240.3.10",{"prefix":{"addr":"10.240.0.0","len":24}},{"range":[80,443]}]}`), true)
	f.Add([]byte(`{"concat":["lan13","02:00:00:00:00:01","10.240.3.10","10.240.0.10",6053]}`), true)
	f.Fuzz(func(t *testing.T, raw []byte, ipv4 bool) {
		key, err := validateTuple(raw, ipv4)
		if err != nil {
			return
		}
		encoded, err := renderTuple(key, 90*time.Second)
		if err != nil {
			t.Fatal(err)
		}
		checked, err := validateLeasedTuple(encoded, ipv4)
		if err != nil || checked != key || key.port == 0 || key.lastPort() < key.port {
			t.Fatalf("accepted interval did not survive canonical bounded encoding: %v", err)
		}
	})
}
