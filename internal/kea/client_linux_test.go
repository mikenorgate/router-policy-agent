package kea

import (
	"encoding/json"
	"net/netip"
	"strings"
	"testing"
	"time"
)

const fixtureMAC = "02AABBCCDDEE"

func fixtureOptions() Options {
	return Options{
		Socket: "/run/synthetic-kea/control.sock", Timeout: time.Second, SubnetID: 22,
		Prefix: netip.MustParsePrefix("192.0.2.0/24"),
	}
}

func fixtureLease() map[string]any {
	return map[string]any{
		"ip-address": "192.0.2.80", "hw-address": "02:aa:bb:cc:dd:ee", "subnet-id": 22,
		"state": 0, "cltt": 1760000000, "valid-lft": 3600,
		"client-id": "01:02:aa:bb:cc:dd:ee", "hostname": "synthetic.invalid",
		"fqdn-fwd": false, "fqdn-rev": false,
	}
}

func fixtureResponse(t *testing.T, leases ...map[string]any) []byte {
	t.Helper()
	data, err := json.Marshal(map[string]any{
		"result": 0, "text": "synthetic lease response",
		"arguments": map[string]any{"leases": leases},
	})
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func TestDecodeLeasesPreservesRenewalAndExpiry(t *testing.T) {
	t.Parallel()
	now := time.Unix(1760000600, 0).UTC()
	leases, err := decodeLeases(fixtureResponse(t, fixtureLease()), fixtureOptions(), fixtureMAC, now)
	if err != nil || len(leases) != 1 {
		t.Fatalf("valid lease: %v", err)
	}
	lease := leases[0]
	if lease.MAC != fixtureMAC || lease.IP.String() != "192.0.2.80" || lease.SubnetID != 22 {
		t.Fatal("ownership changed")
	}
	if lease.UpdatedAt.Unix() != 1760000000 || lease.ValidUntil.Unix() != 1760003600 {
		t.Fatal("query refreshed the original renewal or expiry")
	}
	newer, err := decodeLeases(fixtureResponse(t, fixtureLease()), fixtureOptions(), fixtureMAC, now.Add(time.Minute))
	if err != nil || len(newer) != 1 || newer[0] != lease {
		t.Fatal("reread refreshed a lease")
	}
}

func TestDecodeLeasesWithholdsInvalidEvidence(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name  string
		key   string
		value any
	}{
		{name: "new owner", key: "hw-address", value: "02:aa:bb:cc:dd:ff"},
		{name: "multicast owner", key: "hw-address", value: "01:aa:bb:cc:dd:ee"},
		{name: "other vlan", key: "subnet-id", value: 11},
		{name: "other prefix", key: "ip-address", value: "198.51.100.80"},
		{name: "mapped address", key: "ip-address", value: "::ffff:192.0.2.80"},
		{name: "ipv6 address", key: "ip-address", value: "2001:db8::80"},
		{name: "future renewal", key: "cltt", value: 1760000601},
		{name: "zero renewal", key: "cltt", value: 0},
		{name: "negative renewal", key: "cltt", value: -1},
		{name: "overflow renewal", key: "cltt", value: uint64(1) << 32},
		{name: "overflow lifetime", key: "valid-lft", value: uint64(1) << 32},
		{name: "fractional lifetime", key: "valid-lft", value: 90.5},
		{name: "string lifetime", key: "valid-lft", value: "90"},
		{name: "unknown state", key: "state", value: 99},
		{name: "missing state", key: "state", value: nil},
		{name: "unknown field", key: "allow", value: true},
		{name: "case variant", key: "State", value: 0},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			lease := fixtureLease()
			lease[test.key] = test.value
			if leases, err := decodeLeases(fixtureResponse(t, lease), fixtureOptions(), fixtureMAC, time.Unix(1760000600, 0)); err == nil || len(leases) != 0 {
				t.Fatal("invalid ownership produced evidence")
			}
		})
	}
}

func TestDecodeLeasesInactiveOrAbsent(t *testing.T) {
	t.Parallel()
	for _, name := range []string{"declined", "reclaimed", "zero lifetime", "expired", "expiry boundary", "absent"} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			lease := fixtureLease()
			now := time.Unix(1760000600, 0)
			switch name {
			case "declined":
				lease["state"] = 1
			case "reclaimed":
				lease["state"] = 2
			case "zero lifetime":
				lease["valid-lft"] = 0
			case "expired":
				now = time.Unix(1760003601, 0)
			case "expiry boundary":
				now = time.Unix(1760003600, 0)
			}
			data := fixtureResponse(t, lease)
			if name == "absent" {
				data = []byte(`{"result":3,"text":"not found","arguments":{"leases":[]}}`)
			}
			leases, err := decodeLeases(data, fixtureOptions(), fixtureMAC, now)
			if err != nil || leases == nil || len(leases) != 0 {
				t.Fatalf("absent/inactive lease not an empty observation: %v", err)
			}
		})
	}
}

func TestDecodeLeasesRejectsAmbiguousOrPartialResponses(t *testing.T) {
	t.Parallel()
	valid := fixtureResponse(t, fixtureLease())
	duplicate := fixtureResponse(t, fixtureLease(), fixtureLease())
	invalid := fixtureLease()
	invalid["hw-address"] = "02:aa:bb:cc:dd:ff"
	partial := fixtureResponse(t, fixtureLease(), invalid)
	excess := make([]map[string]any, maximumLeases+1)
	for index := range excess {
		excess[index] = fixtureLease()
	}
	cases := []struct {
		name string
		data []byte
	}{
		{name: "duplicate address", data: duplicate},
		{name: "partial success", data: partial},
		{name: "lease quota", data: fixtureResponse(t, excess...)},
		{name: "error text private", data: []byte(`{"result":1,"text":"do-not-return-this-payload"}`)},
		{name: "unsupported", data: []byte(`{"result":2}`)},
		{name: "missing result", data: []byte(`{"arguments":{"leases":[]}}`)},
		{name: "case variant result", data: []byte(`{"Result":0,"arguments":{"leases":[]}}`)},
		{name: "null result", data: []byte(`{"result":null}`)},
		{name: "no list", data: []byte(`{"result":0}`)},
		{name: "empty success", data: []byte(`{"result":0,"arguments":{"leases":[]}}`)},
		{name: "empty with lease", data: []byte(strings.Replace(string(valid), `"result":0`, `"result":3`, 1))},
		{name: "duplicate key", data: []byte(`{"result":3,"result":0}`)},
		{name: "unknown field", data: []byte(`{"result":3,"allow":true}`)},
		{name: "control agent array", data: append(append([]byte("["), valid...), ']')},
		{name: "trailing value", data: append(append([]byte{}, valid...), []byte("{}")...)},
		{name: "truncated", data: valid[:len(valid)-1]},
		{name: "oversized", data: []byte(strings.Repeat(" ", maximumResponse+1))},
		{name: "deep nesting", data: []byte(`{"result":3,"arguments":` + strings.Repeat("[", 40) + `0` + strings.Repeat("]", 40) + `}`)},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			leases, err := decodeLeases(test.data, fixtureOptions(), fixtureMAC, time.Unix(1760000600, 0))
			if err == nil || len(leases) != 0 || strings.Contains(err.Error(), "do-not-return-this-payload") {
				t.Fatal("invalid response produced evidence or leaked daemon text")
			}
		})
	}
}

func TestMACAndOptions(t *testing.T) {
	t.Parallel()
	for _, input := range []string{fixtureMAC, "02aabbccddee", "02:aa:bb:cc:dd:ee"} {
		mac, hardware, err := canonicalMAC(input)
		if err != nil || mac != fixtureMAC || hardware != "02:aa:bb:cc:dd:ee" {
			t.Fatal("valid mac rejected")
		}
	}
	for _, input := range []string{"", "000000000000", "FFFFFFFFFFFF", "01aabbccddee", `02aabbccddee"}`, "02-aa-bb-cc-dd-ee"} {
		if _, _, err := canonicalMAC(input); err == nil {
			t.Fatal("invalid mac accepted")
		}
	}
	for _, name := range []string{"valid", "relative", "unclean", "abstract", "long", "zero timeout", "long timeout", "zero subnet", "v6", "unmasked"} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			options := fixtureOptions()
			switch name {
			case "relative":
				options.Socket = "relative.sock"
			case "unclean":
				options.Socket = "/run/kea/../control.sock"
			case "abstract":
				options.Socket = "\x00kea"
			case "long":
				options.Socket = "/" + strings.Repeat("s", 107)
			case "zero timeout":
				options.Timeout = 0
			case "long timeout":
				options.Timeout = 11 * time.Second
			case "zero subnet":
				options.SubnetID = 0
			case "v6":
				options.Prefix = netip.MustParsePrefix("2001:db8::/64")
			case "unmasked":
				options.Prefix = netip.MustParsePrefix("192.0.2.80/24")
			}
			if validOptions(options) != (name == "valid") {
				t.Fatal("unexpected local options validation")
			}
		})
	}
	//nolint:staticcheck // Deliberately test rejection of a missing context at the public boundary.
	if _, err := ReadIPv4(nil, fixtureOptions(), fixtureMAC); err == nil {
		t.Fatal("nil context accepted")
	}
}

func FuzzDecodeLeases(f *testing.F) {
	f.Add([]byte(`{"result":3,"arguments":{"leases":[]}}`))
	f.Add([]byte(`{"result":0,"arguments":{"leases":[{"ip-address":"192.0.2.80","hw-address":"02:aa:bb:cc:dd:ee","subnet-id":22,"state":0,"cltt":1760000000,"valid-lft":3600}]}}`))
	f.Fuzz(func(t *testing.T, data []byte) {
		leases, err := decodeLeases(data, fixtureOptions(), fixtureMAC, time.Unix(1760000600, 0))
		if err != nil && len(leases) != 0 {
			t.Fatal("partial evidence on error")
		}
		for _, lease := range leases {
			if lease.MAC != fixtureMAC || !fixtureOptions().Prefix.Contains(lease.IP) || !lease.ValidUntil.After(lease.UpdatedAt) {
				t.Fatal("invalid ownership on success")
			}
		}
	})
}
