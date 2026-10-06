package policy

import (
	"strings"
	"testing"
)

func TestParseGroup(t *testing.T) {
	t.Parallel()
	valid := *accessGroup(t, "access", false, testRule()).Policy
	tests := []struct {
		name      string
		raw       string
		wantError bool
	}{
		{name: "access", raw: valid},
		{name: "placement", raw: `{"schema_version":1,"kind":"placement","vlan_role":"security"}`},
		{name: "duplicate", raw: strings.Replace(valid, `"kind":"access"`, `"kind":"access","kind":"access"`, 1), wantError: true},
		{name: "security access", raw: strings.Replace(valid, `"untrusted"`, `"security"`, 1), wantError: true},
		{name: "unknown key", raw: strings.Replace(valid, `"temporary":false`, `"temporary":false,"allow_security":true`, 1), wantError: true},
		{name: "wrong case", raw: strings.Replace(valid, `"temporary"`, `"Temporary"`, 1), wantError: true},
		{name: "missing false", raw: strings.Replace(valid, `"temporary":false,`, "", 1), wantError: true},
		{name: "null", raw: strings.Replace(valid, `"temporary":false`, `"temporary":null`, 1), wantError: true},
		{name: "subnet", raw: strings.Replace(valid, `/128`, `/64`, 1), wantError: true},
		{name: "tcp port zero", raw: strings.Replace(valid, `[6053]`, `[0]`, 1), wantError: true},
		{name: "overflow", raw: strings.Replace(valid, `[6053]`, `[65536]`, 1), wantError: true},
		{name: "duplicate port", raw: strings.Replace(valid, `[6053]`, `[6053,6053]`, 1), wantError: true},
		{name: "any protocol", raw: strings.Replace(valid, `"tcp"`, `"any"`, 1), wantError: true},
		{name: "expiry on permanent", raw: strings.Replace(valid, `"reason":`, `"expires_at":"2026-01-01T13:00:00Z","reason":`, 1), wantError: true},
		{name: "temporary missing expiry", raw: strings.Replace(valid, `"temporary":false`, `"temporary":true`, 1), wantError: true},
		{name: "oversize", raw: strings.Repeat(" ", AttributeLimit) + valid, wantError: true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			_, err := ParseGroup(test.raw)
			if (err != nil) != test.wantError {
				t.Fatalf("ParseGroup error = %v; want error %v", err, test.wantError)
			}
		})
	}
}

func TestParseHost(t *testing.T) {
	t.Parallel()
	for _, raw := range []string{"10.240.3.10/32", "fdca:1a2b:3::10/128", "9.9.9.9/32"} {
		if _, err := ParseHost(raw); err != nil {
			t.Errorf("valid host rejected: %s: %v", raw, err)
		}
	}
	for _, raw := range []string{"10.240.3.0/24", "fdca:1a2b:3::10/64", "::ffff:10.240.3.10/128",
		"::1/128", "fe80::1/128", "ff02::1/128", "127.0.0.1/32", "0.0.0.0/32", "192.0.2.1/32",
		"2001:db8::1/128", "FDCA:1A2B:3::10/128", "fdca:1a2b:3:0:0:0:0:10/128"} {
		if _, err := ParseHost(raw); err == nil {
			t.Errorf("invalid host accepted: %s", raw)
		}
	}
}

func TestCanonicalMAC(t *testing.T) {
	t.Parallel()
	for _, raw := range []string{"020000000001", "02-00-00-00-00-01", "02:00:00:00:00:01"} {
		mac, err := CanonicalMAC(raw)
		if err != nil || mac != "02:00:00:00:00:01" {
			t.Errorf("CanonicalMAC(%q) = %q, %v", raw, mac, err)
		}
	}
	for _, raw := range []string{"ff:ff:ff:ff:ff:ff", "01:00:00:00:00:01", "00:00:00:00:00:00", "not a mac"} {
		if _, err := CanonicalMAC(raw); err == nil {
			t.Errorf("invalid MAC accepted: %s", raw)
		}
	}
}

func FuzzParseGroup(f *testing.F) {
	f.Add(`{"schema_version":1,"kind":"placement","vlan_role":"untrusted"}`)
	f.Add(`{"schema_version":1,"schema_version":2}`)
	f.Fuzz(func(_ *testing.T, input string) {
		if len(input) <= AttributeLimit+1 {
			_, _ = ParseGroup(input)
		}
	})
}
