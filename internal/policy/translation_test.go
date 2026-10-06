package policy

import (
	"net/netip"
	"slices"
	"testing"
)

func TestResolve(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name      string
		address   string
		real      string
		variants  int
		wantError bool
	}{
		{name: "native private ipv4", address: "10.240.3.10", real: "10.240.3.10", variants: 2},
		{name: "private64", address: "fdca:1a2b:64::af0:30a", real: "10.240.3.10", variants: 2},
		{name: "global64", address: "64:ff9b::909:909", real: "9.9.9.9", variants: 2},
		{name: "nat46", address: "10.250.0.20", real: "fdca:1a2b:2::20", variants: 3},
		{name: "nat64 of nat46", address: "fdca:1a2b:64::afa:14", real: "fdca:1a2b:2::20", variants: 3},
		{name: "native nat46 service", address: "fdca:1a2b:2::20", real: "fdca:1a2b:2::20", variants: 3},
		{name: "private WKP", address: "64:ff9b::af0:30a", wantError: true},
		{name: "CGNAT WKP", address: "64:ff9b::6440:1", wantError: true},
		{name: "global private prefix", address: "fdca:1a2b:64::909:909", wantError: true},
		{name: "unmapped alias", address: "10.250.0.99", wantError: true},
		{name: "loopback", address: "::1", wantError: true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			address := netip.MustParseAddr(test.address)
			endpoint, err := Resolve(testBaseline(), address)
			if (err != nil) != test.wantError {
				t.Fatalf("Resolve error = %v; want error %v", err, test.wantError)
			}
			if err == nil && (endpoint.Real.String() != test.real || len(endpoint.Variants) != test.variants ||
				!slices.Contains(endpoint.Variants, address)) {
				t.Fatalf("unexpected resolution: %+v", endpoint)
			}
		})
	}
}

func TestResolveInvalidCatalog(t *testing.T) {
	t.Parallel()
	for _, mutate := range []func(*Baseline){
		func(b *Baseline) { b.NAT64[0].Prefix = netip.Prefix{} },
		func(b *Baseline) { b.NAT64[0].Scope = "private" },
		func(b *Baseline) { b.NAT64[0].Prefix = netip.MustParsePrefix("::ffff:0:0/96") },
		func(b *Baseline) { b.NAT46[0].Ready = false },
		func(b *Baseline) { b.NAT46[0].Target = netip.MustParseAddr("fdca:1a2b:64::af0:30a") },
	} {
		baseline := testBaseline()
		mutate(&baseline)
		if _, err := Resolve(baseline, netip.MustParseAddr("10.250.0.20")); err == nil {
			t.Error("invalid or unready catalog accepted")
		}
	}
}

func FuzzResolve(f *testing.F) {
	f.Add("10.250.0.20")
	f.Add("64:ff9b::af0:30a")
	f.Fuzz(func(t *testing.T, raw string) {
		address, err := netip.ParseAddr(raw)
		if err != nil {
			return
		}
		endpoint, err := Resolve(testBaseline(), address)
		if err == nil {
			for _, variant := range endpoint.Variants {
				resolved, err := Resolve(testBaseline(), variant)
				if err != nil || resolved.Real != endpoint.Real {
					t.Fatalf("variant changes real identity: %+v", endpoint)
				}
			}
		}
	})
}
