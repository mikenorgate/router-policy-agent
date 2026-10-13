//go:build linux

package ipc

import "testing"

func TestObservationProtocolRejectsAuthority(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name, input string
		valid       bool
	}{
		{"read", `{"schema_version":1,"operation":"observations","generation":"","offset":0}`, true},
		{"mutate", `{"schema_version":1,"operation":"reset","generation":"","offset":0}`, false},
		{"clock", `{"schema_version":1,"operation":"observations","generation":"","offset":0,"clock":1}`, false},
		{"unbound page", `{"schema_version":1,"operation":"observations","generation":"","offset":128}`, false},
		{"duplicate", `{"schema_version":1,"operation":"observations","generation":"","offset":0,"offset":128}`, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := decodeObservationRequest([]byte(tc.input))
			if (err == nil) != tc.valid {
				t.Fatal(err)
			}
		})
	}
}
