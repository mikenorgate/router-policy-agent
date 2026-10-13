package firewall

import "testing"

func TestOptionalObservationActivation(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		names, count              string
		request, status, observer uintptr
		valid                     bool
	}{
		{"requests:status", "2", 3, 4, 0, true},
		{"observations:requests:status", "3", 4, 5, 3, true},
		{"status:observations:requests", "3", 5, 3, 4, true},
		{"requests:status:observations", "3", 3, 4, 5, true},
		{"requests:requests:observations", "3", 0, 0, 0, false},
		{"requests:status:writer", "3", 0, 0, 0, false},
	} {
		env := map[string]string{"LISTEN_PID": "42", "LISTEN_FDS": tc.count, "LISTEN_FDNAMES": tc.names}
		request, status, observer, valid := helperActivationEnvironment(42, func(key string) string { return env[key] })
		if request != tc.request || status != tc.status || observer != tc.observer || valid != tc.valid {
			t.Fatalf("incorrect activation for %s", tc.names)
		}
	}
}
