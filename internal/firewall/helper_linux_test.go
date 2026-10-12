package firewall

import (
	"strconv"
	"testing"
)

func TestHelperRequiresExactSupervisorEnvironment(t *testing.T) {
	t.Parallel()
	for _, test := range []struct {
		name, key, value string
		valid            bool
	}{
		{name: "valid", valid: true},
		{name: "reversed order", key: "LISTEN_FDNAMES", value: "status:requests", valid: true},
		{name: "foreign process", key: "LISTEN_PID", value: "1235"},
		{name: "missing process", key: "LISTEN_PID", value: ""},
		{name: "missing socket", key: "LISTEN_FDS", value: "1"},
		{name: "extra socket", key: "LISTEN_FDS", value: "3"},
		{name: "duplicate name", key: "LISTEN_FDNAMES", value: "requests:requests"},
		{name: "unnamed", key: "LISTEN_FDNAMES", value: ""},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			environment := map[string]string{"LISTEN_PID": strconv.Itoa(1234), "LISTEN_FDS": "2", "LISTEN_FDNAMES": "requests:status"}
			if test.key != "" {
				environment[test.key] = test.value
			}
			request, status, got := activationEnvironment(1234, func(key string) string { return environment[key] })
			if got != test.valid {
				t.Fatal("supervisor environment validation differs")
			}
			if got && (request == status || request < 3 || request > 4 || status < 3 || status > 4) {
				t.Fatal("supervisor descriptor selection differs")
			}
		})
	}
}
