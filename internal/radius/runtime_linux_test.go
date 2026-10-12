package radius

import (
	"encoding/json"
	"strings"
	"testing"
)

func runtimeFixture() []byte {
	return []byte(`{"schema_version":1,"mode":"shadow","radius_user":"daemon","nas_prefixes":["192.0.2.0/24"],"kea_user":"nobody","kea_socket":"/run/kea/kea4-ctrl-socket","subnet_id":22,"ipv4_prefix":"198.51.100.0/24","vlan":22,"maximum_devices":16,"output_directory":"/var/lib/router-policy-radius-shadow"}`)
}

func TestRuntimeConfigStrictShadowOnly(t *testing.T) {
	t.Parallel()
	if _, err := decodeRuntimeConfig(runtimeFixture()); err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		key   string
		value any
	}{
		{"mode", "enforce"}, {"schema_version", 2}, {"radius_user", "root"}, {"kea_user", "user\n"},
		{"nas_prefixes", []string{}}, {"nas_prefixes", []string{"192.0.2.1/24"}},
		{"nas_prefixes", []string{"192.0.2.0/24", "192.0.2.0/24"}},
		{"kea_socket", "/run/kea/../kea/socket"}, {"ipv4_prefix", "2001:db8::/64"},
		{"subnet_id", 0}, {"vlan", 4095}, {"maximum_devices", 257},
		{"output_directory", "/"}, {"output_directory", "/var/\nprivate"},
		{"helper_socket", "/run/privileged-helper"},
	} {
		t.Run(test.key, func(t *testing.T) {
			t.Parallel()
			values := map[string]any{}
			if err := json.Unmarshal(runtimeFixture(), &values); err != nil {
				t.Fatal(err)
			}
			values[test.key] = test.value
			data, err := json.Marshal(values)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := decodeRuntimeConfig(data); err == nil {
				t.Fatal("unsafe runtime configuration admitted")
			}
		})
	}
	for _, data := range [][]byte{
		[]byte(strings.Replace(string(runtimeFixture()), `"mode":"shadow"`, `"mode":"shadow","mode":"shadow"`, 1)),
		append(runtimeFixture(), []byte("{}")...), []byte("{}"), []byte("null"),
	} {
		if _, err := decodeRuntimeConfig(data); err == nil {
			t.Fatal("ambiguous or incomplete configuration admitted")
		}
	}
}

func TestRuntimeServiceNamesAndRootRejection(t *testing.T) {
	t.Parallel()
	for _, name := range []string{"", "root", "0", "daemon;id", "UPPER", strings.Repeat("a", 33)} {
		if localUser(name) {
			t.Fatal("untrusted service name admitted")
		}
	}
	if _, err := serviceUID("root"); err == nil {
		t.Fatal("root service identity admitted")
	}
}
