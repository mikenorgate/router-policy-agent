package firewall

import (
	"strings"
	"testing"
)

func TestControllerICMPIsRootOptIn(t *testing.T) {
	t.Parallel()
	for _, test := range []struct {
		name    string
		enabled bool
	}{
		{name: "absent disabled"}, {name: "enabled", enabled: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			layout := translatedControllerLayout(t, true, test.enabled)
			rules := strings.Join(layout.controllerICMPForwardRules("return", false), "\n")
			if !test.enabled {
				if rules != "" || len(layout.controllerICMPEgressExpressions("lan13")) != 0 {
					t.Fatal("ICMP authority appeared without explicit root opt-in")
				}
				return
			}
			for _, match := range []string{
				"icmp type echo-request", "icmpv6 type echo-reply", "ct state related",
				"ct original ip saddr 10.250.0.10", "ct original ip daddr 10.240.3.0/24",
				"ct original ip6 saddr fdca:1a2b::10", "ct protocol { tcp, udp }",
			} {
				if !strings.Contains(rules, match) {
					t.Fatalf("ICMP guard lacks required exact condition %q", match)
				}
			}
			if strings.Contains(rules, "redirect") || strings.Contains(rules, "neighbor") {
				t.Fatal("controller ICMP admitted unrelated control-plane traffic")
			}
		})
	}
}
