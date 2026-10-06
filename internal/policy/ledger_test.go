package policy

import (
	"net/netip"
	"testing"
	"time"
)

func validLedger() Ledger {
	return Ledger{LastValidated: testNow, FirstSeen: map[string]time.Time{"group/rule": testNow},
		AliasPeers:    map[string]netip.Addr{"group/rule/10.250.0.20/32": netip.MustParseAddr("fdca:1a2b:2::20")},
		NetworkGroups: map[string]bool{"group": true}}
}

func TestCloneLedger(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name   string
		mutate func(*Ledger)
	}{
		{name: "missing clock", mutate: func(l *Ledger) { l.LastValidated = time.Time{} }},
		{name: "invalid first seen key", mutate: func(l *Ledger) { l.FirstSeen["invalid"] = testNow }},
		{name: "zero first seen", mutate: func(l *Ledger) { l.FirstSeen["group/rule"] = time.Time{} }},
		{name: "future first seen", mutate: func(l *Ledger) { l.FirstSeen["group/rule"] = testNow.Add(time.Second) }},
		{name: "invalid alias key", mutate: func(l *Ledger) { l.AliasPeers["invalid"] = netip.MustParseAddr("10.240.2.1") }},
		{name: "invalid alias host", mutate: func(l *Ledger) {
			l.AliasPeers["group/rule/not-an-address/32"] = netip.MustParseAddr("10.240.2.1")
		}},
		{name: "invalid real peer", mutate: func(l *Ledger) {
			l.AliasPeers["group/rule/10.250.0.20/32"] = netip.MustParseAddr("::1")
		}},
		{name: "lost classification", mutate: func(l *Ledger) { l.NetworkGroups["group"] = false }},
		{name: "invalid network key", mutate: func(l *Ledger) { l.NetworkGroups["invalid/key"] = true }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			ledger := validLedger()
			test.mutate(&ledger)
			if _, err := CloneLedger(ledger); err == nil {
				t.Fatal("invalid durable ledger accepted")
			}
		})
	}
	ledger := validLedger()
	cloned, err := CloneLedger(ledger)
	if err != nil {
		t.Fatal(err)
	}
	delete(cloned.FirstSeen, "group/rule")
	if len(ledger.FirstSeen) != 1 {
		t.Fatal("copied ledger shares mutable storage")
	}
}
