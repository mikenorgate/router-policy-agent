package policy

import (
	"errors"
	"maps"
	"net/netip"
	"time"
)

const maximumLedgerEntries = 65536

func copyLedger(ledger Ledger) (Ledger, error) {
	if ledgerSize(ledger) > maximumLedgerEntries {
		return Ledger{}, errors.New("policy: durable ledger quota exceeded")
	}
	firstSeen := map[string]time.Time{}
	aliases := map[string]netip.Addr{}
	groups := map[string]bool{}
	maps.Copy(firstSeen, ledger.FirstSeen)
	maps.Copy(aliases, ledger.AliasPeers)
	maps.Copy(groups, ledger.NetworkGroups)
	return Ledger{LastValidated: ledger.LastValidated, FirstSeen: firstSeen, AliasPeers: aliases, NetworkGroups: groups}, nil
}

func ruleExpiry(groupID string, rule Rule, input Input, ledger *Ledger, leaseSeconds int) (time.Time, error) {
	expires := input.Directory.ObservedAt.Add(time.Duration(leaseSeconds) * time.Second)
	if rule.ExpiresAt == nil {
		return expires, nil
	}
	key := groupID + "/" + rule.ID
	first, exists := ledger.FirstSeen[key]
	if !exists {
		first = input.Now
		ledger.FirstSeen[key] = first
	}
	if first.IsZero() || first.After(input.Now) || rule.ExpiresAt.After(first.Add(7*24*time.Hour)) {
		return time.Time{}, errors.New("policy: temporary rule exceeds first-validation deadline")
	}
	if ledgerSize(*ledger) > maximumLedgerEntries {
		return time.Time{}, errors.New("policy: ledger quota exceeded")
	}
	return earliest(expires, *rule.ExpiresAt), nil
}

func anchorPeer(ledger *Ledger, groupID, ruleID, raw string, supplied, realPeer netip.Addr) bool {
	if supplied == realPeer {
		return true
	}
	key := groupID + "/" + ruleID + "/" + raw
	if prior, exists := ledger.AliasPeers[key]; exists {
		return prior == realPeer
	}
	if ledgerSize(*ledger) >= maximumLedgerEntries {
		return false
	}
	ledger.AliasPeers[key] = realPeer
	return true
}

func ledgerSize(ledger Ledger) int {
	return len(ledger.FirstSeen) + len(ledger.AliasPeers) + len(ledger.NetworkGroups)
}

func earliest(values ...time.Time) time.Time {
	var result time.Time
	for _, value := range values {
		if result.IsZero() || value.Before(result) {
			result = value
		}
	}
	return result
}
