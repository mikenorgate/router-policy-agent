package policy

import (
	"errors"
	"maps"
	"net/netip"
	"strings"
	"time"
)

const maximumLedgerEntries = 65536

func copyLedger(ledger Ledger) (Ledger, error) {
	if ledgerSize(ledger) > maximumLedgerEntries {
		return Ledger{}, errors.New("policy: durable ledger quota exceeded")
	}
	if ledger.LastValidated.IsZero() && ledgerSize(ledger) != 0 {
		return Ledger{}, errors.New("policy: ledger entries require a validated clock")
	}
	for key, first := range ledger.FirstSeen {
		parts := strings.Split(key, "/")
		isValidKey := len(parts) == 2 && identifier.MatchString(parts[0]) && identifier.MatchString(parts[1])
		if !isValidKey || first.IsZero() || first.After(ledger.LastValidated) {
			return Ledger{}, errors.New("policy: invalid first-validation ledger entry")
		}
	}
	for key, peer := range ledger.AliasPeers {
		parts := strings.Split(key, "/")
		isValidKey := len(parts) == 4 && identifier.MatchString(parts[0]) && identifier.MatchString(parts[1])
		if !isValidKey || !validAddress(peer) {
			return Ledger{}, errors.New("policy: invalid alias ledger entry")
		}
		if _, err := ParseHost(parts[2] + "/" + parts[3]); err != nil {
			return Ledger{}, errors.New("policy: invalid alias ledger key")
		}
	}
	for id, isNetwork := range ledger.NetworkGroups {
		if !identifier.MatchString(id) || !isNetwork {
			return Ledger{}, errors.New("policy: invalid network-group ledger entry")
		}
	}
	firstSeen := map[string]time.Time{}
	aliases := map[string]netip.Addr{}
	groups := map[string]bool{}
	maps.Copy(firstSeen, ledger.FirstSeen)
	maps.Copy(aliases, ledger.AliasPeers)
	maps.Copy(groups, ledger.NetworkGroups)
	return Ledger{LastValidated: ledger.LastValidated, FirstSeen: firstSeen, AliasPeers: aliases, NetworkGroups: groups}, nil
}

// CloneLedger validates and copies durable compiler state without sharing maps.
// Persisted deadlines and alias anchors are not editable reader inputs.
func CloneLedger(ledger Ledger) (Ledger, error) {
	return copyLedger(ledger)
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
