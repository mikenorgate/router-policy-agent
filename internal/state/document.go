// Package state retains revocation anchors and managed identity, never permits.
package state

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/netip"
	"slices"
	"time"

	"github.com/mikenorgate/router-policy-agent/internal/policy"
	"github.com/mikenorgate/router-policy-agent/internal/strictjson"
)

// MaximumSize bounds the on-disk envelope before allocation or decoding.
const MaximumSize = 16 << 20

const maximumCohort = 4096

// Document is helper-owned security state. Losing a directory account or a
// binding must not remove its cohort classification and expose legacy allows.
// ClassifiedIPv4/IPv6 are historical deny-only representations, not ownership.
// DirectoryHash binds an observation time to exactly one complete snapshot.
type Document struct {
	SchemaVersion           int           `json:"schema_version"`
	CohortMACs              []string      `json:"cohort_macs"`
	ClassifiedIPv4          []string      `json:"classified_ipv4"`
	ClassifiedIPv6          []string      `json:"classified_ipv6"`
	Ledger                  policy.Ledger `json:"ledger"`
	LastDirectoryObservedAt time.Time     `json:"last_directory_observed_at"`
	DirectoryHash           string        `json:"directory_hash"`
}

// Initial is for explicit first installation, not automatic recovery after
// missing or corrupt state. Runtime startup must not silently call it.
func Initial() Document {
	return Document{
		SchemaVersion: 2, CohortMACs: []string{}, ClassifiedIPv4: []string{}, ClassifiedIPv6: []string{},
		Ledger: policy.Ledger{
			FirstSeen: map[string]time.Time{}, AliasPeers: map[string]netip.Addr{}, NetworkGroups: map[string]bool{},
		},
	}
}

// Clone validates the bounded state and returns independently owned data.
func Clone(document Document) (Document, error) {
	if document.SchemaVersion != 2 {
		return Document{}, errors.New("state: unsupported durable schema")
	}
	classification, err := CloneClassification(Classification{
		MACs: document.CohortMACs, IPv4: document.ClassifiedIPv4, IPv6: document.ClassifiedIPv6,
	})
	if err != nil {
		return Document{}, err
	}
	ledger, err := policy.CloneLedger(document.Ledger)
	if err != nil {
		return Document{}, err
	}
	cohort := classification.MACs
	if document.LastDirectoryObservedAt.IsZero() {
		hasClassification := len(cohort)+len(classification.IPv4)+len(classification.IPv6) != 0
		if document.DirectoryHash != "" || !ledger.LastValidated.IsZero() || hasClassification {
			return Document{}, errors.New("state: inconsistent initial observation")
		}
	} else {
		digest, err := hex.DecodeString(document.DirectoryHash)
		isValidDigest := err == nil && len(digest) == sha256.Size && hex.EncodeToString(digest) == document.DirectoryHash
		if !isValidDigest || document.LastDirectoryObservedAt.After(ledger.LastValidated) {
			return Document{}, errors.New("state: inconsistent directory watermark")
		}
	}
	return Document{SchemaVersion: 2, CohortMACs: cohort,
		ClassifiedIPv4: classification.IPv4, ClassifiedIPv6: classification.IPv6, Ledger: ledger,
		LastDirectoryObservedAt: document.LastDirectoryObservedAt, DirectoryHash: document.DirectoryHash}, nil
}

// Decode requires exact keys and valid durable state, without reader-controlled
// commands, paths, current ownership claims or persisted firewall grants.
func Decode(data []byte) (Document, error) {
	keys := []string{"schema_version", "cohort_macs", "classified_ipv4", "classified_ipv6",
		"ledger", "last_directory_observed_at", "directory_hash"}
	if err := strictjson.Object(data, keys, nil, MaximumSize); err != nil {
		return Document{}, err
	}
	object := map[string]json.RawMessage{}
	if err := strictjson.Decode(data, &object, MaximumSize); err != nil {
		return Document{}, err
	}
	ledgerKeys := []string{"last_validated", "first_seen", "alias_peers", "network_groups"}
	if err := strictjson.Object(object["ledger"], ledgerKeys, nil, MaximumSize); err != nil {
		return Document{}, err
	}
	var document Document
	if err := strictjson.Decode(data, &document, MaximumSize); err != nil {
		return Document{}, err
	}
	return Clone(document)
}

// CheckDirectory rejects observations older than an already processed decision,
// including after restart. Repeating an identical snapshot does not change its
// original lease; changing data at the same observation time is ambiguous.
func CheckDirectory(document Document, snapshot policy.DirectorySnapshot) (string, error) {
	if _, err := Clone(document); err != nil {
		return "", err
	}
	if !snapshot.Complete || snapshot.ObservedAt.IsZero() || snapshot.ObservedAt.Before(document.LastDirectoryObservedAt) {
		return "", errors.New("state: incomplete or replayed directory snapshot")
	}
	data, err := json.Marshal(snapshot)
	if err != nil || len(data) > MaximumSize {
		return "", errors.New("state: invalid directory digest input")
	}
	digest := sha256.Sum256(data)
	hash := hex.EncodeToString(digest[:])
	if snapshot.ObservedAt.Equal(document.LastDirectoryObservedAt) && hash != document.DirectoryHash {
		return "", errors.New("state: conflicting directory snapshot at same observation time")
	}
	return hash, nil
}

// Advance combines a successfully compiled helper-owned ledger with a checked
// snapshot. All known device identities remain classified, even when inactive,
// unbound or absent from later snapshots. This is not an admission decision.
func Advance(document Document, snapshot policy.DirectorySnapshot, ledger policy.Ledger) (Document, error) {
	hash, err := CheckDirectory(document, snapshot)
	if err != nil {
		return Document{}, err
	}
	cohort := slices.Clone(document.CohortMACs)
	for _, device := range snapshot.Devices {
		cohort = append(cohort, device.MAC)
	}
	slices.Sort(cohort)
	cohort = slices.Compact(cohort)
	result, err := Clone(Document{SchemaVersion: 2, CohortMACs: cohort,
		ClassifiedIPv4: document.ClassifiedIPv4, ClassifiedIPv6: document.ClassifiedIPv6, Ledger: ledger,
		LastDirectoryObservedAt: snapshot.ObservedAt, DirectoryHash: hash})
	if err != nil {
		return Document{}, err
	}
	if err := CheckTransition(document, result); err != nil {
		return Document{}, err
	}
	return result, nil
}

// CheckTransition prevents erasing guards or moving immutable anchors during a
// normal refresh. Any deliberate retirement/reset needs a separate reviewed
// administrative operation; the reader protocol has no such operation.
func CheckTransition(previous, next Document) error {
	for _, document := range []Document{previous, next} {
		if _, err := Clone(document); err != nil {
			return err
		}
	}
	isClockRollback := next.Ledger.LastValidated.Before(previous.Ledger.LastValidated)
	isDirectoryRollback := next.LastDirectoryObservedAt.Before(previous.LastDirectoryObservedAt)
	isConflictingObservation := next.LastDirectoryObservedAt.Equal(previous.LastDirectoryObservedAt) &&
		next.DirectoryHash != previous.DirectoryHash
	if isClockRollback || isDirectoryRollback || isConflictingObservation {
		return errors.New("state: durable observation rollback")
	}
	for _, mac := range previous.CohortMACs {
		if _, exists := slices.BinarySearch(next.CohortMACs, mac); !exists {
			return errors.New("state: managed cohort cannot shrink")
		}
	}
	for family, addresses := range [][]string{previous.ClassifiedIPv4, previous.ClassifiedIPv6} {
		nextAddresses := next.ClassifiedIPv4
		if family == 1 {
			nextAddresses = next.ClassifiedIPv6
		}
		for _, address := range addresses {
			if _, exists := slices.BinarySearch(nextAddresses, address); !exists {
				return errors.New("state: historical address classification cannot shrink")
			}
		}
	}
	for key, first := range previous.Ledger.FirstSeen {
		if !next.Ledger.FirstSeen[key].Equal(first) {
			return errors.New("state: temporary first-validation anchor cannot change")
		}
	}
	for key, peer := range previous.Ledger.AliasPeers {
		if next.Ledger.AliasPeers[key] != peer {
			return errors.New("state: alias ownership anchor cannot change")
		}
	}
	for id := range previous.Ledger.NetworkGroups {
		if !next.Ledger.NetworkGroups[id] {
			return errors.New("state: known network classification cannot disappear")
		}
	}
	return nil
}
