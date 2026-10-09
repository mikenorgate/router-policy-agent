package radius

import (
	"bytes"
	"context"
	"errors"
	"net/netip"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/mikenorgate/router-policy-agent/internal/kea"
)

func fixtureCollectorOptions() CollectorOptions {
	return CollectorOptions{
		Journal: JournalOptions{ServiceUID: 123, NASPrefixes: fixtureScope().NASPrefixes, Timeout: time.Second},
		Kea: kea.Options{Socket: "/run/synthetic-kea/control.sock", Timeout: time.Second,
			SubnetID: 22, Prefix: netip.MustParsePrefix("192.0.2.0/24")},
		VLAN: 22, MaximumDevices: 16, Timeout: 10 * time.Second,
	}
}

func fixtureCapturedHistory(t testing.TB) history {
	t.Helper()
	return history{data: fixtureHistory(t, fixtureEvent("Start", 0), fixtureEvent("Alive", 60)),
		scope: fixtureScope(), observedAt: fixtureTime().Add(75 * time.Second)}
}

func TestCollectIPv4RechecksBothSourcesWithoutRefreshingEvidence(t *testing.T) {
	t.Parallel()
	trace := []string{}
	captured := fixtureCapturedHistory(t)
	lease := fixtureLeaseObservation()
	leaseReads := 0
	result, err := collectIPv4(t.Context(), fixtureCollectorOptions(), collectionSources{
		history: func(context.Context) (history, error) {
			trace = append(trace, "history")
			return captured, nil
		},
		lease: func(_ context.Context, mac string) (kea.Observation, error) {
			trace = append(trace, "lease")
			leaseReads++
			if mac != "02:aa:bb:cc:dd:ee" {
				t.Fatal("MAC was not canonical")
			}
			fresh := lease
			if leaseReads == 2 {
				fresh.ObservedAt = fresh.ObservedAt.Add(time.Second)
			}
			return fresh, nil
		},
		now: func() time.Time { return captured.observedAt },
	})
	if err != nil || len(result.Candidates) != 1 || result.Withheld != 0 || len(result.Generation) != 64 {
		t.Fatalf("stable collection failed: %v", err)
	}
	if !slices.Equal(trace, []string{"history", "lease", "history", "lease", "history"}) {
		t.Fatalf("source ordering changed: %v", trace)
	}
	candidate := result.Candidates[0]
	if candidate.LeaseObservedAt != lease.ObservedAt || candidate.LeaseUpdatedAt != lease.Leases[0].UpdatedAt ||
		candidate.LeaseValidUntil != lease.Leases[0].ValidUntil || candidate.Session.ObservedAt != fixtureTime().Add(60*time.Second) ||
		candidate.ValidUntil != fixtureTime().Add(150*time.Second) {
		t.Fatal("recheck refreshed original evidence bounds")
	}
}

func TestCollectIPv4WithholdsObservedSourceRaces(t *testing.T) {
	t.Parallel()
	for _, name := range []string{"initial source loss", "middle source loss", "final source loss", "initial lease loss",
		"recheck lease loss", "stop in middle", "stop at end", "roam", "heartbeat advanced", "history removed", "history rewritten",
		"boot changed", "scope changed", "lease reassigned", "lease renewed", "lease missing", "stale final evidence", "clock reversed"} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			original := fixtureCapturedHistory(t)
			historyReads, leaseReads, clockReads := 0, 0, 0
			result, err := collectIPv4(t.Context(), fixtureCollectorOptions(), collectionSources{
				history: func(context.Context) (history, error) {
					historyReads++
					loss := name == "initial source loss" && historyReads == 1 ||
						name == "middle source loss" && historyReads == 2 || name == "final source loss" && historyReads == 3
					if loss {
						return history{}, errors.New("synthetic unavailable source")
					}
					captured := original
					if historyReads > 1 {
						switch name {
						case "stop in middle":
							captured.data = append(bytes.Clone(original.data), fixtureHistory(t, fixtureEvent("Stop", 74))...)
						case "stop at end":
							if historyReads == 3 {
								captured.data = append(bytes.Clone(original.data), fixtureHistory(t, fixtureEvent("Stop", 74))...)
							}
						case "roam":
							roam := fixtureEvent("Start", 74)
							roam.SessionSeconds, roam.SessionIDHex = "0", "73657373696f6e2d32"
							captured.data = append(bytes.Clone(original.data), fixtureHistory(t, roam)...)
						case "heartbeat advanced":
							captured.data = append(bytes.Clone(original.data), fixtureHistory(t, fixtureEvent("Alive", 74))...)
						case "history removed":
							captured.data = fixtureHistory(t, fixtureEvent("Alive", 60))
						case "history rewritten":
							captured.data = bytes.ReplaceAll(original.data, []byte("synthetic-local"), []byte("replacement-local"))
						case "boot changed":
							captured.scope.BootID = strings.Repeat("f", 32)
						case "scope changed":
							captured.scope.ServiceUID++
						}
					}
					return captured, nil
				},
				lease: func(context.Context, string) (kea.Observation, error) {
					leaseReads++
					if name == "initial lease loss" || name == "recheck lease loss" && leaseReads == 2 {
						return kea.Observation{}, errors.New("synthetic lease unavailable")
					}
					lease := fixtureLeaseObservation()
					if name == "lease missing" {
						lease.Leases = []kea.Lease{}
					}
					if leaseReads == 2 {
						switch name {
						case "lease reassigned":
							lease.Leases[0].MAC = "02AABBCCDDFF"
						case "lease renewed":
							lease.Leases[0].UpdatedAt = lease.Leases[0].UpdatedAt.Add(time.Minute)
						}
					}
					return lease, nil
				},
				now: func() time.Time {
					clockReads++
					if name == "stale final evidence" && clockReads >= 5 {
						return fixtureTime().Add(150 * time.Second)
					}
					if name == "clock reversed" && clockReads > 1 {
						return original.observedAt.Add(-time.Second)
					}
					return original.observedAt
				},
			})
			if err == nil || len(result.Candidates) != 0 || !result.ObservedAt.IsZero() || result.Generation != "" {
				t.Fatal("source race or failure produced a partial collection")
			}
		})
	}
}

func TestCollectIPv4EmptyAndDuplicateOwners(t *testing.T) {
	t.Parallel()
	for _, name := range []string{"empty", "duplicate owner", "quota"} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			captured := fixtureCapturedHistory(t)
			options := fixtureCollectorOptions()
			if name == "empty" {
				captured.data = []byte{}
			} else {
				secondStart, secondInterim := fixtureEvent("Start", 0), fixtureEvent("Alive", 60)
				secondStart.MAC, secondInterim.MAC = "02AABBCCDDFF", "02AABBCCDDFF"
				secondStart.SessionIDHex, secondInterim.SessionIDHex = "73657373696f6e2d32", "73657373696f6e2d32"
				captured.data = fixtureHistory(t, fixtureEvent("Start", 0), secondStart, fixtureEvent("Alive", 60), secondInterim)
			}
			if name == "quota" {
				options.MaximumDevices = 1
			}
			result, err := collectIPv4(t.Context(), options, collectionSources{
				history: func(context.Context) (history, error) { return captured, nil },
				lease: func(_ context.Context, mac string) (kea.Observation, error) {
					if name == "empty" || name == "quota" {
						t.Fatal("unexpected lease query")
					}
					lease := fixtureLeaseObservation()
					lease.Leases[0].MAC = mac
					return lease, nil
				},
				now: func() time.Time { return captured.observedAt },
			})
			if name == "empty" {
				if err != nil || result.Candidates == nil || len(result.Candidates) != 0 || result.Generation == "" {
					t.Fatal("empty source granted or failed")
				}
			} else if err == nil || len(result.Candidates) != 0 {
				t.Fatal("ambiguous or oversized cohort accepted")
			}
		})
	}
}

func TestCollectorRejectsInvalidOptionsAndCancellation(t *testing.T) {
	t.Parallel()
	for _, name := range []string{"valid", "budget", "quota", "vlan", "prefix", "socket", "journal timeout", "nas scope"} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			options := fixtureCollectorOptions()
			switch name {
			case "budget":
				options.Timeout = 31 * time.Second
			case "quota":
				options.MaximumDevices = 257
			case "vlan":
				options.VLAN = 4095
			case "prefix":
				options.Kea.Prefix = netip.MustParsePrefix("2001:db8::/64")
			case "socket":
				options.Kea.Socket = "relative.sock"
			case "journal timeout":
				options.Journal.Timeout = 0
			case "nas scope":
				options.Journal.NASPrefixes = []netip.Prefix{}
			}
			if validCollectorOptions(options) != (name == "valid") {
				t.Fatal("local options validation failed")
			}
		})
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	sources := collectionSources{
		history: func(context.Context) (history, error) {
			t.Fatal("cancelled operation queried history")
			return history{}, nil
		},
		lease: func(context.Context, string) (kea.Observation, error) {
			t.Fatal("cancelled operation queried leases")
			return kea.Observation{}, nil
		},
		now: time.Now,
	}
	if _, err := collectIPv4(ctx, fixtureCollectorOptions(), sources); !errors.Is(err, context.Canceled) {
		t.Fatal("cancellation ignored")
	}
	if _, err := collectIPv4(t.Context(), fixtureCollectorOptions(), collectionSources{}); err == nil {
		t.Fatal("nil dependencies accepted")
	}
}

func TestJournalArgumentsAndOutputBounds(t *testing.T) {
	t.Parallel()
	arguments := journalArguments(fixtureScope())
	for _, forbidden := range []string{"--lines", "--reverse", "--follow", "--file", "--directory", "--merge", "--machine", "--since", "--after-cursor"} {
		for _, argument := range arguments {
			if strings.HasPrefix(argument, forbidden) {
				t.Fatal("partial or alternate journal source admitted")
			}
		}
	}
	for _, required := range []string{"--system", "--all", "--no-pager", "--output=json", "--boot=" + fixtureBoot,
		"--grep=^" + marker, "_SYSTEMD_UNIT=freeradius.service", "SYSLOG_IDENTIFIER=freeradius", "_UID=123"} {
		if !slices.Contains(arguments, required) {
			t.Fatal("missing fixed journal scope")
		}
	}
	output := journalOutput{maximum: 4}
	for _, value := range []string{"abc", "def", "gh"} {
		if n, err := output.Write([]byte(value)); err != nil || n != len(value) {
			t.Fatal("output was not drained")
		}
	}
	if !output.exceeded || output.buffer.String() != "abcd" {
		t.Fatal("output quota retained too much or missed overflow")
	}
	invalid := journalOutput{}
	if _, err := invalid.Write([]byte("x")); err == nil {
		t.Fatal("zero quota accepted")
	}
}

func TestCanonicalJournalHistoryPreservesEvidenceAndEntryOrder(t *testing.T) {
	t.Parallel()
	input := []byte("{\"z\":\"first\", \"a\":9007199254740993}\n{\"z\":\"second\",\"a\":2}\n")
	original := bytes.Clone(input)
	result, err := canonicalHistory(input)
	want := []byte("{\"a\":9007199254740993,\"z\":\"first\"}\n{\"a\":2,\"z\":\"second\"}\n")
	if err != nil || !bytes.Equal(result, want) || !bytes.Equal(input, original) {
		t.Fatalf("journal normalization changed evidence: %v", err)
	}
	if again, err := canonicalHistory(want); err != nil || !bytes.Equal(again, result) {
		t.Fatal("equivalent object ordering changed normalized history")
	}
	if empty, err := canonicalHistory(nil); err != nil || len(empty) != 0 {
		t.Fatal("empty history rejected or fabricated")
	}
	for _, data := range [][]byte{
		[]byte("{\"a\":1}"),
		[]byte("{\"a\":1,\"a\":2}\n"),
		[]byte("null\n"),
		[]byte("[]\n"),
		[]byte("{\"a\":{\"b\":1,\"b\":2}}\n"),
		[]byte("{\"a\":\"" + strings.Repeat("x", maximumEntry) + "\"}\n"),
		bytes.Repeat([]byte("{}\n"), maximumEvents+1),
	} {
		if result, err := canonicalHistory(data); err == nil || len(result) != 0 {
			t.Fatal("ambiguous, partial or oversized journal normalized as complete")
		}
	}
}
