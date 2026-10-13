//go:build integration && kernel && linux

package firewall

import (
	"context"
	"encoding/json"
	"net/netip"
	"testing"
	"time"

	"github.com/mikenorgate/router-policy-agent/internal/state"
)

func TestKernelCompactInternetLeaseExpires(t *testing.T) {
	requireKernelIsolation(t)
	t.Cleanup(func() { requireKernelIsolation(t) })
	ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
	defer cancel()
	backend, _ := setupBackendPacketFixture(ctx, t)
	batch := internetPacketBatch(t, netip.MustParseAddr("fdca:1a2b:3::10"), backend.options.profile.baseline)
	// Shorten only this synthetic kernel fixture; never extend an authorization.
	changes, err := decodeGuardChanges(batch)
	if err != nil {
		t.Fatal(err)
	}
	for _, command := range changes.Commands {
		if command.Add == nil {
			continue
		}
		values := &command.Add.Element
		if values.Name == cohortSet || values.Name == classified4Set || values.Name == classified6Set {
			continue
		}
		for index, raw := range values.Values {
			var element struct {
				Element struct {
					Value   json.RawMessage `json:"val"`
					Timeout int             `json:"timeout"`
				} `json:"elem"`
			}
			if err := json.Unmarshal(raw, &element); err != nil {
				t.Fatal(err)
			}
			element.Element.Timeout = 1
			encoded, err := json.Marshal(element)
			if err != nil {
				t.Fatal(err)
			}
			values.Values[index] = encoded
		}
	}
	batch, err = json.Marshal(changes)
	if err != nil {
		t.Fatal(err)
	}
	if err := validateGuardBatch(ctx, batch); err != nil {
		t.Fatal(err)
	}
	applyGuardFixture(ctx, t, batch)
	inventory, err := backend.options.executor.inspectGuards(ctx, backend.options.profile.layout)
	if err != nil || inventory.leases == 0 {
		t.Fatalf("Internet fixture has no leases before expiry: %v", err)
	}
	time.Sleep(1500 * time.Millisecond)
	inventory, err = backend.options.executor.inspectGuards(ctx, backend.options.profile.layout)
	if err != nil || inventory.leases != 0 || len(inventory.cohort) == 0 {
		t.Fatalf("Internet expiry retained permissions or lost deny classification: %v", err)
	}
}

func TestKernelInternetGeometryDriftStillAllowsSeal(t *testing.T) {
	requireKernelIsolation(t)
	t.Cleanup(func() { requireKernelIsolation(t) })
	ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
	defer cancel()
	backend, _ := setupBackendPacketFixture(ctx, t)
	layout := backend.options.profile.layout
	applyGuardFixture(ctx, t, internetPacketBatch(t, netip.MustParseAddr("fdca:1a2b:3::10"), backend.options.profile.baseline))
	inventory, err := backend.options.executor.inspectGuards(ctx, layout)
	if err != nil || inventory.leases == 0 {
		t.Fatalf("Internet fixture has no leases before drift: %v", err)
	}
	packetNft(ctx, t, "flush set inet "+ownedTable+" internet_excluded4")
	if _, err := backend.options.executor.inspectGuards(ctx, layout); err == nil {
		t.Fatal("changed exclusions were accepted for authorization")
	}
	if err := backend.seal(ctx, state.EmptyClassification()); err != nil {
		t.Fatalf("exclusion drift prevented permit revocation: %v", err)
	}
	data, err := backend.options.executor.run(ctx, commandInput{op: inspectWholeRuleset})
	if err != nil {
		t.Fatal(err)
	}
	sealed, history, err := inspectSealingGuards(ctx, layout, data)
	if err != nil || sealed.leases != 0 || len(history.MACs) == 0 {
		t.Fatalf("sealing lost classification or retained leases: %v", err)
	}
}
