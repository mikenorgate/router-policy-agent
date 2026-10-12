package firewall

import (
	"bytes"
	"context"
	"encoding/json"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/mikenorgate/router-policy-agent/internal/binding"
	"github.com/mikenorgate/router-policy-agent/internal/policy"
	"github.com/mikenorgate/router-policy-agent/internal/state"
)

// The binding is deliberately synthetic. Production must obtain this evidence
// independently; neither an account attribute nor a saved classifier supplies it.
func translatedDeviceGrantFixture(t *testing.T, ready, active, hasBinding bool, scoped ...bool) (*guardLayout, *preparedBatch) {
	t.Helper()
	_, _, _, input := renderFixture(t)
	baseline := translatedControllerBaseline(t, ready, false)
	renderer, err := newRenderer(baseline)
	if err != nil {
		t.Fatal(err)
	}
	anchor := policy.CaptureAge()
	now := time.Now().UTC()
	input.Now, input.Directory.ObservedAt, input.Bindings.ObservedAt = now, now, now
	input.Directory.Groups = input.Directory.Groups[:1]
	input.Directory.Devices[0].MAC, input.Directory.Devices[0].Active = "02:00:00:00:00:13", active
	input.Directory.Devices[0].GroupIDs = []string{input.Directory.Groups[0].ID}
	for _, protocol := range []string{"tcp", "udp"} {
		group := rendererAccessGroup(t, "callback-"+protocol, false, policy.Rule{
			ID: "callback", Direction: policy.FromDevice, Protocol: protocol, DestinationPorts: []uint16{6053},
			Peer: policy.Peer{Addresses: []string{"fdca:1a2b::10/128"}}, Reason: "Synthetic translated callback",
		})
		if len(scoped) != 0 && scoped[0] {
			raw := strings.Replace(*group.Policy, `"schema_version":1`, `"schema_version":2`, 1)
			raw = strings.Replace(raw, "fdca:1a2b::10/128", "fdca:1a2b::10/124", 1)
			raw = strings.Replace(raw, `"destination_ports":[6053]`, `"destination_port_ranges":[{"first":6053,"last":6055}]`, 1)
			group.Policy = &raw
		}
		input.Directory.Groups = append(input.Directory.Groups, group)
		input.Directory.Devices[0].GroupIDs = append(input.Directory.Devices[0].GroupIDs, group.ID)
	}
	input.Bindings.Records[0].MAC, input.Bindings.Records[0].AssociatedAt = "02:00:00:00:00:13", now
	input.Bindings.Records[0].Addresses = []binding.Address{{
		IP: netip.MustParseAddr("10.240.3.10"), Source: "kea_dhcp4", OwnershipID: "synthetic-translated-owner",
		ObservedAt: now, ValidUntil: now.Add(time.Hour),
	}}
	if !hasBinding {
		input.Bindings.Records = nil
	}
	authorization, err := renderer.compiler.CompileAuthorization(t.Context(), input, anchor)
	if err != nil {
		t.Fatal(err)
	}
	candidate, err := authorization.Snapshot(t.Context())
	wantGrants := 0
	if active && hasBinding {
		wantGrants = 2
	}
	if err != nil || len(candidate.Grants) != wantGrants {
		t.Fatalf("synthetic callback compilation failed: %v; grants=%d", err, len(candidate.Grants))
	}
	logical, err := renderer.prepare(t.Context(), replacement{
		authorization: authorization, now: time.Now().UTC(), cohort: []string{"02:00:00:00:00:13"},
	})
	if err != nil {
		t.Fatal(err)
	}
	layout, err := newGuardLayout(baseline)
	if err != nil {
		t.Fatal(err)
	}
	return layout, logical
}

func TestTranslatedScopeMirrorsPreserveListenerIntervals(t *testing.T) {
	t.Parallel()
	for _, ready := range []bool{false, true} {
		t.Run(map[bool]string{false: "mapping unavailable", true: "installed mapping"}[ready], func(t *testing.T) {
			t.Parallel()
			layout, logical := translatedDeviceGrantFixture(t, ready, true, true, true)
			prepared, err := prepareMappedGuards(t.Context(), logical, nil, layout.translationPaths)
			if err != nil {
				t.Fatal(err)
			}
			if err := validatePreparedGuardBatch(t.Context(), prepared); err != nil {
				t.Fatal(err)
			}
			changes, err := decodeGuardChanges(prepared.batch.data)
			if err != nil {
				t.Fatal(err)
			}
			count := 0
			for _, command := range changes.Commands {
				if command.Add == nil || !strings.HasPrefix(command.Add.Element.Name, "transit_") {
					continue
				}
				for _, value := range command.Add.Element.Values {
					if !bytes.Contains(value, []byte(`"range":[6053,6055]`)) || bytes.Contains(value, []byte(`"prefix"`)) {
						t.Fatalf("translation widened the exact mapped peer or lost the listener interval: %s", value)
					}
					count++
				}
			}
			want := 0
			if ready {
				want = 8
			}
			if count != want {
				t.Fatalf("got %d translated scope mirrors, want %d", count, want)
			}
		})
	}
}

func TestTranslatedDeviceMirrors(t *testing.T) {
	t.Parallel()
	for _, test := range []struct {
		name                      string
		ready, active, hasBinding bool
		count                     int
	}{
		{name: "ready exact callback", ready: true, active: true, hasBinding: true, count: 1},
		{name: "map unavailable", active: true, hasBinding: true},
		{name: "account revoked", ready: true, hasBinding: true},
		{name: "binding lost", ready: true, active: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			layout, logical := translatedDeviceGrantFixture(t, test.ready, test.active, test.hasBinding)
			prepared, err := prepareMappedGuards(t.Context(), logical, nil, layout.translationPaths)
			if err != nil {
				t.Fatal(err)
			}
			if err := validatePreparedGuardBatch(t.Context(), prepared); err != nil {
				t.Fatal(err)
			}
			if prepared.batch.startedAt != logical.startedAt || prepared.batch.startBefore != logical.startBefore {
				t.Fatal("translation replaced the original preparation fence")
			}
			commands, err := decodeGuardChanges(prepared.batch.data)
			if err != nil {
				t.Fatal(err)
			}
			adds := map[objectReference][]json.RawMessage{}
			for _, command := range commands.Commands {
				if command.Add != nil {
					value := command.Add.Element
					adds[objectReference{Family: value.Family, Table: value.Table, Name: value.Name}] = value.Values
				}
			}
			for _, ref := range translatedGrantRefs(layout.translationPaths) {
				if len(adds[ref]) != test.count {
					t.Fatalf("translated mirror %s has %d tuples, want %d", ref.Name, len(adds[ref]), test.count)
				}
				if test.count != 0 {
					var physical, translated struct {
						Element struct {
							Timeout int `json:"timeout"`
						} `json:"elem"`
					}
					protocol := "tcp"
					if strings.HasSuffix(ref.Name, "_udp") {
						protocol = "udp"
					}
					if err := json.Unmarshal(adds[ownedRef("lease_from4_"+protocol)][0], &physical); err != nil {
						t.Fatal(err)
					}
					if err := json.Unmarshal(adds[ref][0], &translated); err != nil {
						t.Fatal(err)
					}
					if translated.Element.Timeout != physical.Element.Timeout {
						t.Fatal("translation renewed the original lease timeout")
					}
				}
			}
			if test.count != 0 && !bytes.Contains(prepared.batch.data, []byte(`"nat64-test","fdca:1a2b:64::af0:30a","fdca:1a2b::10",6053`)) {
				t.Fatal("translated tuple did not retain exact path, host and listener")
			}
		})
	}
}

func TestTranslatedMirrorTampering(t *testing.T) {
	t.Parallel()
	layout, logical := translatedDeviceGrantFixture(t, true, true, true)
	prepared, err := prepareMappedGuards(t.Context(), logical, nil, layout.translationPaths)
	if err != nil {
		t.Fatal(err)
	}
	if err := validateGuardBatch(t.Context(), prepared.batch.data); err == nil {
		t.Fatal("native-only validator admitted translated operations")
	}
	for _, test := range []struct {
		name, old, replacement string
		extendTimeout          bool
	}{
		{name: "neighbor instead of device", old: "fdca:1a2b:64::af0:30a", replacement: "fdca:1a2b:64::af0:30b"},
		{name: "wrong translator", old: "nat64-test", replacement: "other-tun"},
		{name: "wrong listener", old: "6053", replacement: "6054"},
		{name: "wrong peer address", old: "fdca:1a2b::10", replacement: "fdca:1a2b::11"},
		{name: "extended translated lifetime", extendTimeout: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			commands, err := decodeGuardChanges(prepared.batch.data)
			if err != nil {
				t.Fatal(err)
			}
			for _, command := range commands.Commands {
				if command.Add != nil && command.Add.Element.Name == "transit_from6_tcp" {
					value := command.Add.Element.Values[0]
					if !test.extendTimeout {
						command.Add.Element.Values[0] = bytes.Replace(value, []byte(test.old), []byte(test.replacement), 1)
						continue
					}
					var lease struct {
						Element struct {
							Value   json.RawMessage `json:"val"`
							Timeout int             `json:"timeout"`
						} `json:"elem"`
					}
					if err := json.Unmarshal(value, &lease); err != nil {
						t.Fatal(err)
					}
					lease.Element.Timeout++
					encoded, err := json.Marshal(lease)
					if err != nil {
						t.Fatal(err)
					}
					command.Add.Element.Values[0] = encoded
				}
			}
			data, err := json.Marshal(commands)
			if err != nil {
				t.Fatal(err)
			}
			if err := validateMappedGuardBatch(t.Context(), data, nil, layout.translationPaths); err == nil {
				t.Fatal("altered translated mirror was admitted")
			}
		})
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if _, err := prepareMappedGuards(ctx, logical, nil, layout.translationPaths); err == nil {
		t.Fatal("cancelled translated preparation succeeded")
	}
}

func TestTranslatedMirrorSealingAndRootGeometry(t *testing.T) {
	t.Parallel()
	layout := translatedControllerLayout(t, true)
	sealed, err := prepareMappedGuardSeal(t.Context(), state.EmptyClassification(), layout.translationPaths)
	if err != nil {
		t.Fatal(err)
	}
	if err := validateGuardSeal(t.Context(), sealed); err != nil {
		t.Fatal(err)
	}
	commands, err := decodeGuardChanges(sealed.batch.data)
	if err != nil {
		t.Fatal(err)
	}
	flushes := map[objectReference]bool{}
	for _, command := range commands.Commands {
		if command.Flush != nil {
			flushes[command.Flush.Set] = true
		}
	}
	for _, ref := range translatedGrantRefs(layout.translationPaths) {
		if !flushes[ref] {
			t.Fatalf("sealing omitted translated mirror %s", ref.Name)
		}
	}
	inventory := &guardInventory{translationPaths: layout.translationPaths}
	if err := inventory.checkPreparedReplacement(t.Context(), sealed); err != nil {
		t.Fatal(err)
	}
	// Preparation retains its own root geometry. A later inspected map must
	// match; neither a readiness change nor a different TUN can reuse it.
	layout.translationPaths[0].isReady = false
	if !sealed.translationPaths[0].isReady {
		t.Fatal("caller changed the retained preparation geometry")
	}
	if err := inventory.checkPreparedReplacement(t.Context(), sealed); err == nil {
		t.Fatal("changed root readiness reused old translated preparation")
	}
}
