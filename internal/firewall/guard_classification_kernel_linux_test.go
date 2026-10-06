//go:build integration && kernel && linux

package firewall

import (
	"bytes"
	"context"
	"encoding/json"
	"net/netip"
	"slices"
	"testing"
	"time"

	"github.com/mikenorgate/router-policy-agent/internal/state"
)

func TestKernelGuardClassificationRestoreAndSeal(t *testing.T) {
	requireKernelIsolation(t)
	t.Cleanup(func() { requireKernelIsolation(t) })
	ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
	defer cancel()
	layout, process := setupClassifiedGuardFixture(ctx, t, nil)
	packetNft(ctx, t, `table inet classification_unrelated_fixture {
 set retained { type ipv4_addr; elements = { 10.243.0.10 }; }
 chain retained_rule { ip saddr @retained drop; }
}`)
	t.Cleanup(func() {
		cleanup, cancel := context.WithTimeout(context.WithoutCancel(t.Context()), 2*time.Second)
		defer cancel()
		packetNft(cleanup, t, "delete table inet classification_unrelated_fixture")
	})
	unrelated := kernelFixtureCommand(ctx, t, "list", "table", "inet", "classification_unrelated_fixture")
	history := guardClassificationFixture()
	sealed, err := prepareGuardSeal(ctx, history)
	if err != nil {
		t.Fatal(err)
	}
	for range 2 {
		applyClassifiedGuardFixture(ctx, t, process, layout, sealed)
		assertClassifiedGuardInventory(ctx, t, process, layout, history, false)
	}

	// Retain all actual compiler-expanded native/counterpart device addresses,
	// plus older zero-grant history. This exercises inventory/restoration, not
	// a translated packet path or the production executable's age fencing.
	active := guardPacketBatch(t, netip.MustParseAddr("10.240.3.10"), netip.MustParseAddr("10.240.0.10"), true)
	logical, additions := classifiedLogicalFixture(t, active)
	history.MACs = append(history.MACs, additions.MACs...)
	history.IPv4 = append(history.IPv4, additions.IPv4...)
	history.IPv6 = append(history.IPv6, additions.IPv6...)
	for _, values := range []*[]string{&history.MACs, &history.IPv4, &history.IPv6} {
		slices.Sort(*values)
		*values = slices.Compact(*values)
	}
	prepared, err := prepareClassifiedGuards(ctx, &preparedBatch{data: logical}, history)
	if err != nil {
		t.Fatal(err)
	}
	applyClassifiedGuardFixture(ctx, t, process, layout, prepared)
	assertClassifiedGuardInventory(ctx, t, process, layout, history, true)
	sealed, err = prepareGuardSeal(ctx, history)
	if err != nil {
		t.Fatal(err)
	}
	applyClassifiedGuardFixture(ctx, t, process, layout, sealed)
	assertClassifiedGuardInventory(ctx, t, process, layout, history, false)

	// Simulate losing only the owned kernel objects, then restoring saved
	// classifiers without any policy grants. No traffic is opened before this
	// fixture restore; real boot traffic ordering still needs qualification.
	packetNft(ctx, t, "delete table inet "+ownedTable+"; delete table netdev "+ownedTable)
	program, err := layout.program(ctx)
	if err != nil {
		t.Fatal(err)
	}
	packetNft(ctx, t, string(program))
	applyClassifiedGuardFixture(ctx, t, process, layout, sealed)
	assertClassifiedGuardInventory(ctx, t, process, layout, history, false)
	empty, err := prepareGuardSeal(ctx, state.EmptyClassification())
	if err != nil {
		t.Fatal(err)
	}
	applyClassifiedGuardFixture(ctx, t, process, layout, empty)
	assertClassifiedGuardInventory(ctx, t, process, layout, history, false)
	after := kernelFixtureCommand(ctx, t, "list", "table", "inet", "classification_unrelated_fixture")
	if !bytes.Equal(unrelated, after) {
		t.Fatal("restoration or sealing changed unrelated kernel objects")
	}
}

func TestKernelZeroGrantHistoryClosesReusedNativeAddresses(t *testing.T) {
	requireKernelIsolation(t)
	t.Cleanup(func() { requireKernelIsolation(t) })
	ctx, cancel := context.WithTimeout(t.Context(), 20*time.Second)
	defer cancel()
	setupPacketLinks(ctx, t)
	layout, process := setupClassifiedGuardFixture(ctx, t, []string{"lan10", "lan13"})
	packetNft(ctx, t, `
table inet classification_legacy_fixture {
 chain forward { type filter hook forward priority 0; policy drop; meta l4proto udp udp dport 6060 accept; }
}
table netdev classification_endpoint_fixture {
 chain peer { type filter hook ingress device "peer0" priority 0; policy drop; }
 chain device_endpoint { type filter hook ingress device "device0" priority 0; policy drop; }
}`)
	t.Cleanup(func() {
		cleanup, cancel := context.WithTimeout(context.WithoutCancel(t.Context()), 2*time.Second)
		defer cancel()
		packetNft(cleanup, t, "delete table inet classification_legacy_fixture; delete table netdev classification_endpoint_fixture")
	})
	history := state.Classification{
		MACs: []string{"02:00:00:00:00:13"}, IPv4: []string{"10.240.3.10"},
		IPv6: []string{"fdca:1a2b:3::10", "fdca:1a2b:64::af0:30a"},
	}
	sealed, err := prepareGuardSeal(ctx, history)
	if err != nil {
		t.Fatal(err)
	}
	applyClassifiedGuardFixture(ctx, t, process, layout, sealed)
	assertClassifiedGuardInventory(ctx, t, process, layout, history, false)
	// Reassign the historical address to a different, unmanaged Ethernet
	// identity. It must still hit the restored IP deny classifier, not inherit
	// a legacy permit. A different never-classified address remains unaffected.
	packetIP(ctx, t, "link", "set", "device0", "address", "02:00:00:00:00:14")
	for _, address := range []string{"10.240.3.10", "fdca:1a2b:3::10", "10.240.3.12", "fdca:1a2b:3::12"} {
		packetIP(ctx, t, "neighbor", "replace", address, "lladdr", "02:00:00:00:00:14", "dev", "lan13", "nud", "permanent")
	}
	peer, device := packetSocket(t, "peer0"), packetSocket(t, "device0")
	for _, family := range []struct{ peer, previous, unrelated string }{
		{peer: "10.240.0.10", previous: "10.240.3.10", unrelated: "10.240.3.12"},
		{peer: "fdca:1a2b::10", previous: "fdca:1a2b:3::10", unrelated: "fdca:1a2b:3::12"},
	} {
		for index, address := range []string{family.previous, family.unrelated} {
			for _, fromPeer := range []bool{false, true} {
				input, output := device, peer
				source, destination := netip.MustParseAddr(address), netip.MustParseAddr(family.peer)
				sourceMAC, routerMAC := "02:00:00:00:00:14", "02:00:00:00:01:13"
				if fromPeer {
					input, output, source, destination = peer, device, destination, source
					sourceMAC, routerMAC = "02:00:00:00:00:10", "02:00:00:00:01:10"
				}
				frame := packetFrame(t, packetDatagram{
					source: source, destination: destination, sourceMAC: sourceMAC, destinationMAC: routerMAC,
					sourcePort: 41200, destinationPort: 6060, payload: "synthetic-restored-classification",
				})
				sendPacket(ctx, t, input, frame)
				receivePacket(ctx, t, output, frame, index == 1)
			}
		}
	}
}

func setupClassifiedGuardFixture(ctx context.Context, t *testing.T, existing []string) (*guardLayout, *process) {
	t.Helper()
	_, _, baseline, _ := renderFixture(t)
	layout, err := newGuardLayout(baseline)
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range layout.interfaces {
		if slices.Contains(existing, name) {
			continue
		}
		packetIP(ctx, t, "link", "add", name, "type", "dummy")
		t.Cleanup(func() {
			cleanup, cancel := context.WithTimeout(context.WithoutCancel(t.Context()), 2*time.Second)
			defer cancel()
			packetIP(cleanup, t, "link", "delete", name)
		})
	}
	program, err := layout.program(ctx)
	if err != nil {
		t.Fatal(err)
	}
	packetNft(ctx, t, string(program))
	t.Cleanup(func() {
		cleanup, cancel := context.WithTimeout(context.WithoutCancel(t.Context()), 2*time.Second)
		defer cancel()
		packetNft(cleanup, t, "delete table inet "+ownedTable+"; delete table netdev "+ownedTable)
	})
	process, err := openProcess(ctx, "/usr/sbin/nft")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := process.close(); err != nil {
			t.Error(err)
		}
	})
	return layout, process
}

func applyClassifiedGuardFixture(
	ctx context.Context, t *testing.T, process *process, layout *guardLayout, prepared *preparedGuardBatch,
) {
	t.Helper()
	if err := validatePreparedGuardBatch(ctx, prepared); err != nil {
		t.Fatal(err)
	}
	inventory, err := process.inspectGuards(ctx, layout)
	if err != nil {
		t.Fatal(err)
	}
	if err := inventory.checkPreparedReplacement(ctx, prepared); err != nil {
		t.Fatal(err)
	}
	executeGuardFixture(ctx, t, prepared.batch.data)
}

func assertClassifiedGuardInventory(
	ctx context.Context, t *testing.T, process *process, layout *guardLayout, history state.Classification, leased bool,
) {
	t.Helper()
	inventory, err := process.inspectGuards(ctx, layout)
	if err != nil {
		t.Fatal(err)
	}
	if (inventory.leases > 0) != leased || !slices.Equal(inventory.cohort, history.MACs) ||
		len(inventory.addresses4) != len(history.IPv4) || len(inventory.addresses6) != len(history.IPv6) {
		t.Fatal("actual guarded transaction lost history, mirror scope or sealing")
	}
	for index, addresses := range [][]netip.Addr{inventory.addresses4, inventory.addresses6} {
		wanted := history.IPv4
		if index == 1 {
			wanted = history.IPv6
		}
		for _, address := range addresses {
			if _, exists := slices.BinarySearch(wanted, address.String()); !exists {
				t.Fatal("actual permanent classification differs from saved history")
			}
		}
	}
}

func classifiedLogicalFixture(t *testing.T, data []byte) ([]byte, state.Classification) {
	t.Helper()
	decoded, err := decodeGuardChanges(data)
	if err != nil {
		t.Fatal(err)
	}
	logical, history := guardChanges{Commands: make([]change, 0)}, state.EmptyClassification()
	for _, command := range decoded.Commands {
		if command.Flush != nil && ownedReference(command.Flush.Set) && isGrantSet(command.Flush.Set.Name) {
			logical.Commands = append(logical.Commands, command)
		}
		if command.Add == nil || command.Add.Element.Family != "inet" {
			continue
		}
		value := command.Add.Element
		if isGrantSet(value.Name) || value.Name == cohortSet {
			logical.Commands = append(logical.Commands, command)
		}
		var destination *[]string
		switch value.Name {
		case cohortSet:
			destination = &history.MACs
		case classified4Set:
			destination = &history.IPv4
		case classified6Set:
			destination = &history.IPv6
		default:
			continue
		}
		for _, raw := range value.Values {
			var text string
			if err := json.Unmarshal(raw, &text); err != nil {
				t.Fatal(err)
			}
			*destination = append(*destination, text)
		}
	}
	source, err := json.Marshal(logical)
	if err != nil {
		t.Fatal(err)
	}
	return source, history
}
