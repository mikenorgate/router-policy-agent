//go:build integration && kernel && linux

package firewall

import (
	"context"
	"net/netip"
	"testing"
	"time"
)

func TestKernelGuardedObjectInspection(t *testing.T) {
	requireKernelIsolation(t)
	t.Cleanup(func() { requireKernelIsolation(t) })
	ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
	defer cancel()
	_, _, baseline, _ := renderFixture(t)
	layout, err := newGuardLayout(baseline)
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range layout.interfaces {
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
	inventory, err := process.inspectGuards(ctx, layout)
	if err != nil || inventory.leases != 0 || len(inventory.cohort) != 0 {
		t.Fatalf("actual empty guard program did not match its fixed inspection schema: %v", err)
	}
	batch := guardPacketBatch(t, netip.MustParseAddr("10.240.3.10"), netip.MustParseAddr("10.240.0.10"), true)
	if err := inventory.checkReplacement(ctx, batch); err != nil {
		t.Fatal(err)
	}
	applyGuardFixture(ctx, t, batch)
	inventory, err = process.inspectGuards(ctx, layout)
	if err != nil || inventory.leases == 0 || len(inventory.cohort) != 1 ||
		len(inventory.addresses4) == 0 || len(inventory.addresses6) == 0 {
		t.Fatalf("actual guarded mirrors or counterpart classification were rejected: %v", err)
	}
	// Native and compiler-derived counterpart tuples all participate in the
	// inventory. This does not qualify translated forwarding or translator fences.
	addressCount := len(inventory.addresses4) + len(inventory.addresses6)
	revocation, err := prepareGuards(ctx, &preparedBatch{data: clearBatch(t)})
	if err != nil {
		t.Fatal(err)
	}
	if err := inventory.checkReplacement(ctx, revocation.batch.data); err != nil {
		t.Fatal(err)
	}
	applyGuardFixture(ctx, t, revocation.batch.data)
	inventory, err = process.inspectGuards(ctx, layout)
	if err != nil || inventory.leases != 0 || len(inventory.cohort) != 1 ||
		len(inventory.addresses4)+len(inventory.addresses6) != addressCount {
		t.Fatalf("actual lease revocation erased permanent classification: %v", err)
	}
	applyGuardFixture(ctx, t, batch)
	packetNft(ctx, t, "flush set netdev "+ownedTable+" egress_lease_to4_tcp")
	if inventory, err := process.inspectGuards(ctx, layout); err == nil || inventory != nil {
		t.Fatal("actual missing final-egress mirror produced trusted inventory")
	}
	applyGuardFixture(ctx, t, revocation.batch.data)
	packetNft(ctx, t, "add rule inet "+ownedTable+" guard_forward accept")
	if inventory, err := process.inspectGuards(ctx, layout); err == nil || inventory != nil {
		t.Fatal("an actual extra guard rule was accepted")
	}
}
