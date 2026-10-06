//go:build integration && kernel && linux

package firewall

import (
	"bytes"
	"context"
	"testing"
	"time"
)

func TestKernelPinnedProfileUsesItsPairedContract(t *testing.T) {
	requireKernelIsolation(t)
	t.Cleanup(func() { requireKernelIsolation(t) })
	ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
	defer cancel()
	root, options, data := privateRouterProfileFixture(t)
	profile, err := loadRouterProfile(ctx, options)
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range profile.layout.interfaces {
		packetIP(ctx, t, "link", "add", name, "type", "dummy")
		t.Cleanup(func() {
			cleanup, cancel := context.WithTimeout(context.WithoutCancel(t.Context()), 2*time.Second)
			defer cancel()
			packetIP(cleanup, t, "link", "delete", name)
		})
	}
	program, err := profile.layout.program(ctx)
	if err != nil {
		t.Fatal(err)
	}
	packetNft(ctx, t, string(program)+reviewedKernelFixture)
	t.Cleanup(func() {
		cleanup, cancel := context.WithTimeout(context.WithoutCancel(t.Context()), 2*time.Second)
		defer cancel()
		packetNft(cleanup, t,
			"delete table inet reviewed_floor; delete table inet "+ownedTable+"; delete table netdev "+ownedTable,
		)
	})
	executor, err := openProcess(ctx, "/usr/sbin/nft")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := executor.close(); err != nil {
			t.Error(err)
		}
	})
	observation, err := profile.inspect(ctx, executor)
	if err != nil || observation.digest != profile.ruleset.digest || observation.guards.leases != 0 {
		t.Fatalf("pinned profile did not verify its independently authored installed fixture: %v", err)
	}
	before, err := executor.execute(ctx, inspectWholeRuleset, nil)
	if err != nil {
		t.Fatal(err)
	}
	// A separately approved synthetic bundle cannot use another bundle's layout
	// merely because its surrounding object contract happens to be unchanged.
	changed := bytes.Replace(
		data,
		[]byte(`"lan13"`),
		[]byte(`"other13"`),
		1,
	)
	if bytes.Equal(data, changed) {
		t.Fatal("pairing test did not change its synthetic interface")
	}
	if err := root.WriteFile(routerProfileFile, changed, 0o600); err != nil {
		t.Fatal(err)
	}
	if mismatched, err := loadRouterProfile(ctx, options); err == nil || mismatched != nil {
		t.Fatal("changed root-owned bytes were learned as their own expected profile")
	}
	options.SHA256 = routerProfileDigest(changed) // Test-only approval of an independently authored fixture.
	second, err := loadRouterProfile(ctx, options)
	if err != nil {
		t.Fatal(err)
	}
	if observation, err := second.inspect(ctx, executor); err == nil || observation != nil {
		t.Fatal("a different trusted layout accepted the old installed guard")
	}
	if _, err := profile.inspect(ctx, executor); err != nil {
		t.Fatal("stored file replacement mutated the already loaded immutable profile")
	}
	after, err := executor.execute(ctx, inspectWholeRuleset, nil)
	if err != nil || !bytes.Equal(before, after) {
		t.Fatal("successful or rejected profile inspection changed actual firewall objects")
	}
	packetNft(ctx, t, "insert rule inet reviewed_floor forward accept")
	if observation, err := profile.inspect(ctx, executor); err == nil || observation != nil {
		t.Fatal("a pinned profile accepted actual early-accept drift")
	}
}
