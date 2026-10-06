//go:build integration && kernel && linux

package firewall

import (
	"bytes"
	"context"
	"encoding/json"
	"net"
	"os"
	"os/exec"
	"testing"
	"time"
)

// This test must run in a disposable network namespace, not a deployment host.
// The acknowledgement and empty network checks catch accidental host execution;
// the test target must create the isolation, never use a host network namespace.
func TestKernelOwnedTransactionAndElementExpiry(t *testing.T) {
	requireKernelIsolation(t)
	ctx, cancel := context.WithTimeout(t.Context(), 15*time.Second)
	defer cancel()
	setupKernelObjects(ctx, t)
	process, err := openProcess(ctx, "/usr/sbin/nft")
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := process.close(); err != nil {
			t.Error(err)
		}
	}()
	before := kernelFixtureCommand(
		ctx,
		t,
		"list",
		"table",
		"inet",
		"unrelated_fixture",
	)
	if _, err := process.execute(ctx, applyOwned, leasedBatch(t)); err != nil {
		// Fixture-only diagnostics never bypass the production redaction boundary.
		diagnostic := exec.CommandContext(
			ctx,
			"/usr/sbin/nft",
			"--json",
			"--file",
			"-",
		)
		diagnostic.Env = []string{"LC_ALL=C", "PATH=/usr/sbin:/usr/bin"}
		diagnostic.Stdin = bytes.NewReader(leasedBatch(t))
		output, diagnosticError := diagnostic.CombinedOutput()
		t.Fatalf(
			"actual owned-set transaction failed: %v; synthetic fixture diagnostic: %v, %s",
			err,
			diagnosticError,
			output,
		)
	}
	data, err := process.execute(ctx, inspectOwned, nil)
	if err != nil || elementCount(t, data, "lease_to6_tcp") != 1 || elementCount(t, data, cohortSet) != 1 {
		t.Fatalf("native concatenation or cohort was not installed: %v", err)
	}
	// On this selected libnftables build, JSON timeout=2 must mean two seconds,
	// not two milliseconds and not two thousand seconds.
	timer := time.NewTimer(3100 * time.Millisecond)
	defer timer.Stop()
	select {
	case <-timer.C:
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	data, err = process.execute(ctx, inspectOwned, nil)
	if err != nil || elementCount(t, data, "lease_to6_tcp") != 0 || elementCount(t, data, cohortSet) != 1 {
		t.Fatalf("kernel expiry removed classification or retained permit: %v", err)
	}
	if _, err := process.execute(ctx, applyOwned, clearBatch(t)); err != nil {
		t.Fatal(err)
	}
	// Exercise actual typed compiler output through the deadline-checked runner.
	renderer, input, _, source := renderFixture(t)
	now := time.Now().UTC()
	source.Now, source.Directory.ObservedAt, source.Bindings.ObservedAt = now, now, now
	for index := range source.Bindings.Records {
		record := &source.Bindings.Records[index]
		record.AssociatedAt = now
		for address := range record.Addresses {
			record.Addresses[address].ObservedAt = now
			record.Addresses[address].ValidUntil = now.Add(time.Hour)
		}
	}
	input.candidate, err = renderer.compiler.CompileContext(ctx, source)
	if err != nil {
		t.Fatal(err)
	}
	input.now, input.existingCohort = time.Now().UTC(), []string{"02:00:00:00:00:01"}
	prepared, err := renderer.prepare(ctx, input)
	if err != nil {
		t.Fatal(err)
	}
	if err := process.applyPrepared(ctx, prepared); err != nil {
		t.Fatalf("compiled typed transaction failed on the actual kernel: %v", err)
	}
	data, err = process.execute(ctx, inspectOwned, nil)
	if err != nil || elementCount(t, data, "lease_to6_tcp") != 1 || elementCount(t, data, cohortSet) != 1 {
		t.Fatal("typed transaction lost the tuple or permanent classification")
	}
	after := kernelFixtureCommand(
		ctx,
		t,
		"list",
		"table",
		"inet",
		"unrelated_fixture",
	)
	if !bytes.Equal(before, after) {
		t.Fatal("owned operation changed unrelated baseline objects")
	}
	// Keep a live IPv4 tuple in the first set. A later missing object must roll
	// back its attempted flush, not merely preserve an already empty set.
	var rollback struct {
		Commands []json.RawMessage `json:"nftables"`
	}
	if err := json.Unmarshal(leasedBatch(t), &rollback); err != nil {
		t.Fatal(err)
	}
	rollback.Commands = append(rollback.Commands[:len(grantSets)], rollback.Commands[len(grantSets)+1:]...)
	rollbackData, err := json.Marshal(rollback)
	if err != nil {
		t.Fatal(err)
	}
	rollbackData = bytes.ReplaceAll(rollbackData, []byte(`"lease_to6_tcp"`), []byte(`"lease_from4_tcp"`))
	rollbackData = bytes.ReplaceAll(rollbackData, []byte("fdca:1a2b:3::10"), []byte("10.240.3.10"))
	rollbackData = bytes.ReplaceAll(rollbackData, []byte("fdca:1a2b::10"), []byte("10.240.0.10"))
	rollbackData = bytes.ReplaceAll(rollbackData, []byte(`"timeout":2`), []byte(`"timeout":20`))
	// Only the addition's name changes; keep every distinct flush in place.
	rollback.Commands = nil
	if err := json.Unmarshal(rollbackData, &rollback); err != nil {
		t.Fatal(err)
	}
	var cleanPrefix struct {
		Commands []json.RawMessage `json:"nftables"`
	}
	if err := json.Unmarshal(clearBatch(t), &cleanPrefix); err != nil {
		t.Fatal(err)
	}
	copy(rollback.Commands[:len(grantSets)], cleanPrefix.Commands)
	rollbackData, err = json.Marshal(rollback)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := process.execute(ctx, applyOwned, rollbackData); err != nil {
		t.Fatalf("rollback fixture could not install its live tuple: %v", err)
	}
	kernelFixtureCommand(
		ctx,
		t,
		"delete",
		"set",
		"inet",
		ownedTable,
		"lease_from6_tcp",
	)
	if _, err := process.execute(ctx, applyOwned, clearBatch(t)); err == nil {
		t.Fatal("missing-owned-object transaction falsely succeeded")
	}
	data, err = process.execute(ctx, inspectOwned, nil)
	if err != nil || elementCount(t, data, cohortSet) != 1 || elementCount(t, data, "lease_from4_tcp") != 1 {
		t.Fatal("failed transaction changed existing grants or persistent cohort")
	}
}

func requireKernelIsolation(t *testing.T) {
	t.Helper()
	if os.Geteuid() != 0 || os.Getenv("ROUTER_POLICY_KERNEL_TEST") != "isolated" {
		t.Fatal("kernel qualification requires the acknowledged isolated root runner")
	}
	interfaces, err := net.Interfaces()
	if err != nil || len(interfaces) != 1 || interfaces[0].Name != "lo" {
		t.Fatal("kernel qualification requires an initially empty network namespace")
	}
}

func setupKernelObjects(ctx context.Context, t *testing.T) {
	t.Helper()
	commands := []any{
		map[string]any{"add": map[string]any{"table": map[string]any{"family": "inet", "name": ownedTable}}},
		map[string]any{"add": map[string]any{"table": map[string]any{"family": "inet", "name": "unrelated_fixture"}}},
		map[string]any{"add": map[string]any{"set": map[string]any{
			"family": "inet", "table": "unrelated_fixture", "name": "protected", "type": "ipv4_addr",
			"elem": []string{"10.241.0.10"},
		}}},
		map[string]any{"add": map[string]any{"set": map[string]any{
			"family": "inet", "table": ownedTable, "name": cohortSet, "type": "ether_addr", "size": 4096,
		}}},
	}
	for _, name := range grantSets {
		addressType := "ipv6_addr"
		if ipv4Set(name) {
			addressType = "ipv4_addr"
		}
		commands = append(commands, map[string]any{"add": map[string]any{"set": map[string]any{
			"family": "inet", "table": ownedTable, "name": name, "size": 16384,
			"type":  []string{"ifname", "ether_addr", addressType, addressType, "inet_service"},
			"flags": []string{"timeout"}, "timeout": 90,
		}}})
	}
	data, err := json.Marshal(map[string]any{"nftables": commands})
	if err != nil {
		t.Fatal(err)
	}
	command := exec.CommandContext(
		ctx,
		"/usr/sbin/nft",
		"--json",
		"--file",
		"-",
	)
	command.Env = []string{"LC_ALL=C", "PATH=/usr/sbin:/usr/bin"}
	command.Stdin = bytes.NewReader(data)
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("isolated synthetic nft fixture failed: %v, %s", err, output)
	}
}

// Fixture-only authority is deliberately separate from the restricted runner.
// It cannot be called by a production executable or the reader protocol.
func kernelFixtureCommand(ctx context.Context, t *testing.T, arguments ...string) []byte {
	t.Helper()
	args := append([]string{"--json"}, arguments...)
	// #nosec G204 -- Fixed test fixture operations in an isolated namespace.
	command := exec.CommandContext(ctx, "/usr/sbin/nft", args...)
	command.Env = []string{"LC_ALL=C", "PATH=/usr/sbin:/usr/bin"}
	output, err := command.CombinedOutput()
	if err != nil {
		t.Fatalf("isolated synthetic fixture operation failed: %v, %s", err, output)
	}
	return output
}

func elementCount(t *testing.T, data []byte, name string) int {
	t.Helper()
	var observed struct {
		Objects []struct {
			Set *struct {
				Name     string            `json:"name"`
				Elements []json.RawMessage `json:"elem"`
			} `json:"set"`
		} `json:"nftables"`
	}
	if err := json.Unmarshal(data, &observed); err != nil {
		t.Fatal(err)
	}
	for _, object := range observed.Objects {
		if object.Set != nil && object.Set.Name == name {
			return len(object.Set.Elements)
		}
	}
	t.Fatalf("owned set is absent: %s", name)
	return 0
}
