//go:build integration && kernel && servicekernel && linux

package firewall

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"math"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/mikenorgate/router-policy-agent/internal/state"
)

func TestKernelGuardedServiceRecoveryCommand(t *testing.T) {
	requireKernelIsolation(t)
	buildContext, cancel := context.WithTimeout(t.Context(), time.Minute)
	defer cancel()
	binary := buildRecoveryCommand(buildContext, t)
	for _, name := range []string{"healthy", "floor and generation drift", "missing history", "corrupt history", "guard drift"} {
		t.Run(name, func(t *testing.T) {
			recoveryPacketFixture(t, binary, name)
		})
	}
}

func buildRecoveryCommand(ctx context.Context, t *testing.T) string {
	t.Helper()
	directory, err := os.MkdirTemp("", "rpa-recover-command-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := os.RemoveAll(directory); err != nil {
			t.Error(err)
		}
	})
	// #nosec G302 -- Synthetic executable must be reachable by the non-root child.
	if err := os.Chmod(directory, 0o755); err != nil {
		t.Fatal(err)
	}
	binary := filepath.Join(directory, "router-policy-recover")
	// #nosec G204 -- Fixed Go build target and executable in a fresh isolated fixture.
	command := exec.CommandContext(
		ctx,
		"/usr/local/go/bin/go",
		"build",
		"-buildvcs=false",
		"-trimpath",
		"-o",
		binary,
		"../../cmd/router-policy-recover",
	)
	command.Env = []string{
		"GOCACHE=" + filepath.Join(directory, "cache"), "GOMAXPROCS=4",
		"PATH=/usr/local/go/bin:/usr/sbin:/usr/bin:/bin",
	}
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("build synthetic recovery command: %v: %s", err, output)
	}
	return binary
}

type recoveryCommandOptions struct {
	binary, directory, timeout string
	credential                 *syscall.Credential
	isSuccessful               bool
}

func runRecoveryCommand(ctx context.Context, t *testing.T, options recoveryCommandOptions) {
	t.Helper()
	timeout := options.timeout
	if timeout == "" {
		timeout = "5s"
	}
	// #nosec G204 -- Built fixture executable and fixed recovery flags, no shell/program input.
	command := exec.CommandContext(
		ctx,
		options.binary,
		"-config-directory",
		options.directory,
		"-timeout",
		timeout,
	)
	command.Env = []string{"LC_ALL=C", "PATH=/usr/sbin:/usr/bin"}
	if options.credential != nil {
		command.SysProcAttr = &syscall.SysProcAttr{Credential: options.credential}
	}
	var output, diagnostics bytes.Buffer
	command.Stdout, command.Stderr = &output, &diagnostics
	err := command.Run()
	if (err == nil) != options.isSuccessful {
		t.Fatalf("recovery exit differs from expected scope: %v", err)
	}
	if !options.isSuccessful {
		var exit *exec.ExitError
		validExit := errors.As(err, &exit) && exit.ExitCode() == 1
		validOutput := output.Len() == 0 && strings.Contains(diagnostics.String(), "recovery not verified")
		if !validExit || !validOutput {
			t.Fatal("failed recovery printed success, ignored cancellation or changed its failure boundary")
		}
		if strings.Contains(diagnostics.String(), options.directory) {
			t.Fatal("recovery disclosed private deployment paths")
		}
		return
	}
	report := map[string]any{}
	if err := json.Unmarshal(output.Bytes(), &report); err != nil || diagnostics.Len() != 0 {
		t.Fatal("actual recovery command did not return a clean report")
	}
	validScope := report["scope"] == "owned_application_grants" && report["permit_state"] == "sealed"
	validHistory := report["history_state"] == "retained" && report["floor_state"] == "unverified"
	if !validScope || !validHistory || len(report) != 5 {
		t.Fatal("actual recovery command overstated its verified scope")
	}
}

func recoveryPacketFixture(t *testing.T, binary, name string) {
	t.Helper()
	requireKernelIsolation(t)
	t.Cleanup(func() { requireKernelIsolation(t) })
	ctx, cancel := context.WithTimeout(t.Context(), 45*time.Second)
	defer cancel()
	backend, writerRoot := setupBackendPacketFixture(ctx, t)
	options := configuredKernelOptions(
		ctx,
		t,
		backend,
		writerRoot,
	)
	config, err := loadHelperConfig(ctx, options.directory)
	if err != nil {
		t.Fatal(err)
	}
	authorization, history := backendAuthorizationFixture(t, backend.options.profile, 0)
	if err := backend.apply(ctx, authorization, history); err != nil {
		t.Fatal(err)
	}
	assertClassifiedGuardInventory(ctx, t, backend.options.executor, backend.options.profile.layout, history, true)
	durable, err := state.CloneClassification(history)
	if err != nil {
		t.Fatal(err)
	}
	durable.MACs = append(durable.MACs, "02:00:00:00:00:16")
	durable.IPv4 = append(durable.IPv4, "10.240.3.16")
	durable.IPv6 = append(durable.IPv6, "fdca:1a2b:3::16")
	for _, values := range []*[]string{&durable.MACs, &durable.IPv4, &durable.IPv6} {
		slices.Sort(*values)
	}
	document := state.Initial()
	document.CohortMACs, document.ClassifiedIPv4, document.ClassifiedIPv6 = durable.MACs, durable.IPv4, durable.IPv6
	// Future immutable anchors prove recovery never needs a usable wall clock,
	// refreshes authorization, erases a watermark or learns a new mapping.
	document.LastDirectoryObservedAt = time.Date(2090, 1, 1, 12, 0, 0, 0, time.UTC)
	document.DirectoryHash = strings.Repeat("a", 64)
	document.Ledger.LastValidated = document.LastDirectoryObservedAt
	document.Ledger.FirstSeen["synthetic-access/maintenance"] = document.LastDirectoryObservedAt
	document.Ledger.AliasPeers["synthetic-access/service/10.250.0.20/32"] = netip.MustParseAddr("fdca:1a2b:2::20")
	document.Ledger.NetworkGroups["synthetic-access"] = true
	store, err := state.Open(ctx, state.Options{Directory: config.StateDir, OwnerUID: 0})
	if err != nil {
		t.Fatal(err)
	}
	if err := errors.Join(store.Save(ctx, document), store.Close()); err != nil {
		t.Fatal(err)
	}
	stateRoot, err := os.OpenRoot(config.StateDir)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := stateRoot.Close(); err != nil {
			t.Error(err)
		}
	}()
	saved, err := stateRoot.ReadFile("state.json")
	if err != nil {
		t.Fatal(err)
	}
	peer, device := packetSocket(t, "peer0"), packetSocket(t, "device0")
	traffic := func(allowed bool) {
		t.Helper()
		for _, datagram := range backendNativeFrames(t) {
			from, to := device, peer
			if datagram.sourceMAC == "02:00:00:00:00:10" {
				from, to = peer, device
			}
			frame := packetFrame(t, datagram)
			sendPacket(ctx, t, from, frame)
			receivePacket(ctx, t, to, frame, allowed)
		}
	}
	unrelatedTraffic := func(isEstablished bool) {
		t.Helper()
		// Model a separate unclassified device, including its real final MAC.
		// Restore the original fixture identity before testing managed flows.
		packetIP(
			ctx,
			t,
			"link",
			"set",
			"device0",
			"address",
			"02:00:00:00:00:14",
		)
		unrelatedDevice := device
		mac, err := net.ParseMAC("02:00:00:00:00:14")
		if err != nil {
			t.Fatal(err)
		}
		unrelatedDevice.mac = mac
		for _, family := range []struct{ peer, device string }{
			{peer: "10.240.0.10", device: "10.240.3.12"},
			{peer: "fdca:1a2b::10", device: "fdca:1a2b:3::12"},
		} {
			packetIP(
				ctx,
				t,
				"neighbor",
				"replace",
				family.device,
				"lladdr",
				"02:00:00:00:00:14",
				"dev",
				"lan13",
				"nud",
				"permanent",
			)
			request := packetDatagram{
				source: netip.MustParseAddr(family.device), destination: netip.MustParseAddr(family.peer),
				sourceMAC: "02:00:00:00:00:14", destinationMAC: "02:00:00:00:01:13",
				sourcePort: 42200, destinationPort: 6060, payload: "synthetic-unrelated-recovery-flow",
			}
			before := guardFixtureCounter(ctx, t, "reviewed_floor", "flow_hits")
			frame := packetFrame(t, request)
			sendPacket(ctx, t, device, frame)
			receivePacket(ctx, t, peer, frame, true)
			if isEstablished && guardFixtureCounter(ctx, t, "reviewed_floor", "flow_hits") <= before {
				t.Fatal("recovery flushed an unrelated established connection")
			}
			// UDP is established only after a correlated reply; repeated
			// one-way datagrams alone do not qualify conntrack preservation.
			request.source, request.destination = request.destination, request.source
			request.sourcePort, request.destinationPort = request.destinationPort, request.sourcePort
			request.sourceMAC, request.destinationMAC = "02:00:00:00:00:10", "02:00:00:00:01:10"
			frame = packetFrame(t, request)
			sendPacket(ctx, t, peer, frame)
			receivePacket(ctx, t, unrelatedDevice, frame, true)
		}
		packetIP(
			ctx,
			t,
			"link",
			"set",
			"device0",
			"address",
			"02:00:00:00:00:13",
		)
	}
	traffic(true)
	commandOptions := recoveryCommandOptions{binary: binary, directory: options.directory}
	if name == "healthy" {
		unrelatedTraffic(false)
		// A real separate process must not steal the helper's exclusive lock.
		owner, err := state.Open(ctx, state.Options{Directory: config.StateDir, OwnerUID: 0})
		if err != nil {
			t.Fatal(err)
		}
		runRecoveryCommand(ctx, t, commandOptions)
		if err := owner.Close(); err != nil {
			t.Fatal(err)
		}
		// Root configuration must not be reachable through an unprivileged CLI.
		unprivileged := commandOptions
		unprivileged.credential = &syscall.Credential{Uid: 65534, Gid: 0, NoSetGroups: true}
		runRecoveryCommand(ctx, t, unprivileged)
		blockedRecoveryFixture(ctx, t, writerRoot, commandOptions)
		// None of these failures may remove leases or discard classifiers.
		assertClassifiedGuardInventory(ctx, t, backend.options.executor, backend.options.profile.layout, history, true)
		traffic(true)
	}
	switch name {
	case "floor and generation drift":
		packetNft(ctx, t, "insert rule inet reviewed_floor forward accept")
		closed := backend.options.expected
		closed.Ready = false
		writeGenerationFixture(t, writerRoot, closed)
	case "missing history":
		if err := stateRoot.Remove("state.json"); err != nil {
			t.Fatal(err)
		}
	case "corrupt history":
		saved = []byte(`{"schema_version":2}`)
		if err := stateRoot.WriteFile("state.json", saved, 0o600); err != nil {
			t.Fatal(err)
		}
	case "guard drift":
		packetNft(ctx, t, "add chain inet "+ownedTable+" unexpected_fixture")
	}
	external := kernelFixtureCommand(ctx, t, "list", "table", "inet", "reviewed_floor")
	commandOptions.isSuccessful = name == "healthy" || name == "floor and generation drift"
	runRecoveryCommand(ctx, t, commandOptions)
	after := kernelFixtureCommand(ctx, t, "list", "table", "inet", "reviewed_floor")
	if !bytes.Equal(external, after) {
		t.Fatal("scoped recovery changed or repaired the external baseline")
	}
	if name == "guard drift" {
		// Fix only our intentional fixture drift to inspect the untouched guards;
		// the actual command must never repair it or claim successful sealing.
		packetNft(ctx, t, "delete chain inet "+ownedTable+" unexpected_fixture")
		assertClassifiedGuardInventory(ctx, t, backend.options.executor, backend.options.profile.layout, history, true)
		traffic(true)
	} else {
		expectedHistory := history
		if commandOptions.isSuccessful {
			expectedHistory = durable
		}
		assertClassifiedGuardInventory(ctx, t, backend.options.executor, backend.options.profile.layout, expectedHistory, false)
		traffic(false)
	}
	if name == "healthy" {
		unrelatedTraffic(true)
	}
	contents, readErr := stateRoot.ReadFile("state.json")
	if name == "missing history" {
		if !errors.Is(readErr, os.ErrNotExist) {
			t.Fatal("recovery initialized missing durable history")
		}
	} else if readErr != nil || !bytes.Equal(contents, saved) {
		t.Fatal("recovery reset, repaired or changed durable anchors/classification")
	}
	store, err = state.Open(ctx, state.Options{Directory: config.StateDir, OwnerUID: 0})
	if err != nil {
		t.Fatal("actual recovery process retained the persistent-state lock")
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	for _, listener := range []*net.UnixListener{options.requests, options.status} {
		if err := listener.SetDeadline(time.Now().Add(time.Second)); err != nil {
			t.Fatal("recovery adopted or closed an unrelated supervisor listener")
		}
	}
}

func blockedRecoveryFixture(
	ctx context.Context,
	t *testing.T,
	root *os.Root,
	options recoveryCommandOptions,
) {
	t.Helper()
	// Deliberately hold the exact fixture lock past the child's operation and
	// retry deadlines. This is a stalled writer, not a compliant With callback.
	lock, err := root.Open(".lock")
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := lock.Close(); err != nil {
			t.Error(err)
		}
	}()
	fd := lock.Fd()
	if fd > math.MaxInt {
		t.Fatal("invalid fixture lock descriptor")
	}
	if err := syscall.Flock(int(fd), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		t.Fatal(err)
	}
	options.timeout = "100ms"
	runRecoveryCommand(ctx, t, options)
}
