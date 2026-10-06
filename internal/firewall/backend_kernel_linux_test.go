//go:build integration && kernel && linux

package firewall

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/netip"
	"os"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/mikenorgate/router-policy-agent/internal/binding"
	"github.com/mikenorgate/router-policy-agent/internal/policy"
	"github.com/mikenorgate/router-policy-agent/internal/state"
)

// Independently authored router-side bridge and endpoint objects. The expected
// artifact below is not captured from nft output or generated from guard code.
const backendKernelExtra = `
  meta mark & 0xff000000 == 0xa1000000 accept
  meta mark & 0xff000000 == 0xa2000000 accept
  meta mark & 0xff000000 == 0xa3000000 accept
  meta mark & 0xff000000 == 0xa4000000 accept
  meta l4proto udp udp dport 6060 accept
`

const backendEndpointProgram = `
table netdev backend_endpoints {
 chain peer { type filter hook ingress device "peer0" priority 0; policy drop; }
 chain device_endpoint { type filter hook ingress device "device0" priority 0; policy drop; }
}
`

func backendPacketProfileFixture(t testing.TB) (*routerProfile, string) {
	t.Helper()
	profile, program, _ := backendPacketProfileDataFixture(t)
	return profile, program
}

func backendPacketProfileDataFixture(t testing.TB) (*routerProfile, string, []byte) {
	t.Helper()
	var artifact struct {
		Schema  int               `json:"schema_version"`
		Objects []json.RawMessage `json:"objects"`
	}
	if err := json.Unmarshal([]byte(reviewedArtifactFixture), &artifact); err != nil {
		t.Fatal(err)
	}
	objects := make([]json.RawMessage, 0, len(artifact.Objects)+8)
	inserted := false
	for _, raw := range artifact.Objects {
		// Insert independently specified bridge statements before the ordinary
		// default drop, after the fixture's protected safety/stateful paths.
		if bytes.Contains(raw, []byte(`"chain":"forward","expr":[{"counter":{}}`)) {
			inserted = true
			for _, tag := range []uint64{0xa1000000, 0xa2000000, 0xa3000000, 0xa4000000} {
				statement := map[string]any{"rule": map[string]any{
					"family": "inet", "table": "reviewed_floor", "chain": "forward",
					"expr": []any{
						map[string]any{"match": map[string]any{
							"op": "==", "left": map[string]any{"&": []any{
								map[string]any{"meta": map[string]any{"key": "mark"}}, uint64(0xff000000),
							}}, "right": tag,
						}},
						map[string]any{"accept": nil},
					},
				}}
				encoded, err := json.Marshal(statement)
				if err != nil {
					t.Fatal(err)
				}
				objects = append(objects, encoded)
			}
			// nft eliminates the redundant explicit l4proto test: accessing
			// udp dport already creates its transport dependency.
			objects = append(objects, json.RawMessage(`{"rule":{"family":"inet","table":"reviewed_floor","chain":"forward","expr":[{"match":{"op":"==","left":{"payload":{"protocol":"udp","field":"dport"}},"right":6060}},{"accept":null}]}}`))
		}
		objects = append(objects, raw)
	}
	objects = append(objects,
		json.RawMessage(`{"table":{"family":"netdev","name":"backend_endpoints"}}`),
		json.RawMessage(`{"chain":{"family":"netdev","table":"backend_endpoints","name":"peer","type":"filter","hook":"ingress","prio":0,"policy":"drop","dev":"peer0"}}`),
		json.RawMessage(`{"chain":{"family":"netdev","table":"backend_endpoints","name":"device_endpoint","type":"filter","hook":"ingress","prio":0,"policy":"drop","dev":"device0"}}`),
	)
	artifact.Objects = objects
	reviewed, err := json.Marshal(artifact)
	if err != nil {
		t.Fatal(err)
	}
	baseline, err := os.ReadFile("../../examples/baseline.json")
	if err != nil {
		t.Fatal(err)
	}
	data, err := json.Marshal(profileEnvelope{SchemaVersion: 1, Baseline: baseline, ReviewedRuleset: reviewed})
	if err != nil {
		t.Fatal(err)
	}
	profile, err := decodePinnedProfile(t.Context(), data, routerProfileDigest(data))
	if err != nil {
		t.Fatal(err)
	}
	program := strings.Replace(reviewedKernelFixture, "  counter drop", backendKernelExtra+"  counter drop", 1)
	if program == reviewedKernelFixture || !inserted {
		t.Fatal("independent backend bridge fixture was not constructed")
	}
	return profile, program + backendEndpointProgram, data
}

func setupBackendPacketFixture(ctx context.Context, t *testing.T) (*guardedBackend, *os.Root) {
	t.Helper()
	setupPacketLinks(ctx, t)
	profile, routerProgram := backendPacketProfileFixture(t)
	for _, name := range profile.layout.interfaces {
		if slices.Contains([]string{"lan10", "lan13"}, name) {
			continue
		}
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
	packetNft(ctx, t, string(program)+routerProgram)
	t.Cleanup(func() {
		cleanup, cancel := context.WithTimeout(context.WithoutCancel(t.Context()), 2*time.Second)
		defer cancel()
		packetNft(cleanup, t, "delete table inet reviewed_floor; delete table netdev backend_endpoints; "+
			"delete table inet "+ownedTable+"; delete table netdev "+ownedTable)
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
	gate, root, _ := generationGateFixture(t)
	expected := writerGenerationFixture()
	expected.FloorHash = profile.ruleset.digest
	writeGenerationFixture(t, root, expected)
	backend, err := newGuardedBackend(backendOptions{
		profile: profile, executor: executor, generation: gate, expected: expected, clock: time.Now,
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := profile.inspect(ctx, executor); err != nil {
		t.Fatalf("independently authored backend fixture did not match: %v", err)
	}
	return backend, root
}

func backendInputFixture(t *testing.T, observationAge time.Duration) policy.Input {
	t.Helper()
	_, _, _, input := renderFixture(t)
	input.Now = time.Now().Round(0).UTC()
	observed := input.Now.Add(-observationAge)
	input.Directory.ObservedAt = observed
	input.Bindings.ObservedAt = observed
	input.Directory.Devices[0].MAC = "02:00:00:00:00:13"
	record := &input.Bindings.Records[0]
	record.MAC, record.AssociatedAt = "02:00:00:00:00:13", observed
	for index := range record.Addresses {
		record.Addresses[index].ObservedAt = observed
		record.Addresses[index].ValidUntil = input.Now.Add(time.Hour)
	}
	record.Addresses = append(record.Addresses, binding.Address{
		IP: netip.MustParseAddr("10.240.3.10"), Source: "kea_dhcp4", OwnershipID: "synthetic-backend-v4",
		ObservedAt: observed, ValidUntil: input.Now.Add(time.Hour),
	})
	input.Directory.Groups = input.Directory.Groups[:1]
	input.Directory.Devices[0].GroupIDs = []string{input.Directory.Groups[0].ID}
	for _, direction := range []policy.Direction{policy.ToDevice, policy.FromDevice} {
		for _, protocol := range []string{"tcp", "udp"} {
			id := "backend-" + string(direction) + "-" + protocol
			input.Directory.Groups = append(input.Directory.Groups, rendererAccessGroup(t, id, false, policy.Rule{
				ID: "native-listener", Direction: direction,
				Peer:     policy.Peer{Addresses: []string{"10.240.0.10/32", "fdca:1a2b::10/128"}},
				Protocol: protocol, DestinationPorts: []uint16{6053}, Reason: "Synthetic native backend test",
			}))
			input.Directory.Devices[0].GroupIDs = append(input.Directory.Devices[0].GroupIDs, id)
		}
	}
	return input
}

func backendAuthorizationFixture(
	t *testing.T,
	profile *routerProfile,
	observationAge time.Duration,
) (policy.Authorization, state.Classification) {
	t.Helper()
	input := backendInputFixture(t, observationAge)
	authorization, err := profile.renderer.compiler.CompileAuthorization(t.Context(), input, policy.CaptureAge())
	if err != nil {
		t.Fatal(err)
	}
	candidate, err := authorization.Snapshot(t.Context())
	if err != nil || len(candidate.Grants) == 0 || len(candidate.Denials) != 0 {
		t.Fatalf("synthetic backend evidence did not authorize its native flows: %v", err)
	}
	history := state.Classification{
		MACs: []string{"02:00:00:00:00:13", "02:00:00:00:00:15"},
		IPv4: []string{"10.240.3.15"}, IPv6: []string{"fdca:1a2b:3::15"},
	}
	for _, grant := range candidate.Grants {
		for _, address := range grant.Device.Variants {
			if address.Is4() {
				history.IPv4 = append(history.IPv4, address.String())
				continue
			}
			history.IPv6 = append(history.IPv6, address.String())
		}
	}
	for _, values := range []*[]string{&history.IPv4, &history.IPv6} {
		slices.Sort(*values)
		*values = slices.Compact(*values)
	}
	owned, err := state.CloneClassification(history)
	if err != nil {
		t.Fatal(err)
	}
	return authorization, owned
}

func backendNativeFrames(t *testing.T) []packetDatagram {
	t.Helper()
	frames := make([]packetDatagram, 0, 8)
	for _, family := range []struct{ peer, device string }{
		{peer: "10.240.0.10", device: "10.240.3.10"},
		{peer: "fdca:1a2b::10", device: "fdca:1a2b:3::10"},
	} {
		for _, flow := range []struct {
			fromPeer       bool
			source, target uint16
		}{
			{fromPeer: true, source: 42100, target: 6053},
			{source: 6053, target: 42100},
			{source: 42101, target: 6053},
			{fromPeer: true, source: 6053, target: 42101},
		} {
			datagram := packetDatagram{
				source: netip.MustParseAddr(family.device), destination: netip.MustParseAddr(family.peer),
				sourceMAC: "02:00:00:00:00:13", destinationMAC: "02:00:00:00:01:13",
				sourcePort: flow.source, destinationPort: flow.target, payload: "synthetic-guarded-backend",
			}
			if flow.fromPeer {
				datagram.source, datagram.destination = datagram.destination, datagram.source
				datagram.sourceMAC, datagram.destinationMAC = "02:00:00:00:00:10", "02:00:00:00:01:10"
			}
			frames = append(frames, datagram)
		}
	}
	return frames
}

func TestKernelGuardedBackendAppliesAndSealsNativeFlows(t *testing.T) {
	requireKernelIsolation(t)
	t.Cleanup(func() { requireKernelIsolation(t) })
	ctx, cancel := context.WithTimeout(t.Context(), 45*time.Second)
	defer cancel()
	backend, root := setupBackendPacketFixture(ctx, t)
	authorization, history := backendAuthorizationFixture(t, backend.options.profile, 0)
	peer, device := packetSocket(t, "peer0"), packetSocket(t, "device0")
	traffic := func(allowed bool) {
		for _, datagram := range backendNativeFrames(t) {
			input, output := device, peer
			if datagram.sourceMAC == "02:00:00:00:00:10" {
				input, output = peer, device
			}
			frame := packetFrame(t, datagram)
			sendPacket(ctx, t, input, frame)
			receivePacket(ctx, t, output, frame, allowed)
		}
	}
	if err := backend.seal(ctx, history); err != nil {
		t.Fatal(err)
	}
	traffic(false)
	if err := backend.apply(ctx, authorization, history); err != nil {
		t.Fatal(err)
	}
	traffic(true)
	if guardFixtureCounter(ctx, t, "reviewed_floor", "flow_hits") == 0 {
		t.Fatal("backend packet fixture did not exercise established acceptance")
	}
	if err := backend.seal(ctx, state.EmptyClassification()); err != nil {
		t.Fatal(err)
	}
	traffic(false)
	assertClassifiedGuardInventory(ctx, t, backend.options.executor, backend.options.profile.layout, history, false)
	for _, name := range []string{"canceled request", "invalid authorization", "closed generation", "floor drift"} {
		t.Run(name, func(t *testing.T) {
			if err := backend.apply(ctx, authorization, history); err != nil {
				t.Fatal(err)
			}
			traffic(true)
			before := guardFixtureCounter(ctx, t, "reviewed_floor", "flow_hits")
			requestCtx, requestAuthorization := ctx, authorization
			var changedFloor []byte
			switch name {
			case "canceled request":
				canceled, cancel := context.WithCancel(ctx)
				cancel()
				requestCtx = canceled
			case "invalid authorization":
				requestAuthorization = policy.Authorization{}
			case "closed generation":
				closed := backend.options.expected
				closed.Ready = false
				writeGenerationFixture(t, root, closed)
			case "floor drift":
				packetNft(ctx, t, "insert rule inet reviewed_floor forward accept")
				changedFloor = kernelFixtureCommand(ctx, t, "list", "table", "inet", "reviewed_floor")
			}
			err := backend.apply(requestCtx, requestAuthorization, history)
			if err == nil {
				t.Fatal("unsafe evidence, generation or floor reported an applied policy")
			}
			if name == "canceled request" && !errors.Is(err, context.Canceled) {
				t.Fatal("request cancellation was discarded")
			}
			assertClassifiedGuardInventory(ctx, t, backend.options.executor, backend.options.profile.layout, history, false)
			if name == "floor drift" {
				after := kernelFixtureCommand(ctx, t, "list", "table", "inet", "reviewed_floor")
				if !bytes.Equal(changedFloor, after) {
					t.Fatal("cleanup repaired or modified an external router table")
				}
			}
			traffic(false)
			if guardFixtureCounter(ctx, t, "reviewed_floor", "flow_hits") != before {
				t.Fatal("failed application left revoked traffic reaching an established shortcut")
			}
			if name == "closed generation" {
				// Test-only owning-writer publication advances the sequence; an old
				// ready record is not restored to make the next attempt pass.
				next := backend.options.expected
				next.Sequence++
				writeGenerationFixture(t, root, next)
				options := backend.options
				options.expected = next
				backend, err = newGuardedBackend(options)
				if err != nil {
					t.Fatal(err)
				}
			}
		})
	}
}

func TestKernelGuardedBackendLeaseExpiresWithoutTrafficRenewal(t *testing.T) {
	requireKernelIsolation(t)
	t.Cleanup(func() { requireKernelIsolation(t) })
	ctx, cancel := context.WithTimeout(t.Context(), 20*time.Second)
	defer cancel()
	backend, _ := setupBackendPacketFixture(ctx, t)
	authorization, history := backendAuthorizationFixture(t, backend.options.profile, 82*time.Second)
	if err := backend.apply(ctx, authorization, history); err != nil {
		t.Fatal(err)
	}
	peer, device := packetSocket(t, "peer0"), packetSocket(t, "device0")
	for _, datagram := range backendNativeFrames(t) {
		input, output := device, peer
		if datagram.sourceMAC == "02:00:00:00:00:10" {
			input, output = peer, device
		}
		frame := packetFrame(t, datagram)
		sendPacket(ctx, t, input, frame)
		receivePacket(ctx, t, output, frame, true)
	}
	// The original eight-second lifetime is reduced by preparation/command
	// budgets to three kernel seconds. No directory refresh or timer renewal
	// occurs; established traffic must stop once those elements expire.
	timer := time.NewTimer(4 * time.Second)
	defer timer.Stop()
	activity := time.NewTicker(100 * time.Millisecond)
	defer activity.Stop()
activityLoop:
	for {
		select {
		case <-timer.C:
			break activityLoop
		case <-ctx.Done():
			t.Fatal(ctx.Err())
		case <-activity.C:
			for _, datagram := range backendNativeFrames(t) {
				input := device
				if datagram.sourceMAC == "02:00:00:00:00:10" {
					input = peer
				}
				datagram.payload = "synthetic-backend-lease-activity"
				sendPacket(ctx, t, input, packetFrame(t, datagram))
			}
		}
	}
	before := guardFixtureCounter(ctx, t, "reviewed_floor", "flow_hits")
	for _, datagram := range backendNativeFrames(t) {
		input, output := device, peer
		if datagram.sourceMAC == "02:00:00:00:00:10" {
			input, output = peer, device
		}
		// Distinct bytes cannot match allowed activity queued before expiry.
		datagram.payload = "synthetic-backend-after-expiry"
		frame := packetFrame(t, datagram)
		sendPacket(ctx, t, input, frame)
		receivePacket(ctx, t, output, frame, false)
	}
	if guardFixtureCounter(ctx, t, "reviewed_floor", "flow_hits") != before {
		t.Fatal("expired backend traffic reached an established shortcut")
	}
	assertClassifiedGuardInventory(ctx, t, backend.options.executor, backend.options.profile.layout, history, false)
}
