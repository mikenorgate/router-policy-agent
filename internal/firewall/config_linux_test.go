package firewall

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/mikenorgate/router-policy-agent/internal/agent"
)

func helperConfigFixture() helperConfig {
	return helperConfig{
		SchemaVersion: 1,
		Mode:          agent.Enforce,
		Profile:       helperProfile{Directory: "/opt/policy/profile", SHA256: strings.Repeat("a", 64)},
		GenerationDir: "/run/policy/writers", StateDir: "/var/lib/policy", NFTExecutable: "/usr/sbin/nft",
		ReaderUID: 65534, OperatorUID: 65533, RequestTimeoutMS: 2000,
		RequestSocket: "/run/policy/requests.sock", StatusSocket: "/run/policy/status.sock",
		ExpectedGeneration: writerGenerationFixture(),
	}
}

func helperConfigBytes(t testing.TB, config helperConfig) []byte {
	t.Helper()
	data, err := json.Marshal(config)
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func TestHelperConfigRequiresExactStructureAndIndependentPins(t *testing.T) {
	t.Parallel()
	valid := helperConfigBytes(t, helperConfigFixture())
	for _, test := range []struct {
		name string
		data []byte
	}{
		{name: "empty", data: []byte{}},
		{name: "oversized", data: []byte(strings.Repeat(" ", maximumHelperConfig+1))},
		{name: "unknown root", data: []byte(strings.Replace(string(valid), `"schema_version":1`, `"schema_version":1,"bindings":{}`, 1))},
		{name: "duplicate root", data: []byte(strings.Replace(string(valid), `"schema_version":1`, `"schema_version":1,"schema_version":1`, 1))},
		{name: "unknown profile", data: []byte(strings.Replace(string(valid), `"profile":{`, `"profile":{"clock":"fixture",`, 1))},
		{name: "duplicate profile", data: []byte(strings.Replace(string(valid), `"sha256":`, `"sha256":"`+strings.Repeat("b", 64)+`","sha256":`, 1))},
		{name: "unknown generation", data: []byte(strings.Replace(string(valid), `"expected_generation":{`, `"expected_generation":{"commands":[],`, 1))},
		{name: "reader negative", data: []byte(strings.Replace(string(valid), `"reader_uid":65534`, `"reader_uid":-1`, 1))},
		{name: "reader overflow", data: []byte(strings.Replace(string(valid), `"reader_uid":65534`, `"reader_uid":4294967296`, 1))},
		{name: "timeout fractional", data: []byte(strings.Replace(string(valid), `"request_timeout_ms":2000`, `"request_timeout_ms":1.5`, 1))},
		{name: "case mismatch", data: []byte(strings.Replace(string(valid), `"reader_uid"`, `"Reader_UID"`, 1))},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			config, err := decodeHelperConfig(t.Context(), test.data)
			if err == nil || config != (helperConfig{}) {
				t.Fatal("invalid configuration produced a partial or successful result")
			}
		})
	}
	object := map[string]json.RawMessage{}
	if err := json.Unmarshal(valid, &object); err != nil {
		t.Fatal(err)
	}
	for key := range object {
		t.Run("missing or null "+key, func(t *testing.T) {
			t.Parallel()
			fields := map[string]json.RawMessage{}
			for name, value := range object {
				fields[name] = value
			}
			delete(fields, key)
			for range 2 {
				data, err := json.Marshal(fields)
				if err != nil {
					t.Fatal(err)
				}
				if got, err := decodeHelperConfig(t.Context(), data); err == nil || got != (helperConfig{}) {
					t.Fatal("missing/null configuration field was accepted")
				}
				fields[key] = json.RawMessage(`null`)
			}
		})
	}
	got, err := decodeHelperConfig(t.Context(), valid)
	if err != nil || got != helperConfigFixture() {
		t.Fatalf("valid helper configuration changed on decode: %v", err)
	}
}

func TestHelperConfigRejectsUnsafeResourceGeometry(t *testing.T) {
	t.Parallel()
	for _, test := range []struct {
		name   string
		change func(*helperConfig)
	}{
		{name: "schema", change: func(c *helperConfig) { c.SchemaVersion = 2 }},
		{name: "missing mode", change: func(c *helperConfig) { c.Mode = "" }},
		{name: "unknown mode", change: func(c *helperConfig) { c.Mode = "apply" }},
		{name: "case variant mode", change: func(c *helperConfig) { c.Mode = "Shadow" }},
		{name: "shadow source enforcement", change: func(c *helperConfig) { c.BindingSource = radiusShadowSource }},
		{name: "unknown binding source", change: func(c *helperConfig) { c.Mode = agent.Shadow; c.BindingSource = "unknown" }},
		{name: "root reader", change: func(c *helperConfig) { c.ReaderUID = 0 }},
		{name: "root operator", change: func(c *helperConfig) { c.OperatorUID = 0 }},
		{name: "same identity", change: func(c *helperConfig) { c.OperatorUID = c.ReaderUID }},
		{name: "zero timeout", change: func(c *helperConfig) { c.RequestTimeoutMS = 0 }},
		{name: "long timeout", change: func(c *helperConfig) { c.RequestTimeoutMS = 10001 }},
		{name: "invalid pin", change: func(c *helperConfig) { c.Profile.SHA256 = strings.Repeat("A", 64) }},
		{name: "closed expected writer", change: func(c *helperConfig) { c.ExpectedGeneration.Ready = false }},
		{name: "invalid writer", change: func(c *helperConfig) { c.ExpectedGeneration.Sequence = 0 }},
		{name: "relative profile", change: func(c *helperConfig) { c.Profile.Directory = "profile" }},
		{name: "root directory", change: func(c *helperConfig) { c.StateDir = "/" }},
		{name: "unclean directory", change: func(c *helperConfig) { c.GenerationDir = "/run/../run/writers" }},
		{name: "control path", change: func(c *helperConfig) { c.NFTExecutable = "/usr/sbin/nft\x00" }},
		{name: "long resource path", change: func(c *helperConfig) { c.StateDir = "/" + strings.Repeat("x", 4096) }},
		{name: "overlapping directories", change: func(c *helperConfig) { c.GenerationDir = c.StateDir + "/writers" }},
		{name: "reverse overlapping directories", change: func(c *helperConfig) { c.Profile.Directory = c.StateDir + "/profile" }},
		{name: "same directories", change: func(c *helperConfig) { c.Profile.Directory = c.StateDir }},
		{name: "socket under private root", change: func(c *helperConfig) { c.StatusSocket = c.StateDir + "/status.sock" }},
		{name: "same sockets", change: func(c *helperConfig) { c.StatusSocket = c.RequestSocket }},
		{name: "relative socket", change: func(c *helperConfig) { c.StatusSocket = "status.sock" }},
		{name: "long socket", change: func(c *helperConfig) { c.RequestSocket = "/" + strings.Repeat("x", 107) }},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			config := helperConfigFixture()
			test.change(&config)
			if err := config.validate(); err == nil {
				t.Fatal("unsafe typed configuration passed validation")
			}
			if got, err := decodeHelperConfig(t.Context(), helperConfigBytes(t, config)); err == nil || got != (helperConfig{}) {
				t.Fatal("unsafe privileged resource configuration was accepted")
			}
		})
	}
	for _, timeout := range []uint32{1, 10000} {
		config := helperConfigFixture()
		config.RequestTimeoutMS = timeout
		if _, err := decodeHelperConfig(t.Context(), helperConfigBytes(t, config)); err != nil {
			t.Fatal("valid timeout boundary rejected")
		}
	}
	config := helperConfigFixture()
	config.Mode = agent.Shadow
	if got, err := decodeHelperConfig(t.Context(), helperConfigBytes(t, config)); err != nil || got.Mode != agent.Shadow {
		t.Fatal("explicit shadow configuration was rejected or changed to enforcement")
	}
}

func TestHelperConfigShadowSourceRequiresExplicitShadowMode(t *testing.T) {
	t.Parallel()
	config := helperConfigFixture()
	config.Mode, config.BindingSource = agent.Shadow, radiusShadowSource
	got, err := decodeHelperConfig(t.Context(), helperConfigBytes(t, config))
	if err != nil || got != config {
		t.Fatal("explicit shadow input configuration rejected", err)
	}
}

func TestHelperConfigurationCancellationAndSupervision(t *testing.T) {
	t.Parallel()
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if got, err := decodeHelperConfig(ctx, helperConfigBytes(t, helperConfigFixture())); !errors.Is(err, context.Canceled) || got != (helperConfig{}) {
		t.Fatal("canceled configuration returned usable resources")
	}
	// Deliberately invalid input; production wiring always supplies a context.
	var missingContext context.Context
	if _, err := decodeHelperConfig(missingContext, []byte{}); err == nil {
		t.Fatal("nil context accepted")
	}
	if err := serveHelperPair(missingContext, nil, nil); err == nil {
		t.Fatal("missing supervisor inputs accepted")
	}
	for _, name := range []string{"request failure", "status failure", "parent cancellation", "unexpected success"} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			var joined atomic.Int32
			failure := errors.New("synthetic server failure")
			wait := func(ctx context.Context) error {
				<-ctx.Done()
				joined.Add(1)
				return ctx.Err()
			}
			fail := func(context.Context) error { joined.Add(1); return failure }
			requests, status := fail, wait
			switch name {
			case "status failure":
				requests, status = wait, fail
			case "parent cancellation":
				requests, status = wait, wait
				cancel()
			case "unexpected success":
				requests = func(context.Context) error { joined.Add(1); return nil }
			}
			err := serveHelperPair(ctx, requests, status)
			if !errors.Is(err, context.Canceled) || joined.Load() != 2 {
				t.Fatal("supervision did not cancel and join both servers")
			}
			if strings.HasSuffix(name, "failure") && !errors.Is(err, failure) {
				t.Fatal("supervision lost the triggering failure")
			}
		})
	}
}

func FuzzHelperConfig(f *testing.F) {
	f.Add(helperConfigBytes(f, helperConfigFixture()))
	f.Add([]byte(`{"schema_version":1}`))
	f.Add([]byte(`null`))
	f.Fuzz(func(t *testing.T, data []byte) {
		config, err := decodeHelperConfig(t.Context(), data)
		if err != nil {
			if config != (helperConfig{}) {
				t.Fatal("invalid configuration returned a partial value")
			}
			return
		}
		if err := config.validate(); err != nil {
			t.Fatal("accepted configuration violated its privileged bounds")
		}
		got, err := decodeHelperConfig(t.Context(), helperConfigBytes(t, config))
		if err != nil || got != config {
			t.Fatal("accepted configuration did not round-trip")
		}
	})
}

func TestConfiguredListenerRequiresNamedUnixStream(t *testing.T) {
	t.Parallel()
	stream := serviceUnitListener(t)
	closed := serviceUnitListener(t)
	if err := closed.Close(); err != nil {
		t.Fatal(err)
	}
	packet, err := net.ListenUnix("unixpacket", &net.UnixAddr{
		Name: filepath.Join(t.TempDir(), "packet.sock"), Net: "unixpacket",
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := packet.Close(); err != nil {
			t.Error(err)
		}
	})
	for _, test := range []struct {
		name     string
		listener *net.UnixListener
		path     string
		expected bool
	}{
		{name: "stream", listener: stream, path: stream.Addr().String(), expected: true},
		{name: "wrong path", listener: stream, path: "/unavailable"},
		{name: "packet socket", listener: packet, path: packet.Addr().String()},
		{name: "missing", path: "/unavailable"},
		{name: "zero value", listener: &net.UnixListener{}, path: "/unavailable"},
		{name: "closed", listener: closed, path: closed.Addr().String()},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			if got := configuredListenerMatches(test.listener, test.path); got != test.expected {
				t.Fatal("listener geometry/type did not match the configured stream contract")
			}
		})
	}
}
