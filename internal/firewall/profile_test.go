package firewall

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"strings"
	"testing"

	"github.com/mikenorgate/router-policy-agent/internal/policy"
)

func routerProfileFixture(t testing.TB) []byte {
	t.Helper()
	baseline, err := os.ReadFile("../../examples/baseline.json")
	if err != nil {
		t.Fatal(err)
	}
	data, err := json.Marshal(profileEnvelope{
		SchemaVersion: 1, Baseline: baseline, ReviewedRuleset: []byte(reviewedArtifactFixture),
	})
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func routerProfileDigest(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

func TestPinnedProfilePairsCompilationRenderingAndInspection(t *testing.T) {
	t.Parallel()
	data := routerProfileFixture(t)
	digest := routerProfileDigest(data)
	profile, err := decodePinnedProfile(t.Context(), data, digest)
	if err != nil {
		t.Fatal(err)
	}
	if profile.digest != digest || profile.digest == profile.ruleset.digest {
		t.Fatal("bundle pin was confused with the normalized ruleset identity")
	}
	_, _, _, input := renderFixture(t)
	authorization, err := profile.renderer.compiler.CompileAuthorization(t.Context(), input, policy.CaptureAge())
	if err != nil {
		t.Fatal(err)
	}
	candidate, err := authorization.Snapshot(t.Context())
	if err != nil || len(candidate.Grants) != 1 || candidate.BaselineHash == profile.digest {
		t.Fatal("paired compiler lost its independent baseline identity")
	}
	batch, err := profile.renderer.prepare(t.Context(), replacement{
		authorization: authorization, cohort: []string{"02:00:00:00:00:01"}, now: input.Now,
	})
	if err != nil || !bytes.Contains(batch.data, []byte(`"lease_to6_tcp"`)) {
		t.Fatalf("paired renderer rejected its compiler authorization: %v", err)
	}
	_, listing := fullRulesetFixture(t)
	observation, err := profile.ruleset.inspect(t.Context(), profile.layout, listing)
	if err != nil || observation.digest != profile.ruleset.digest {
		t.Fatalf("paired contract/layout did not inspect a complete fixture: %v", err)
	}
	before, err := profile.layout.program(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	clear(data)
	after, err := profile.layout.program(t.Context())
	if err != nil || !bytes.Equal(before, after) || profile.digest != digest {
		t.Fatal("profile retained caller-owned mutable bytes")
	}
	if _, err := profile.ruleset.inspect(t.Context(), profile.layout, listing); err != nil {
		t.Fatal("caller mutation changed the reviewed object contract")
	}
}

func TestPinnedProfilesCannotExchangeAuthorization(t *testing.T) {
	t.Parallel()
	original := routerProfileFixture(t)
	changed := bytes.Replace(
		original,
		[]byte(`"generation":"synthetic-v1"`),
		[]byte(`"generation":"synthetic-v2"`),
		1,
	)
	if bytes.Equal(original, changed) {
		t.Fatal("test did not change its synthetic catalog")
	}
	first, err := decodePinnedProfile(t.Context(), original, routerProfileDigest(original))
	if err != nil {
		t.Fatal(err)
	}
	second, err := decodePinnedProfile(t.Context(), changed, routerProfileDigest(changed))
	if err != nil {
		t.Fatal(err)
	}
	_, _, _, input := renderFixture(t)
	authorization, err := first.renderer.compiler.CompileAuthorization(t.Context(), input, policy.CaptureAge())
	if err != nil {
		t.Fatal(err)
	}
	if batch, err := second.renderer.prepare(t.Context(), replacement{
		authorization: authorization, cohort: []string{"02:00:00:00:00:01"}, now: input.Now,
	}); err == nil || batch != nil {
		t.Fatal("a different pinned compiler catalog accepted old authorization")
	}
	if first.digest == second.digest || first.ruleset.digest != second.ruleset.digest {
		t.Fatal("whole-bundle identity did not bind catalog-only changes")
	}
}

func TestPinnedProfileRejectsInvalidBundleAndPin(t *testing.T) {
	t.Parallel()
	original := routerProfileFixture(t)
	for _, test := range []struct {
		name string
		data []byte
		pin  string
	}{
		{name: "missing pin", data: original},
		{name: "short pin", data: original, pin: "abc"},
		{name: "uppercase pin", data: original, pin: strings.ToUpper(routerProfileDigest(original))},
		{name: "nonhex pin", data: original, pin: strings.Repeat("z", 64)},
		{name: "wrong pin", data: original, pin: strings.Repeat("0", 64)},
		{name: "empty data", data: []byte{}},
		{name: "oversized data", data: bytes.Repeat([]byte("x"), maximumRouterProfile+1)},
		{name: "array", data: []byte(`[]`)},
		{name: "null", data: []byte(`null`)},
		{name: "missing baseline", data: []byte(`{"schema_version":1,"reviewed_ruleset":{}}`)},
		{name: "missing ruleset", data: []byte(`{"schema_version":1,"baseline":{}}`)},
		{name: "wrong schema", data: bytes.Replace(
			original,
			[]byte(`"schema_version":1`),
			[]byte(`"schema_version":2`),
			1,
		)},
		{name: "unknown field", data: bytes.Replace(
			original,
			[]byte(`"schema_version":1`),
			[]byte(`"schema_version":1,"private_note":"synthetic-private-value"`),
			1,
		)},
		{name: "self supplied digest", data: bytes.Replace(
			original,
			[]byte(`"schema_version":1`),
			[]byte(`"schema_version":1,"sha256":"self-asserted"`),
			1,
		)},
		{name: "case variant", data: bytes.Replace(
			original,
			[]byte(`"baseline":`),
			[]byte(`"Baseline":`),
			1,
		)},
		{name: "duplicate key", data: bytes.Replace(
			original,
			[]byte(`"schema_version":1`),
			[]byte(`"schema_version":1,"schema_version":1`),
			1,
		)},
		{name: "nested duplicate", data: bytes.Replace(
			original,
			[]byte(`"generation":"synthetic-v1"`),
			[]byte(`"generation":"synthetic-v1","generation":"synthetic-v1"`),
			1,
		)},
		{name: "null baseline", data: []byte(`{"schema_version":1,"baseline":null,"reviewed_ruleset":{}}`)},
		{name: "null ruleset", data: []byte(`{"schema_version":1,"baseline":{},"reviewed_ruleset":null}`)},
		{name: "invalid baseline", data: bytes.Replace(
			original,
			[]byte(`"lease_seconds":90`),
			[]byte(`"lease_seconds":91`),
			1,
		)},
		{name: "invalid ruleset", data: bytes.Replace(
			original,
			[]byte(`"policy":"drop"`),
			[]byte(`"policy":"accept"`),
			1,
		)},
		{name: "live listing is not a profile", data: []byte(`{"nftables":[]}`)},
		{name: "trailing JSON", data: append(bytes.Clone(original), []byte(`{}`)...)},
		{name: "invalid utf8", data: append(bytes.Clone(original), 0xff)},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			pin := test.pin
			if pin == "" && test.name != "missing pin" {
				// A matching test pin exercises strict decoding, not just mismatch.
				pin = routerProfileDigest(test.data)
			}
			profile, err := decodePinnedProfile(t.Context(), test.data, pin)
			if err == nil || profile != nil {
				t.Fatal("invalid profile produced full or partial trusted components")
			}
			if strings.Contains(err.Error(), "synthetic-private-value") {
				t.Fatal("profile diagnostic exposed input data")
			}
		})
	}
}

func TestPinnedProfileCancellationAndPrivateDiagnostics(t *testing.T) {
	t.Parallel()
	data := routerProfileFixture(t)
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	profile, err := decodePinnedProfile(ctx, data, routerProfileDigest(data))
	if !errors.Is(err, context.Canceled) || profile != nil {
		t.Fatal("canceled profile decoding returned components or lost cancellation")
	}
	var missingContext context.Context // Deliberately exercise the fail-closed nil dependency.
	if profile, err := decodePinnedProfile(missingContext, data, routerProfileDigest(data)); err == nil || profile != nil {
		t.Fatal("nil context accepted")
	}
	marker := errors.Join(errors.New("synthetic-private-path"), context.DeadlineExceeded)
	err = profileFailure("read failed", marker)
	if strings.Contains(err.Error(), "synthetic-private-path") || !errors.Is(err, context.DeadlineExceeded) {
		t.Fatal("redaction lost cancellation or exposed the underlying private error")
	}
}

func FuzzPinnedProfile(f *testing.F) {
	f.Add(routerProfileFixture(f))
	f.Add([]byte(`{"schema_version":1,"baseline":{},"reviewed_ruleset":{}}`))
	f.Add([]byte{})
	f.Fuzz(func(t *testing.T, data []byte) {
		pin := routerProfileDigest(data)
		profile, err := decodePinnedProfile(t.Context(), data, pin)
		if err != nil {
			if profile != nil {
				t.Fatal("failed decoding returned partial components")
			}
			return
		}
		if profile.digest != pin || profile.renderer == nil || profile.renderer.compiler == nil ||
			profile.layout == nil || profile.ruleset == nil {
			t.Fatal("accepted profile lost its pinned component pairing")
		}
		repeated, err := decodePinnedProfile(t.Context(), bytes.Clone(data), pin)
		if err != nil || repeated.digest != profile.digest ||
			!bytes.Equal(repeated.ruleset.program, profile.ruleset.program) {
			t.Fatal("pinned profile decoding is not deterministic")
		}
		changed := bytes.Clone(data)
		changed = append(changed, ' ')
		if different, err := decodePinnedProfile(t.Context(), changed, pin); err == nil || different != nil {
			t.Fatal("an equivalent but unpinned JSON representation was accepted")
		}
	})
}
