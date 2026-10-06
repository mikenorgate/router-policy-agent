package firewall

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"

	"github.com/mikenorgate/router-policy-agent/internal/policy"
	"github.com/mikenorgate/router-policy-agent/internal/strictjson"
)

const maximumRouterProfile = 8 << 20

// routerProfile binds compiler/rendering configuration and the independently
// reviewed object contract to one image-owned pin. Its digest is not the
// compiler hash, an observed ruleset hash, or proof that P01-P10 are enforced.
// The caller must obtain the pin from its verified owning release, not from
// this file, reader IPC, generation metadata or a live firewall listing.
type routerProfile struct {
	digest   string
	renderer *renderer
	layout   *guardLayout
	ruleset  *reviewedRuleset
}

type profileEnvelope struct {
	SchemaVersion   int             `json:"schema_version"`
	Baseline        json.RawMessage `json:"baseline"`
	ReviewedRuleset json.RawMessage `json:"reviewed_ruleset"`
}

// decodePinnedProfile authenticates exact bytes against an independently
// supplied pin, then builds every component from the same validated baseline.
// It does not verify a release signature or establish filesystem ownership;
// production loading must use loadRouterProfile, with a trusted pin source.
// The pin covers serialized bytes, not equivalent normalized JSON. The format
// has no self-declared digest or signature that could replace the trusted pin.
func decodePinnedProfile(ctx context.Context, data []byte, pin string) (*routerProfile, error) {
	if ctx == nil {
		return nil, errors.New("firewall: missing router profile context")
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if !generationHash(pin) {
		return nil, errors.New("firewall: invalid router profile digest pin")
	}
	if len(data) == 0 || len(data) > maximumRouterProfile {
		return nil, errors.New("firewall: invalid router profile size")
	}
	sum := sha256.Sum256(data)
	digest := hex.EncodeToString(sum[:])
	if digest != pin {
		return nil, errors.New("firewall: router profile digest mismatch")
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	keys := []string{"schema_version", "baseline", "reviewed_ruleset"}
	if err := strictjson.Object(data, keys, nil, maximumRouterProfile); err != nil {
		return nil, profileFailure("invalid structure", err)
	}
	var envelope profileEnvelope
	if err := strictjson.Decode(data, &envelope, maximumRouterProfile); err != nil {
		return nil, profileFailure("invalid schema", err)
	}
	if envelope.SchemaVersion != 1 {
		return nil, errors.New("firewall: unsupported router profile schema")
	}
	baseline, err := policy.DecodeBaseline(envelope.Baseline)
	if err != nil {
		return nil, profileFailure("invalid baseline", err)
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	ruleset, err := decodeReviewedRuleset(ctx, envelope.ReviewedRuleset)
	if err != nil {
		return nil, profileFailure("invalid reviewed ruleset", err)
	}
	renderer, err := newRenderer(baseline)
	if err != nil {
		return nil, profileFailure("compiler construction failed", err)
	}
	layout, err := newGuardLayout(baseline)
	if err != nil {
		return nil, profileFailure("guard construction failed", err)
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return &routerProfile{digest: digest, renderer: renderer, layout: layout, ruleset: ruleset}, nil
}

// Profile paths and policy data stay out of printable diagnostics. Trusted
// callers can still inspect the cause using errors.Is/As; IPC must keep using
// fixed response codes rather than exposing any underlying error chain.
type profileLoadError struct {
	stage string
	cause error
}

func profileFailure(stage string, cause error) error {
	return &profileLoadError{stage: stage, cause: cause}
}

func (e *profileLoadError) Error() string { return "firewall: router profile " + e.stage }
func (e *profileLoadError) Unwrap() error { return e.cause }
