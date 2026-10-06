package policy

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"time"
)

// Authorization is an immutable, process-local compiler result with an elapsed
// age anchor. It is trusted helper plumbing, not a reader input or a persisted
// permit. A zero value authorizes nothing. Copies retain the original anchor.
type Authorization struct {
	data *authorization
}

type authorization struct {
	candidate Candidate
	anchor    time.Time
}

// AgeAnchor is a helper-local elapsed-time sample. Its private reading cannot be
// supplied as a UTC timestamp, restored from JSON or edited by another package.
// Copies preserve the sample; the zero value is invalid.
type AgeAnchor struct {
	tick time.Time
}

// CaptureAge samples time.Now before the helper obtains its trusted UTC reading.
// On the qualified Linux runtime, time.Since uses this reading's monotonic clock.
func CaptureAge() AgeAnchor {
	return AgeAnchor{tick: time.Now()}
}

// MarshalJSON prevents persisting or transporting an elapsed-time sample.
func (anchor AgeAnchor) MarshalJSON() ([]byte, error) {
	return nil, errors.New("policy: age anchor cannot be serialized")
}

// UnmarshalJSON invalidates the sample and rejects serialized age anchors.
// Its pointer receiver follows encoding/json's canonical mutation contract.
func (anchor *AgeAnchor) UnmarshalJSON(_ []byte) error {
	if anchor != nil {
		*anchor = AgeAnchor{}
	}
	return errors.New("policy: age anchor cannot be deserialized")
}

// CompileAuthorization compiles raw evidence and pins its remaining lifetime to
// anchor, captured by the helper before obtaining input.Now.
// Directory/binding authentication and UTC synchronization remain the helper's
// responsibility. Reader IPC must never supply either clock or this result.
func (compiler *Compiler) CompileAuthorization(
	ctx context.Context,
	input Input,
	anchor AgeAnchor,
) (Authorization, error) {
	if anchor.tick.IsZero() || time.Since(anchor.tick) < 0 {
		return Authorization{}, errors.New("policy: invalid authorization age anchor")
	}
	input.Now = input.Now.Round(0).UTC()
	candidate, err := compiler.CompileContext(ctx, input)
	if err != nil {
		return Authorization{}, err
	}
	return Authorization{data: &authorization{candidate: candidate, anchor: anchor.tick}}, nil
}

// Snapshot returns an independent diagnostic/state copy, never an editable
// reference to the result used for enforcement. It does not renew authorization.
func (authorization Authorization) Snapshot(ctx context.Context) (Candidate, error) {
	if ctx == nil || authorization.data == nil {
		return Candidate{}, errors.New("policy: missing authorization or context")
	}
	if err := ctx.Err(); err != nil {
		return Candidate{}, err
	}
	owned := authorization.data.candidate
	ledger, err := CloneLedger(owned.Ledger)
	if err != nil {
		return Candidate{}, fmt.Errorf("policy: copy authorization ledger: %w", err)
	}
	owned.Ledger = ledger
	owned.Denials = slices.Clone(owned.Denials)
	owned.Grants = slices.Clone(owned.Grants)
	for index := range owned.Grants {
		if err := ctx.Err(); err != nil {
			return Candidate{}, err
		}
		grant := &owned.Grants[index]
		grant.Device.Variants = slices.Clone(grant.Device.Variants)
		grant.Peer.Variants = slices.Clone(grant.Peer.Variants)
		grant.Contributors = slices.Clone(grant.Contributors)
	}
	if err := ctx.Err(); err != nil {
		return Candidate{}, err
	}
	return owned, nil
}

// Remaining clips a grant by both its UTC expiry and elapsed time since the
// original helper reading. Queueing, compilation and persistence consume the
// same lifetime; a later UTC rollback cannot restart it. The index refers to
// Snapshot's grant ordering, not a caller-supplied grant or deadline.
func (authorization Authorization) Remaining(index int, utc time.Time) (time.Duration, error) {
	if authorization.data == nil || utc.IsZero() {
		return 0, errors.New("policy: missing authorization or utc reading")
	}
	owned := authorization.data
	if index < 0 || index >= len(owned.candidate.Grants) || utc.Before(owned.candidate.CompiledAt) {
		return 0, errors.New("policy: invalid authorization grant or utc reading")
	}
	elapsed := time.Since(owned.anchor)
	if elapsed < 0 {
		return 0, errors.New("policy: authorization elapsed clock regressed")
	}
	expires := owned.candidate.Grants[index].ExpiresAt()
	remaining := min(expires.Sub(utc), expires.Sub(owned.candidate.CompiledAt)-elapsed)
	if remaining <= 0 {
		return 0, errors.New("policy: authorization expired")
	}
	return remaining, nil
}

// MarshalJSON refuses to turn a process-local lifetime into restorable data.
func (authorization Authorization) MarshalJSON() ([]byte, error) {
	return nil, errors.New("policy: authorization cannot be serialized")
}

// UnmarshalJSON rejects reader/persisted permits and invalidates any old value.
// Its pointer receiver follows encoding/json's canonical mutation contract.
func (authorization *Authorization) UnmarshalJSON(_ []byte) error {
	if authorization != nil {
		*authorization = Authorization{}
	}
	return errors.New("policy: authorization cannot be deserialized")
}
