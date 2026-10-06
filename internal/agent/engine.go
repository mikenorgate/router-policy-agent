// Package agent coordinates helper-owned evidence, durable state and application.
// It neither collects directory credentials nor accepts privileged reader inputs.
package agent

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"time"

	"github.com/mikenorgate/router-policy-agent/internal/binding"
	"github.com/mikenorgate/router-policy-agent/internal/ipc"
	"github.com/mikenorgate/router-policy-agent/internal/policy"
	"github.com/mikenorgate/router-policy-agent/internal/state"
)

// Mode must be explicitly selected by trusted helper configuration.
type Mode string

const (
	// Shadow records validation anchors but never changes firewall objects.
	Shadow Mode = "shadow"
	// Enforce requires a separately qualified, restricted firewall backend.
	Enforce Mode = "enforce"
)

// Persistence exposes normal state operations only. Initialization and reset
// are deliberately absent. Both functions must honor context cancellation.
type Persistence struct {
	Load func(context.Context) (state.Document, error)
	Save func(context.Context, state.Document) error
}

// Enforcement is trusted helper wiring, never reader-supplied implementation.
// Seal removes owned application permits and retains closed classification of
// both existing and supplied cohort members, without touching unrelated rules.
// Apply must atomically replace owned tuples, preserve the closed cohort and
// enforce absolute kernel deadlines, the floor and mapping-generation checks.
// It must retain Authorization's original age anchor, not rebuild a lifetime
// from its diagnostic snapshot or a newly sampled UTC clock.
// A successful callback is not itself packet-level evidence of those properties.
type Enforcement struct {
	Seal  func(context.Context, []string) error
	Apply func(context.Context, policy.Authorization, []string) error
}

// Options contains privileged local dependencies. Bindings must reread an
// independently authenticated, qualified producer on every call. Clock is the
// helper's synchronized UTC source; runtime wiring must independently qualify
// that source. The engine measures elapsed time itself. Reader IPC supplies
// neither time configuration nor ownership evidence.
type Options struct {
	Mode     Mode
	State    Persistence
	Bindings func(context.Context) (binding.Snapshot, error)
	Clock    func() time.Time
	Firewall Enforcement
}

// Engine owns an immutable compiler and serializes startup, requests and stop.
// The caller retains ownership of the persistent store and backend resources.
// Engine must not be copied or used before Start succeeds.
type Engine struct {
	compiler         *policy.Compiler
	options          Options
	gate             chan struct{}
	started          bool
	clock            helperClock
	lease            time.Duration
	maximumDevices   int
	startupTime      time.Time
	startupDirectory time.Time
}

// New copies and validates the helper-owned baseline. Shadow mode rejects
// firewall callbacks to prevent accidentally mutating packets during an audit.
func New(baseline policy.Baseline, options Options) (*Engine, error) {
	validMode := options.Mode == Shadow || options.Mode == Enforce
	validFirewall := options.Mode == Enforce && options.Firewall.Seal != nil && options.Firewall.Apply != nil ||
		options.Mode == Shadow && options.Firewall.Seal == nil && options.Firewall.Apply == nil
	if !validMode || !validFirewall || options.State.Load == nil || options.State.Save == nil ||
		options.Bindings == nil || options.Clock == nil {
		return nil, errors.New("agent: invalid helper dependencies")
	}
	compiler, err := policy.New(baseline)
	if err != nil {
		return nil, err
	}
	return &Engine{
		compiler: compiler, options: options, gate: make(chan struct{}, 1),
		lease: time.Duration(baseline.LeaseSeconds) * time.Second, maximumDevices: baseline.MaximumDevices,
	}, nil
}

// Start clears application permits before loading state. It never initializes
// missing state or restores a persisted permit. Directory and ownership evidence
// must be freshly observed after startup before they can authorize. Unsafe state
// or clocks leave enforcement closed; kernel classification is a backend gate.
func (engine *Engine) Start(ctx context.Context) error {
	if err := engine.acquire(ctx); err != nil {
		return err
	}
	defer engine.release()
	engine.started = false
	if err := engine.seal(ctx, nil); err != nil {
		return err
	}
	document, err := engine.options.State.Load(ctx)
	if err != nil {
		return fmt.Errorf("agent: load startup state: %w", err)
	}
	document, err = state.Clone(document)
	if err != nil {
		return err
	}
	if err := engine.seal(ctx, document.CohortMACs); err != nil {
		return err
	}
	now, err := engine.now()
	if err != nil {
		return err
	}
	if now.authorization.Before(document.Ledger.LastValidated) {
		return errors.New("agent: unsafe startup clock")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	engine.started = true
	engine.startupTime = now.authorization
	engine.startupDirectory = document.LastDirectoryObservedAt
	return nil
}

// Process is the authenticated IPC callback. It observes and saves the complete
// directory watermark/cohort before collecting bindings, then independently
// compiles and durably saves deadline/alias anchors before application. Failures
// cannot renew a lease or restore older directory decisions. In enforce mode
// they trigger bounded permit removal, even if the request has been canceled.
func (engine *Engine) Process(
	ctx context.Context,
	snapshot policy.DirectorySnapshot,
) (receipt ipc.Receipt, result error) {
	if err := engine.acquire(ctx); err != nil {
		return ipc.Receipt{}, err
	}
	defer engine.release()
	if !engine.started {
		return ipc.Receipt{}, errors.New("agent: helper is not started")
	}
	var cohort []string
	defer func() {
		if result != nil {
			receipt = ipc.Receipt{}
			cleanup, cancel := context.WithTimeout(context.WithoutCancel(ctx), 2*time.Second)
			defer cancel()
			if err := engine.seal(cleanup, cohort); err != nil {
				engine.started = false
				result = errors.Join(result, err)
			}
		}
	}()
	document, err := engine.options.State.Load(ctx)
	if err != nil {
		return ipc.Receipt{}, fmt.Errorf("agent: load request state: %w", err)
	}
	document, err = state.Clone(document)
	if err != nil {
		return ipc.Receipt{}, err
	}
	cohort = document.CohortMACs
	if _, err := state.CheckDirectory(document, snapshot); err != nil {
		return ipc.Receipt{}, err
	}
	now, err := engine.now()
	if err != nil {
		return ipc.Receipt{}, err
	}
	isBeforeStartup := snapshot.ObservedAt.Before(engine.startupTime)
	isPersistedReplay := !engine.startupDirectory.IsZero() && !snapshot.ObservedAt.After(engine.startupDirectory)
	if isBeforeStartup || isPersistedReplay || !binding.Fresh(snapshot.ObservedAt, now.utc, engine.lease) {
		return ipc.Receipt{}, errors.New("agent: directory observation predates startup or is not fresh")
	}
	ledger, err := engine.compiler.ObserveDirectory(ctx, snapshot, now.authorization, document.Ledger)
	if err != nil {
		return ipc.Receipt{}, err
	}
	observed, err := state.Advance(document, snapshot, ledger)
	if err != nil {
		return ipc.Receipt{}, err
	}
	cohort = observed.CohortMACs
	if err := engine.options.State.Save(ctx, observed); err != nil {
		return ipc.Receipt{}, fmt.Errorf("agent: persist observation: %w", err)
	}
	bindings, err := engine.options.Bindings(ctx)
	if err != nil {
		return ipc.Receipt{}, fmt.Errorf("agent: collect qualified bindings: %w", err)
	}
	now, err = engine.now()
	if err != nil {
		return ipc.Receipt{}, err
	}
	// Validate against actual UTC as well as the conservative authorization
	// clock. Its monotonic lower bound must not admit future-dated evidence.
	if err := binding.Validate(bindings, now.utc, engine.lease, engine.maximumDevices); err != nil {
		return ipc.Receipt{}, err
	}
	if err := engine.checkStartupBindings(ctx, bindings); err != nil {
		return ipc.Receipt{}, err
	}
	authorization, err := engine.compiler.CompileAuthorization(ctx, policy.Input{
		Directory: snapshot, Bindings: bindings, Ledger: observed.Ledger, Now: now.authorization,
	}, now.anchor)
	if err != nil {
		return ipc.Receipt{}, err
	}
	candidate, err := authorization.Snapshot(ctx)
	if err != nil {
		return ipc.Receipt{}, err
	}
	next, err := state.Advance(observed, snapshot, candidate.Ledger)
	if err != nil {
		return ipc.Receipt{}, err
	}
	if err := engine.options.State.Save(ctx, next); err != nil {
		return ipc.Receipt{}, fmt.Errorf("agent: persist authorization anchors: %w", err)
	}
	if err := ctx.Err(); err != nil {
		return ipc.Receipt{}, err
	}
	now, err = engine.now()
	if err != nil {
		return ipc.Receipt{}, err
	}
	for index := range candidate.Grants {
		if _, err := authorization.Remaining(index, now.authorization); err != nil {
			return ipc.Receipt{}, fmt.Errorf("agent: authorization expired before application: %w", err)
		}
	}
	status := ipc.StatusShadow
	if engine.options.Mode == Enforce {
		if err := engine.options.Firewall.Apply(ctx, authorization, slices.Clone(cohort)); err != nil {
			return ipc.Receipt{}, fmt.Errorf("agent: apply owned policy: %w", err)
		}
		status = ipc.StatusApplied
	}
	if err := ctx.Err(); err != nil {
		return ipc.Receipt{}, err
	}
	return ipc.Receipt{SchemaVersion: 1, Status: status, BaselineHash: candidate.BaselineHash,
		CompiledAt: candidate.CompiledAt, GrantCount: len(candidate.Grants), DenialCount: len(candidate.Denials)}, nil
}

func (engine *Engine) checkStartupBindings(ctx context.Context, snapshot binding.Snapshot) error {
	if snapshot.ObservedAt.Before(engine.startupTime) {
		return errors.New("agent: binding snapshot predates helper startup")
	}
	for _, record := range snapshot.Records {
		if err := ctx.Err(); err != nil {
			return err
		}
		if record.AssociatedAt.Before(engine.startupTime) {
			return errors.New("agent: association evidence predates helper startup")
		}
		for _, address := range record.Addresses {
			if address.ObservedAt.Before(engine.startupTime) {
				return errors.New("agent: address evidence predates helper startup")
			}
		}
	}
	return nil
}

// Stop prevents further requests and removes only owned application permits.
// It does not erase durable state or closed classifications.
func (engine *Engine) Stop(ctx context.Context) error {
	if err := engine.acquire(ctx); err != nil {
		return err
	}
	defer engine.release()
	engine.started = false
	return engine.seal(ctx, nil)
}

func (engine *Engine) seal(ctx context.Context, cohort []string) error {
	if engine.options.Mode == Shadow {
		return nil
	}
	return engine.options.Firewall.Seal(ctx, slices.Clone(cohort))
}

func (engine *Engine) acquire(ctx context.Context) error {
	if engine == nil || engine.gate == nil || ctx == nil {
		return errors.New("agent: invalid engine or context")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	select {
	case engine.gate <- struct{}{}:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (engine *Engine) release() {
	<-engine.gate
}
