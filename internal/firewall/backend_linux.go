package firewall

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"slices"
	"time"

	"github.com/mikenorgate/router-policy-agent/internal/policy"
	"github.com/mikenorgate/router-policy-agent/internal/state"
	"github.com/mikenorgate/router-policy-agent/internal/strictjson"
)

// guardedBackend is private helper plumbing. Its dependencies and expected
// generation come from the owning router integration, never reader IPC. The
// caller owns their lifetimes. Construction does not qualify P01-P10, release
// provenance, actual writer cooperation, clock synchronization or translation.
type guardedBackend struct {
	options backendOptions
}

type backendOptions struct {
	profile    *routerProfile
	executor   *process
	generation *generationGate
	expected   writerGeneration
	clock      func() time.Time
}

func newGuardedBackend(options backendOptions) (*guardedBackend, error) {
	if err := validateBackendOptions(options); err != nil {
		return nil, err
	}
	return &guardedBackend{options: options}, nil
}

func validateBackendOptions(options backendOptions) error {
	validProfile := options.profile != nil && generationHash(options.profile.digest)
	validExecutor := options.executor != nil && options.executor.gate != nil
	validGeneration := options.generation != nil && options.generation.fence != nil
	if !validProfile || !validExecutor || !validGeneration || options.clock == nil {
		return errors.New("firewall: missing guarded backend dependencies")
	}
	p := options.profile
	validCompiler := p.renderer != nil && p.renderer.compiler != nil
	validLayout := p.layout != nil && len(p.layout.managedInterfaces) != 0
	validContract := p.ruleset != nil && len(p.ruleset.program) != 0 && generationHash(p.ruleset.digest)
	if !validCompiler || !validLayout || !validContract {
		return errors.New("firewall: incomplete guarded backend profile")
	}
	if err := options.expected.validate(); err != nil {
		return err
	}
	if !options.expected.Ready || options.expected.FloorHash != p.ruleset.digest {
		return errors.New("firewall: guarded backend generation does not match its reviewed floor")
	}
	return nil
}

// apply preserves the compiler's original age anchor across writer/executor
// queueing, inspection and rendering. Any failure attempts bounded sealing even
// after cancellation or a generation change. A failed cleanup is returned too;
// callers must not report application success or reopen readiness on failure.
func (b *guardedBackend) apply(
	ctx context.Context,
	authorization policy.Authorization,
	classification state.Classification,
) (result error) {
	if b == nil || ctx == nil {
		return errors.New("firewall: missing guarded backend or context")
	}
	if err := validateBackendOptions(b.options); err != nil {
		return err
	}
	history := state.EmptyClassification()
	defer func() {
		if result == nil {
			return
		}
		cleanup, cancel := context.WithTimeout(context.WithoutCancel(ctx), 2*time.Second)
		defer cancel()
		result = errors.Join(result, b.seal(cleanup, history))
	}()
	owned, err := state.CloneClassification(classification)
	if err != nil {
		return err
	}
	history = owned
	post := []byte{}
	if err := b.options.generation.with(ctx, b.options.expected, func(bounded context.Context) error {
		var err error
		post, err = b.options.executor.replaceGuarded(
			bounded,
			b.options,
			authorization,
			history,
		)
		return err
	}); err != nil {
		return err
	}
	// Capture the complete post-commit listing while both gates are held,
	// then validate those owned bytes without extending the writer critical
	// section. This is evidence at that fenced point, not a reusable permit.
	// A cooperating later writer must revoke before changing its owned state.
	_, err = b.options.profile.ruleset.inspect(ctx, b.options.profile.layout, post)
	if err != nil {
		return fmt.Errorf("firewall: verify applied baseline: %w", err)
	}
	return nil
}

// seal does not require ready generation metadata or an unchanged external
// floor: revocation must remain possible after either fails. It still requires
// the shared fence and exact code-owned guard objects. It removes all lease
// mirrors atomically and unions deny-only classification without retiring any
// kernel history. It never repairs external rules or opens forwarding at boot.
func (b *guardedBackend) seal(ctx context.Context, classification state.Classification) error {
	if b == nil || ctx == nil {
		return errors.New("firewall: missing guarded sealing dependencies")
	}
	if err := validateBackendOptions(b.options); err != nil {
		return err
	}
	history, err := state.CloneClassification(classification)
	if err != nil {
		return err
	}
	var receipt sealingObservation
	if err := b.options.generation.fence.With(ctx, func(bounded context.Context, _ *os.Root) error {
		var err error
		receipt, err = b.options.executor.sealGuarded(bounded, b.options.profile.layout, history)
		return err
	}); err != nil {
		return err
	}
	sealed, actual, err := inspectSealingGuards(ctx, b.options.profile.layout, receipt.data)
	if err != nil {
		return fmt.Errorf("firewall: verify sealed guards: %w", err)
	}
	sameCohort := slices.Equal(actual.MACs, receipt.history.MACs)
	sameAddresses := slices.Equal(actual.IPv4, receipt.history.IPv4) && slices.Equal(actual.IPv6, receipt.history.IPv6)
	if sealed.leases != 0 || !sameCohort || !sameAddresses {
		return errors.New("firewall: sealed lease or classification verification failed")
	}
	return ctx.Err()
}

func (p *process) replaceGuarded(
	ctx context.Context,
	options backendOptions,
	authorization policy.Authorization,
	history state.Classification,
) ([]byte, error) {
	if err := p.acquire(ctx); err != nil {
		return nil, err
	}
	defer p.release()
	observation, err := p.observeProfile(ctx, options.profile)
	if err != nil {
		return nil, fmt.Errorf("firewall: inspect application baseline: %w", err)
	}
	logical, err := options.profile.renderer.prepare(ctx, replacement{
		authorization: authorization, cohort: history.MACs,
		existingCohort: observation.guards.cohort, now: options.clock(),
	})
	if err != nil {
		return nil, fmt.Errorf("firewall: render application: %w", err)
	}
	prepared, err := prepareClassifiedGuards(ctx, logical, history)
	if err != nil {
		return nil, fmt.Errorf("firewall: prepare application mirrors: %w", err)
	}
	if err := observation.guards.checkPreparedReplacement(ctx, prepared); err != nil {
		return nil, fmt.Errorf("firewall: check application replacement: %w", err)
	}
	if _, err := p.run(ctx, commandInput{op: applyGuarded, guarded: prepared}); err != nil {
		return nil, fmt.Errorf("firewall: apply guarded replacement: %w", err)
	}
	return p.run(ctx, commandInput{op: inspectWholeRuleset})
}

// observeProfile is called only while the executor gate is already held.
func (p *process) observeProfile(ctx context.Context, profile *routerProfile) (*rulesetObservation, error) {
	data, err := p.run(ctx, commandInput{op: inspectWholeRuleset})
	if err != nil {
		return nil, err
	}
	return profile.ruleset.inspect(ctx, profile.layout, data)
}

type sealingObservation struct {
	data    []byte
	history state.Classification
}

func (p *process) sealGuarded(
	ctx context.Context,
	layout *guardLayout,
	history state.Classification,
) (sealingObservation, error) {
	if err := p.acquire(ctx); err != nil {
		return sealingObservation{}, err
	}
	defer p.release()
	data, err := p.run(ctx, commandInput{op: inspectWholeRuleset})
	if err != nil {
		return sealingObservation{}, err
	}
	inventory, retained, err := inspectSealingGuards(ctx, layout, data)
	if err != nil {
		return sealingObservation{}, fmt.Errorf("firewall: inspect sealing guards: %w", err)
	}
	for index, values := range []*[]string{&history.MACs, &history.IPv4, &history.IPv6} {
		additions := retained.MACs
		switch index {
		case 1:
			additions = retained.IPv4
		case 2:
			additions = retained.IPv6
		}
		*values = append(*values, additions...)
		slices.Sort(*values)
		*values = slices.Compact(*values)
	}
	prepared, err := prepareGuardSeal(ctx, history)
	if err != nil {
		return sealingObservation{}, err
	}
	if err := inventory.checkPreparedReplacement(ctx, prepared); err != nil {
		return sealingObservation{}, err
	}
	if _, err := p.run(ctx, commandInput{op: sealGuarded, guarded: prepared}); err != nil {
		return sealingObservation{}, err
	}
	data, err = p.run(ctx, commandInput{op: inspectWholeRuleset})
	if err != nil {
		return sealingObservation{}, err
	}
	return sealingObservation{data: data, history: history}, nil
}

// inspectSealingGuards checks the exact fixed objects but deliberately does not
// require consistent leased mirrors. An expiry-boundary observation, damaged
// lease content or closed owner generation must not prevent removing permits.
// Both permanent MAC sets are retained and repaired to their union. Historical
// address observations remain denial only, never ownership or authorization.
func inspectSealingGuards(
	ctx context.Context,
	layout *guardLayout,
	data []byte,
) (*guardInventory, state.Classification, error) {
	empty := state.EmptyClassification()
	if ctx == nil || layout == nil {
		return nil, empty, errors.New("firewall: missing sealing inspection dependencies")
	}
	if err := strictjson.Object(data, []string{"nftables"}, nil, maximumOutput); err != nil {
		return nil, empty, err
	}
	var listing struct {
		Objects []json.RawMessage `json:"nftables"`
	}
	if err := strictjson.Decode(data, &listing, maximumOutput); err != nil {
		return nil, empty, err
	}
	if len(listing.Objects) < 2 || len(listing.Objects) > maximumRulesetObjects {
		return nil, empty, errors.New("firewall: sealing inventory size invalid")
	}
	if err := verifyListingMetadata(listing.Objects[0]); err != nil {
		return nil, empty, err
	}
	_, guards, err := splitRuleset(ctx, listing.Objects)
	if err != nil {
		return nil, empty, err
	}
	inet, err := layout.inspectTable(ctx, "inet", guards.inet)
	if err != nil {
		return nil, empty, err
	}
	netdev, err := layout.inspectTable(ctx, "netdev", guards.netdev)
	if err != nil {
		return nil, empty, err
	}
	macs, err := listedGuardMACs(inet.sets[cohortSet].Elements)
	if err != nil {
		return nil, empty, err
	}
	other, err := listedGuardMACs(netdev.sets[cohortSet].Elements)
	if err != nil {
		return nil, empty, err
	}
	macs = append(macs, other...)
	slices.Sort(macs)
	macs = slices.Compact(macs)
	addresses4, err := listedGuardAddresses(ctx, inet.sets[classified4Set].Elements, true)
	if err != nil {
		return nil, empty, err
	}
	addresses6, err := listedGuardAddresses(ctx, inet.sets[classified6Set].Elements, false)
	if err != nil {
		return nil, empty, err
	}
	history := state.Classification{MACs: macs, IPv4: []string{}, IPv6: []string{}}
	for _, address := range addresses4 {
		history.IPv4 = append(history.IPv4, address.String())
	}
	for _, address := range addresses6 {
		history.IPv6 = append(history.IPv6, address.String())
	}
	slices.Sort(history.IPv4)
	slices.Sort(history.IPv6)
	owned, err := state.CloneClassification(history)
	if err != nil {
		return nil, empty, err
	}
	leaseElements := 0
	for _, name := range grantSets {
		for _, ref := range guardLeaseRefs(name) {
			observation := inet
			if ref.Family == "netdev" {
				observation = netdev
			}
			leaseElements += len(observation.sets[ref.Name].Elements)
		}
	}
	if err := ctx.Err(); err != nil {
		return nil, empty, err
	}
	return &guardInventory{
		cohort: macs, addresses4: addresses4, addresses6: addresses6,
		managedInterfaces: slices.Clone(layout.managedInterfaces), leases: leaseElements,
	}, owned, nil
}
