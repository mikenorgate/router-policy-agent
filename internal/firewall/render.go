package firewall

import (
	"cmp"
	"context"
	"encoding/json"
	"errors"
	"slices"
	"time"

	"github.com/mikenorgate/router-policy-agent/internal/policy"
)

// Preparation and command execution each consume a bounded part of the lease.
// The checked executor refuses a prepared batch that waited beyond this window.
const preparationBudget = 2 * time.Second

type renderer struct {
	compiler       *policy.Compiler
	maximumDevices int
	lease          time.Duration
}

type replacement struct {
	candidate      policy.Candidate
	cohort         []string
	existingCohort []string
	now            time.Time
}

type preparedBatch struct {
	data        []byte
	preparedAt  time.Time
	startBefore time.Time
}

type change struct {
	Flush *setChange     `json:"flush,omitempty"`
	Add   *elementChange `json:"add,omitempty"`
}

type setChange struct {
	Set objectReference `json:"set"`
}

type elementChange struct {
	Element elements `json:"element"`
}

func newRenderer(baseline policy.Baseline) (*renderer, error) {
	compiler, err := policy.New(baseline)
	if err != nil {
		return nil, err
	}
	return &renderer{
		compiler: compiler, maximumDevices: baseline.MaximumDevices,
		lease: time.Duration(baseline.LeaseSeconds) * time.Second,
	}, nil
}

// prepare is private trusted-helper plumbing, not a reader grant interface.
// existingCohort must come from independently checked kernel objects. Rendering
// retains all known classification and appends only newly classified identities.
// It does not install the packet guards, qualify bindings or coordinate mappings.
func (renderer *renderer) prepare(ctx context.Context, input replacement) (*preparedBatch, error) {
	if renderer == nil || ctx == nil {
		return nil, errors.New("firewall: missing renderer or context")
	}
	validClock := !input.now.IsZero() && !input.now.Before(input.candidate.CompiledAt)
	validAge := input.now.Before(input.candidate.CompiledAt.Add(renderer.lease))
	if !validClock || !validAge {
		return nil, errors.New("firewall: candidate clock or age invalid")
	}
	if err := renderer.compiler.CheckCandidate(ctx, input.candidate); err != nil {
		return nil, err
	}
	cohort, additions, err := renderer.cohort(input)
	if err != nil {
		return nil, err
	}
	tuples := map[string]map[tupleKey]time.Time{}
	for _, name := range grantSets {
		tuples[name] = map[tupleKey]time.Time{}
	}
	for _, grant := range input.candidate.Grants {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		if !cohort[grant.MAC] {
			return nil, errors.New("firewall: grant identity is outside the permanent cohort")
		}
		compatible := false
		for _, device := range grant.Device.Variants {
			for _, peer := range grant.Peer.Variants {
				if device.Is4() != peer.Is4() {
					continue
				}
				compatible = true
				key := tupleKey{
					interfaceName: grant.Interface, mac: grant.MAC, device: device, peer: peer, port: grant.Port,
				}
				name := grantSet(grant.Direction, grant.Protocol, device.Is4())
				deadline := grant.ExpiresAt()
				if deadline.After(tuples[name][key]) {
					tuples[name][key] = deadline
				}
			}
		}
		if !compatible {
			return nil, errors.New("firewall: grant has no compatible installed representation")
		}
	}
	commands := make([]change, 0, 2*len(grantSets)+1)
	for _, name := range grantSets {
		commands = append(commands, change{Flush: &setChange{Set: ownedRef(name)}})
	}
	if len(additions) != 0 {
		values := make([]json.RawMessage, 0, len(additions))
		for _, mac := range additions {
			value, err := json.Marshal(mac)
			if err != nil {
				return nil, errors.New("firewall: cohort encoding failed")
			}
			values = append(values, value)
		}
		commands = append(commands, addElements(cohortSet, values))
	}
	for _, name := range grantSets {
		keys := make([]tupleKey, 0, len(tuples[name]))
		for key := range tuples[name] {
			keys = append(keys, key)
		}
		slices.SortFunc(keys, compareTuple)
		values := make([]json.RawMessage, 0, len(keys))
		for _, key := range keys {
			if err := ctx.Err(); err != nil {
				return nil, err
			}
			value, err := renderTuple(key, tuples[name][key].Sub(input.now))
			if err != nil {
				return nil, err
			}
			values = append(values, value)
		}
		if len(values) != 0 {
			commands = append(commands, addElements(name, values))
		}
	}
	data, err := json.Marshal(struct {
		Commands []change `json:"nftables"`
	}{Commands: commands})
	if err != nil {
		return nil, errors.New("firewall: owned transaction encoding failed")
	}
	if err := validateBatch(data); err != nil {
		return nil, err
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return &preparedBatch{
		data: data, preparedAt: input.now, startBefore: input.now.Add(preparationBudget),
	}, nil
}

func (renderer *renderer) cohort(input replacement) (map[string]bool, []string, error) {
	known, combined := map[string]bool{}, map[string]bool{}
	for index, identities := range [][]string{input.existingCohort, input.cohort} {
		if len(identities) > renderer.maximumDevices {
			return nil, nil, errors.New("firewall: cohort input exceeds quota")
		}
		seen := map[string]bool{}
		for _, mac := range identities {
			canonical, err := policy.CanonicalMAC(mac)
			if err != nil || canonical != mac || seen[mac] {
				return nil, nil, errors.New("firewall: invalid or duplicate cohort identity")
			}
			seen[mac], combined[mac] = true, true
			if index == 0 {
				known[mac] = true
			}
		}
	}
	if len(combined) > renderer.maximumDevices {
		return nil, nil, errors.New("firewall: permanent cohort quota exceeded")
	}
	additions := make([]string, 0)
	for mac := range combined {
		if !known[mac] {
			additions = append(additions, mac)
		}
	}
	slices.Sort(additions)
	return combined, additions, nil
}

func grantSet(direction policy.Direction, protocol string, ipv4 bool) string {
	prefix, family := "lease_to", "6"
	if direction == policy.FromDevice {
		prefix = "lease_from"
	}
	if ipv4 {
		family = "4"
	}
	return prefix + family + "_" + protocol
}

func ownedRef(name string) objectReference {
	return objectReference{Family: "inet", Table: ownedTable, Name: name}
}

func addElements(name string, values []json.RawMessage) change {
	return change{Add: &elementChange{Element: elements{
		Family: "inet", Table: ownedTable, Name: name, Values: values,
	}}}
}

func renderTuple(key tupleKey, remaining time.Duration) (json.RawMessage, error) {
	timeout := int((remaining - preparationBudget - commandBudget) / time.Second)
	if timeout < 1 || timeout > maximumElementLifetime {
		return nil, errors.New("firewall: grant has insufficient or excessive remaining lifetime")
	}
	// Mixed types are confined to nftables' ordered JSON tuple boundary.
	data, err := json.Marshal(map[string]any{"elem": map[string]any{
		"timeout": timeout, "val": map[string]any{"concat": []any{
			key.interfaceName, key.mac, key.device.String(), key.peer.String(), key.port,
		}},
	}})
	if err != nil {
		return nil, errors.New("firewall: tuple encoding failed")
	}
	return data, nil
}

func compareTuple(left, right tupleKey) int {
	return cmp.Or(
		cmp.Compare(left.interfaceName, right.interfaceName),
		cmp.Compare(left.mac, right.mac),
		left.device.Compare(right.device),
		left.peer.Compare(right.peer),
		cmp.Compare(left.port, right.port),
	)
}
