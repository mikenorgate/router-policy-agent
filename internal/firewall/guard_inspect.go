package firewall

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/netip"
	"slices"

	"github.com/mikenorgate/router-policy-agent/internal/policy"
	"github.com/mikenorgate/router-policy-agent/internal/strictjson"
)

// guardInventory is a verified observation of our fixed objects, not fresh
// authorization, boot restoration, or a fence against another privileged writer.
type guardInventory struct {
	cohort            []string
	addresses4        []netip.Addr
	addresses6        []netip.Addr
	managedInterfaces []string
	leases            int
}

type guardListings struct {
	inet   []byte
	netdev []byte
}

type guardTableObservation struct {
	sets map[string]listedSet
}

func (layout *guardLayout) inspect(ctx context.Context, listings guardListings) (*guardInventory, error) {
	if ctx == nil || layout == nil || len(layout.managedInterfaces) == 0 {
		return nil, errors.New("firewall: missing guarded inspection dependencies")
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	inet, err := layout.inspectTable(ctx, "inet", listings.inet)
	if err != nil {
		return nil, err
	}
	netdev, err := layout.inspectTable(ctx, "netdev", listings.netdev)
	if err != nil {
		return nil, err
	}
	cohort, err := listedGuardMACs(inet.sets[cohortSet].Elements)
	if err != nil {
		return nil, err
	}
	other, err := listedGuardMACs(netdev.sets[cohortSet].Elements)
	if err != nil || !slices.Equal(cohort, other) {
		return nil, errors.New("firewall: permanent guard cohorts differ")
	}
	addresses4, err := listedGuardAddresses(ctx, inet.sets[classified4Set].Elements, true)
	if err != nil {
		return nil, err
	}
	addresses6, err := listedGuardAddresses(ctx, inet.sets[classified6Set].Elements, false)
	if err != nil {
		return nil, err
	}
	inventory := &guardInventory{
		cohort: cohort, addresses4: addresses4, addresses6: addresses6,
		managedInterfaces: slices.Clone(layout.managedInterfaces),
	}
	if err := inventory.checkMirrors(ctx, inet, netdev); err != nil {
		return nil, err
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return inventory, nil
}

func (layout *guardLayout) inspectTable(
	ctx context.Context,
	family string,
	data []byte,
) (*guardTableObservation, error) {
	schema, err := layout.schema(family)
	if err != nil {
		return nil, err
	}
	if err := strictjson.Object(data, []string{"nftables"}, nil, maximumOutput); err != nil {
		return nil, err
	}
	var listing struct {
		Objects []json.RawMessage `json:"nftables"`
	}
	if err := strictjson.Decode(data, &listing, maximumOutput); err != nil {
		return nil, err
	}
	count := 2 + len(schema.sets) + len(schema.chains)
	for _, rules := range schema.rules {
		count += len(rules)
	}
	if len(listing.Objects) != count {
		return nil, errors.New("firewall: guarded object inventory differs")
	}
	if err := verifyOwnedListingHeader(listing.Objects[:2], family); err != nil {
		return nil, err
	}
	observed := &guardTableObservation{sets: map[string]listedSet{}}
	handles, chains, rules := map[uint64]bool{}, map[string]bool{}, map[string]int{}
	for _, raw := range listing.Objects[2:] {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		kind, fields, err := guardObject(raw)
		if err != nil {
			return nil, err
		}
		var expected map[string]any
		name, key := "", "name"
		if kind == "rule" {
			key = "chain"
		}
		if err := json.Unmarshal(fields[key], &name); err != nil {
			return nil, errors.New("firewall: invalid guarded object identity")
		}
		switch kind {
		case "set":
			expected = schema.sets[name]
			if _, exists := observed.sets[name]; exists {
				return nil, errors.New("firewall: duplicate guarded set")
			}
		case "chain":
			expected = schema.chains[name]
			if chains[name] {
				return nil, errors.New("firewall: duplicate guarded chain")
			}
			chains[name] = true
		case "rule":
			if rules[name] >= len(schema.rules[name]) {
				return nil, errors.New("firewall: unexpected guarded rule")
			}
			expected = map[string]any{"family": family, "table": ownedTable,
				"chain": name, "expr": schema.rules[name][rules[name]]}
			rules[name]++
		default:
			return nil, errors.New("firewall: unexpected guarded object")
		}
		handle, err := checkGuardObject(fields, expected, kind == "set")
		if err != nil {
			return nil, err
		}
		if handles[handle] {
			return nil, errors.New("firewall: duplicate guarded object handle")
		}
		handles[handle] = true
		if kind == "set" {
			var set listedSet
			if err := json.Unmarshal(raw, &struct {
				Set *listedSet `json:"set"`
			}{Set: &set}); err != nil {
				return nil, errors.New("firewall: guarded set decoding failed")
			}
			if uint64(len(set.Elements)) > set.Size {
				return nil, errors.New("firewall: guarded set capacity exceeded")
			}
			observed.sets[name] = set
		}
	}
	for name := range schema.chains {
		if !chains[name] || rules[name] != len(schema.rules[name]) {
			return nil, errors.New("firewall: guarded chain or rules missing")
		}
	}
	if len(observed.sets) != len(schema.sets) {
		return nil, errors.New("firewall: guarded sets missing")
	}
	return observed, nil
}

func guardObject(raw json.RawMessage) (string, map[string]json.RawMessage, error) {
	if err := strictjson.Object(raw, nil, []string{"set", "chain", "rule"}, maximumOutput); err != nil {
		return "", nil, err
	}
	object := map[string]json.RawMessage{}
	if err := json.Unmarshal(raw, &object); err != nil || len(object) != 1 {
		return "", nil, errors.New("firewall: exact guarded object required")
	}
	for kind, value := range object {
		fields := map[string]json.RawMessage{}
		if err := strictjson.Decode(value, &fields, maximumOutput); err != nil || fields == nil {
			return "", nil, errors.New("firewall: guarded object fields required")
		}
		return kind, fields, nil
	}
	return "", nil, errors.New("firewall: guarded object missing")
}

func checkGuardObject(fields map[string]json.RawMessage, expected map[string]any, hasElements bool) (uint64, error) {
	if expected == nil {
		return 0, errors.New("firewall: guarded object outside fixed schema")
	}
	required := make([]string, 0, len(expected)+1)
	for key := range expected {
		required = append(required, key)
	}
	required = append(required, "handle")
	optional := []string{}
	if hasElements {
		optional = append(optional, "elem")
	}
	data, err := json.Marshal(fields)
	if err != nil {
		return 0, errors.New("firewall: guarded header encoding failed")
	}
	if err := strictjson.Object(data, required, optional, maximumOutput); err != nil {
		return 0, err
	}
	var handle uint64
	if err := json.Unmarshal(fields["handle"], &handle); err != nil || handle == 0 {
		return 0, errors.New("firewall: invalid guarded object handle")
	}
	delete(fields, "handle")
	delete(fields, "elem")
	actual, err := json.Marshal(fields)
	if err != nil {
		return 0, errors.New("firewall: guarded header normalization failed")
	}
	want, err := json.Marshal(expected)
	if err != nil {
		return 0, errors.New("firewall: fixed guard schema encoding failed")
	}
	actual, err = canonicalGuardJSON(actual)
	if err != nil {
		return 0, err
	}
	if !bytes.Equal(actual, want) {
		return 0, errors.New("firewall: fixed guard schema or rule order differs")
	}
	return handle, nil
}

func listedGuardMACs(elements []json.RawMessage) ([]string, error) {
	if err := validateMACs(elements); err != nil {
		return nil, err
	}
	macs := make([]string, 0, len(elements))
	for _, raw := range elements {
		var mac string
		if err := json.Unmarshal(raw, &mac); err != nil {
			return nil, errors.New("firewall: invalid guarded mac")
		}
		macs = append(macs, mac)
	}
	slices.Sort(macs)
	return macs, nil
}

func listedGuardAddresses(ctx context.Context, elements []json.RawMessage, ipv4 bool) ([]netip.Addr, error) {
	addresses := make([]netip.Addr, 0, len(elements))
	seen := map[netip.Addr]bool{}
	for _, raw := range elements {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		var value string
		if err := json.Unmarshal(raw, &value); err != nil {
			return nil, errors.New("firewall: canonical classified address required")
		}
		prefix := "/128"
		if ipv4 {
			prefix = "/32"
		}
		address, err := policy.ParseHost(value + prefix)
		if err != nil || address.Is4() != ipv4 || address.String() != value || seen[address] {
			return nil, errors.New("firewall: invalid or duplicate classified address")
		}
		seen[address] = true
		addresses = append(addresses, address)
	}
	slices.SortFunc(addresses, netip.Addr.Compare)
	return addresses, nil
}
