package firewall

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"slices"
	"strconv"

	"github.com/mikenorgate/router-policy-agent/internal/strictjson"
)

const (
	maximumReviewedRuleset = 4 << 20
	maximumRulesetObjects  = 8192
	maximumChainDepth      = 16
)

// reviewedRuleset is immutable comparison data prepared by an independent
// image-policy owner. It must never be learned from the running router or
// supplied over reader IPC. Decoding does not authenticate its source or prove
// P01-P10; trusted loading, semantic review and packet qualification are separate.
type reviewedRuleset struct {
	program []byte
	digest  string
}

// rulesetObservation describes a single verified listing, not permission or
// proof of translator state. The caller still needs the shared writer fence.
type rulesetObservation struct {
	digest string
	guards *guardInventory
}

type rulesetObject struct {
	kind, family, table, name string
	fields                    map[string]json.RawMessage
}

type rulesetProgram struct {
	objects    map[string]json.RawMessage
	rules      map[string][]json.RawMessage
	chains     map[string]bool
	baseChains map[string]bool
	edges      map[string][]string
	hooks      map[string]bool
}

// decodeReviewedRuleset accepts a distinct artifact schema, not native listing
// output. Counters have no statistics and objects have no runtime handles.
func decodeReviewedRuleset(ctx context.Context, data []byte) (*reviewedRuleset, error) {
	if ctx == nil {
		return nil, errors.New("firewall: missing reviewed ruleset context")
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if err := strictjson.Object(data, []string{"schema_version", "objects"}, nil, maximumReviewedRuleset); err != nil {
		return nil, err
	}
	var artifact struct {
		Schema  int               `json:"schema_version"`
		Objects []json.RawMessage `json:"objects"`
	}
	if err := strictjson.Decode(data, &artifact, maximumReviewedRuleset); err != nil {
		return nil, err
	}
	if artifact.Schema != 1 {
		return nil, errors.New("firewall: unsupported reviewed ruleset schema")
	}
	program, err := normalizeRuleset(ctx, artifact.Objects, false)
	if err != nil {
		return nil, err
	}
	sum := sha256.Sum256(program)
	return &reviewedRuleset{program: program, digest: hex.EncodeToString(sum[:])}, nil
}

func (contract *reviewedRuleset) inspect(
	ctx context.Context,
	layout *guardLayout,
	data []byte,
) (*rulesetObservation, error) {
	validContract := contract != nil && len(contract.program) != 0
	validLayout := layout != nil && len(layout.managedInterfaces) != 0
	if ctx == nil || !validContract || !validLayout {
		return nil, errors.New("firewall: missing reviewed ruleset inspection dependencies")
	}
	if err := ctx.Err(); err != nil {
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
	if len(listing.Objects) < 2 || len(listing.Objects) > maximumRulesetObjects {
		return nil, errors.New("firewall: complete ruleset inventory size invalid")
	}
	if err := verifyListingMetadata(listing.Objects[0]); err != nil {
		return nil, err
	}
	protected, guards, err := splitRuleset(ctx, listing.Objects)
	if err != nil {
		return nil, err
	}
	program, err := normalizeRuleset(ctx, protected, true)
	if err != nil {
		return nil, err
	}
	if !bytes.Equal(program, contract.program) {
		return nil, errors.New("firewall: reviewed ruleset drift detected")
	}
	inventory, err := layout.inspect(ctx, guards)
	if err != nil {
		return nil, err
	}
	if err := checkRulesetHookOrder(listing.Objects[1:]); err != nil {
		return nil, err
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	sum := sha256.Sum256(program)
	digest := hex.EncodeToString(sum[:])
	if digest != contract.digest {
		return nil, errors.New("firewall: reviewed ruleset identity differs")
	}
	return &rulesetObservation{digest: digest, guards: inventory}, nil
}

func splitRuleset(ctx context.Context, objects []json.RawMessage) ([]json.RawMessage, guardListings, error) {
	protected := []json.RawMessage{}
	owned := map[string][]json.RawMessage{
		"inet": {objects[0]}, "netdev": {objects[0]},
	}
	for _, raw := range objects[1:] {
		if err := ctx.Err(); err != nil {
			return nil, guardListings{}, err
		}
		object, err := decodeRulesetObject(raw)
		if err != nil {
			return nil, guardListings{}, err
		}
		if object.table != ownedTable {
			protected = append(protected, raw)
			continue
		}
		if _, exists := owned[object.family]; !exists {
			return nil, guardListings{}, errors.New("firewall: unexpected helper table family")
		}
		owned[object.family] = append(owned[object.family], raw)
	}
	encode := func(objects []json.RawMessage) ([]byte, error) {
		data, err := json.Marshal(struct {
			Objects []json.RawMessage `json:"nftables"`
		}{Objects: objects})
		if err != nil {
			return nil, errors.New("firewall: complete guard listing encoding failed")
		}
		return data, nil
	}
	inet, err := encode(owned["inet"])
	if err != nil {
		return nil, guardListings{}, err
	}
	netdev, err := encode(owned["netdev"])
	if err != nil {
		return nil, guardListings{}, err
	}
	return protected, guardListings{inet: inet, netdev: netdev}, nil
}

func normalizeRuleset(ctx context.Context, objects []json.RawMessage, actual bool) ([]byte, error) {
	if len(objects) == 0 || len(objects) > maximumRulesetObjects {
		return nil, errors.New("firewall: reviewed object inventory size invalid")
	}
	program := rulesetProgram{
		objects: map[string]json.RawMessage{}, rules: map[string][]json.RawMessage{},
		chains: map[string]bool{}, edges: map[string][]string{}, hooks: map[string]bool{},
		baseChains: map[string]bool{},
	}
	tables, handles := map[string]bool{}, map[string]bool{}
	collections := map[string]bool{}
	for _, raw := range objects {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		object, err := decodeRulesetObject(raw)
		if err != nil {
			return nil, err
		}
		if object.table == ownedTable {
			return nil, errors.New("firewall: reviewed artifact cannot own helper objects")
		}
		if err := object.normalize(actual); err != nil {
			return nil, err
		}
		table := object.family + "/" + object.table
		if object.kind == "set" || object.kind == "map" {
			key := table + "/" + object.name
			if collections[key] {
				return nil, errors.New("firewall: duplicate collection namespace")
			}
			collections[key] = true
		}
		if actual && object.kind != "table" {
			key := table + "/" + string(object.fields["handle"])
			if handles[key] {
				return nil, errors.New("firewall: duplicate ruleset object handle")
			}
			handles[key] = true
		}
		delete(object.fields, "handle")
		if err := program.append(object); err != nil {
			return nil, err
		}
		if object.kind == "table" {
			tables[table] = true
		}
	}
	for _, raw := range objects {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		object, err := decodeRulesetObject(raw)
		if err != nil {
			return nil, err
		}
		if !tables[object.family+"/"+object.table] {
			return nil, errors.New("firewall: ruleset object has no reviewed table")
		}
	}
	if !program.hooks["input"] || !program.hooks["forward"] || !program.hooks["output"] {
		return nil, errors.New("firewall: reviewed standalone drop hooks missing")
	}
	if err := checkRulesetHookOrder(objects); err != nil {
		return nil, err
	}
	if err := program.checkGraph(ctx); err != nil {
		return nil, err
	}
	encoded, err := json.Marshal(struct {
		Objects map[string]json.RawMessage   `json:"objects"`
		Rules   map[string][]json.RawMessage `json:"rules"`
	}{Objects: program.objects, Rules: program.rules})
	if err != nil {
		return nil, errors.New("firewall: reviewed program encoding failed")
	}
	return encoded, nil
}

func (program *rulesetProgram) append(object rulesetObject) error {
	encoded, err := json.Marshal(object.fields)
	if err != nil {
		return errors.New("firewall: ruleset object encoding failed")
	}
	canonical, err := canonicalGuardJSON(encoded)
	if err != nil {
		return err
	}
	key := object.family + "/" + object.table + "/" + object.name
	if object.kind == "rule" {
		if _, exists := program.rules[key]; !exists {
			program.rules[key] = []json.RawMessage{}
		}
		program.rules[key] = append(program.rules[key], canonical)
		targets, err := rulesetRuleTargets(object.fields["expr"])
		if err != nil {
			return err
		}
		for _, target := range targets {
			program.edges[key] = append(program.edges[key], object.family+"/"+object.table+"/"+target)
		}
		return nil
	}
	identity := object.kind + "/" + key
	if _, exists := program.objects[identity]; exists {
		return errors.New("firewall: duplicate reviewed object identity")
	}
	program.objects[identity] = canonical
	if object.kind == "chain" {
		program.chains[key] = true
		program.baseChains[key] = object.fields["hook"] != nil
		isFilter := string(object.fields["type"]) == `"filter"`
		isDrop := string(object.fields["policy"]) == `"drop"`
		if object.family == "inet" && isFilter && isDrop {
			var hook string
			if err := json.Unmarshal(object.fields["hook"], &hook); err != nil {
				return errors.New("firewall: invalid reviewed drop hook")
			}
			program.hooks[hook] = true
		}
	}
	return nil
}

func (program *rulesetProgram) checkGraph(ctx context.Context) error {
	for chain := range program.rules {
		if !program.chains[chain] {
			return errors.New("firewall: reviewed rule chain missing")
		}
	}
	for _, targets := range program.edges {
		for _, target := range targets {
			if !program.chains[target] || program.baseChains[target] {
				return errors.New("firewall: reviewed regular jump target missing")
			}
		}
	}
	heights, path := map[string]int{}, map[string]bool{}
	var visit func(string, int) (int, error)
	visit = func(chain string, depth int) (int, error) {
		if err := ctx.Err(); err != nil {
			return 0, err
		}
		if depth > maximumChainDepth || path[chain] {
			return 0, errors.New("firewall: reviewed chain graph cyclic or excessive")
		}
		if height, exists := heights[chain]; exists {
			if depth+height-1 > maximumChainDepth {
				return 0, errors.New("firewall: reviewed chain graph excessive")
			}
			return height, nil
		}
		path[chain] = true
		defer delete(path, chain)
		height := 1
		for _, target := range program.edges[chain] {
			child, err := visit(target, depth+1)
			if err != nil {
				return 0, err
			}
			height = max(height, child+1)
		}
		heights[chain] = height
		return height, nil
	}
	for chain := range program.chains {
		if _, err := visit(chain, 1); err != nil {
			return err
		}
	}
	return nil
}

// Same-priority base chains have no qualified ordering. Include the helper's
// fixed hooks in this check, rather than considering only reviewed tables.
func checkRulesetHookOrder(objects []json.RawMessage) error {
	seen := map[string]bool{}
	for _, raw := range objects {
		object, err := decodeRulesetObject(raw)
		if err != nil {
			return err
		}
		if object.kind != "chain" || object.fields["hook"] == nil {
			continue
		}
		var hook, device string
		var priority int32
		if err := json.Unmarshal(object.fields["hook"], &hook); err != nil {
			return errors.New("firewall: invalid ruleset hook")
		}
		if rawDevice := object.fields["dev"]; rawDevice != nil {
			if err := json.Unmarshal(rawDevice, &device); err != nil {
				return errors.New("firewall: invalid ruleset hook device")
			}
		}
		if err := json.Unmarshal(object.fields["prio"], &priority); err != nil {
			return errors.New("firewall: invalid ruleset hook priority")
		}
		families := []string{object.family}
		if object.family == "inet" {
			families = []string{"ip", "ip6"}
		}
		for _, family := range families {
			key := family + "/" + hook + "/" + device + "/" + strconv.FormatInt(int64(priority), 10)
			if seen[key] {
				return errors.New("firewall: ambiguous ruleset hook ordering")
			}
			seen[key] = true
		}
	}
	return nil
}

func canonicalRulesetElements(raw json.RawMessage) (json.RawMessage, error) {
	values := []json.RawMessage{}
	if raw != nil {
		if err := json.Unmarshal(raw, &values); err != nil || values == nil {
			return nil, errors.New("firewall: ruleset element array required")
		}
	}
	if len(values) > maximumTupleCount {
		return nil, errors.New("firewall: reviewed element quota exceeded")
	}
	canonical := make([]string, 0, len(values))
	for _, value := range values {
		encoded, err := canonicalGuardJSON(value)
		if err != nil {
			return nil, err
		}
		canonical = append(canonical, string(encoded))
	}
	slices.Sort(canonical)
	for index, value := range canonical {
		if index > 0 && canonical[index-1] == value {
			return nil, errors.New("firewall: duplicate reviewed element")
		}
		values[index] = json.RawMessage(value)
	}
	encoded, err := json.Marshal(values)
	if err != nil {
		return nil, errors.New("firewall: reviewed element encoding failed")
	}
	return encoded, nil
}
