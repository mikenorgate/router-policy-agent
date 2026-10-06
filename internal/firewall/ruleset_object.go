package firewall

import (
	"bytes"
	"encoding/json"
	"errors"
	"slices"

	"github.com/mikenorgate/router-policy-agent/internal/strictjson"
)

func decodeRulesetObject(raw json.RawMessage) (rulesetObject, error) {
	outer := map[string]json.RawMessage{}
	if err := strictjson.Decode(raw, &outer, maximumOutput); err != nil {
		return rulesetObject{}, err
	}
	if len(outer) != 1 {
		return rulesetObject{}, errors.New("firewall: exact ruleset object required")
	}
	object := rulesetObject{fields: map[string]json.RawMessage{}}
	for kind, fields := range outer {
		switch kind {
		case "table", "chain", "set", "map", "rule", "counter":
			object.kind = kind
		default:
			// Flowtables, compatibility extensions and other unqualified object
			// kinds are not invisible exceptions to a reviewed ruleset.
			return rulesetObject{}, errors.New("firewall: unsupported ruleset object kind")
		}
		if err := strictjson.Decode(fields, &object.fields, maximumOutput); err != nil || object.fields == nil {
			return rulesetObject{}, errors.New("firewall: ruleset object fields required")
		}
	}
	for key, value := range object.fields {
		canonical, err := canonicalGuardJSON(value)
		if err != nil {
			return rulesetObject{}, err
		}
		object.fields[key] = canonical
	}
	var err error
	object.family, err = rulesetString(object.fields["family"])
	if err != nil {
		return rulesetObject{}, err
	}
	switch object.family {
	case "inet", "ip", "ip6", "arp", "bridge", "netdev":
	default:
		return rulesetObject{}, errors.New("firewall: unsupported ruleset family")
	}
	key := "name"
	if object.kind == "rule" {
		key = "chain"
	}
	object.name, err = rulesetString(object.fields[key])
	if err != nil {
		return rulesetObject{}, err
	}
	object.table = object.name
	if object.kind != "table" {
		object.table, err = rulesetString(object.fields["table"])
		if err != nil {
			return rulesetObject{}, err
		}
	}
	return object, nil
}

func rulesetString(raw json.RawMessage) (string, error) {
	var value string
	if err := json.Unmarshal(raw, &value); err != nil || len(value) == 0 || len(value) > 128 {
		return "", errors.New("firewall: bounded ruleset identifier required")
	}
	for _, character := range value {
		isLetter := character >= 'a' && character <= 'z' || character >= 'A' && character <= 'Z'
		isDigit := character >= '0' && character <= '9'
		isSeparator := character == '_' || character == '.' || character == '-' || character == ':'
		if !isLetter && !isDigit && !isSeparator {
			return "", errors.New("firewall: unsupported ruleset identifier")
		}
	}
	return value, nil
}

func (object *rulesetObject) normalize(actual bool) error {
	required, optional := []string{"family", "table", "name"}, []string{"comment"}
	switch object.kind {
	case "table":
		required = []string{"family", "name"}
		optional = append(optional, "flags")
	case "chain":
		optional = append(optional, "type", "hook", "prio", "policy", "dev")
	case "rule":
		required = []string{"family", "table", "chain", "expr"}
	case "set", "map":
		required = append(required, "type")
		optional = append(optional, "flags", "size", "policy", "elem")
		if object.kind == "map" {
			required = append(required, "map")
		}
	case "counter":
		if actual {
			required = append(required, "packets", "bytes")
		}
	}
	if actual {
		required = append(required, "handle")
	}
	data, err := json.Marshal(object.fields)
	if err != nil {
		return errors.New("firewall: ruleset fields encoding failed")
	}
	if err := strictjson.Object(data, required, optional, maximumOutput); err != nil {
		return err
	}
	if actual {
		var handle uint64
		if err := json.Unmarshal(object.fields["handle"], &handle); err != nil || handle == 0 {
			return errors.New("firewall: positive ruleset handle required")
		}
	}
	switch object.kind {
	case "table":
		if object.fields["flags"] != nil {
			// Dormant or owner-bound tables need their own qualified lifecycle.
			return errors.New("firewall: unqualified table flags")
		}
	case "chain":
		return object.checkChain()
	case "rule":
		expressions, err := normalizeRulesetExpressions(object.fields["expr"], actual)
		if err != nil {
			return err
		}
		object.fields["expr"] = expressions
	case "set", "map":
		if err := object.checkCollection(); err != nil {
			return err
		}
		elements, err := canonicalRulesetElements(object.fields["elem"])
		if err != nil {
			return err
		}
		object.fields["elem"] = elements
	case "counter":
		if actual {
			if err := checkCounterStatistics(object.fields); err != nil {
				return err
			}
			delete(object.fields, "packets")
			delete(object.fields, "bytes")
		}
	}
	return nil
}

func (object *rulesetObject) checkChain() error {
	if object.fields["hook"] == nil {
		for _, field := range []string{"type", "prio", "policy", "dev"} {
			if object.fields[field] != nil {
				return errors.New("firewall: partial ruleset base chain")
			}
		}
		return nil
	}
	hook, err := rulesetString(object.fields["hook"])
	if err != nil {
		return err
	}
	switch hook {
	case "prerouting", "input", "forward", "output", "postrouting", "ingress", "egress":
	default:
		return errors.New("firewall: unsupported ruleset hook")
	}
	kind, err := rulesetString(object.fields["type"])
	if err != nil {
		return err
	}
	switch kind {
	case "filter", "nat", "route":
	default:
		return errors.New("firewall: unsupported ruleset chain type")
	}
	policy, err := rulesetString(object.fields["policy"])
	if err != nil || policy != "drop" && policy != "accept" {
		return errors.New("firewall: unsupported ruleset base policy")
	}
	var priority int32
	if err := json.Unmarshal(object.fields["prio"], &priority); err != nil {
		return errors.New("firewall: signed ruleset priority required")
	}
	isDeviceHook := hook == "ingress" || hook == "egress"
	if isDeviceHook {
		if _, err := rulesetString(object.fields["dev"]); err != nil {
			return err
		}
		return nil
	}
	if object.fields["dev"] != nil {
		return errors.New("firewall: unexpected ruleset hook device")
	}
	return nil
}

func (object *rulesetObject) checkCollection() error {
	var datatype string
	if err := json.Unmarshal(object.fields["type"], &datatype); err != nil {
		parts := []string{}
		if err := json.Unmarshal(object.fields["type"], &parts); err != nil || len(parts) == 0 || len(parts) > 6 {
			return errors.New("firewall: reviewed collection datatype invalid")
		}
		for _, part := range parts {
			if len(part) == 0 || len(part) > 128 {
				return errors.New("firewall: reviewed collection datatype invalid")
			}
		}
	} else if len(datatype) == 0 || len(datatype) > 128 {
		return errors.New("firewall: reviewed collection datatype invalid")
	}
	if object.kind == "map" {
		mapping, err := rulesetString(object.fields["map"])
		if err != nil || mapping == "verdict" {
			return errors.New("firewall: unqualified map or verdict indirection")
		}
	}
	if flags := object.fields["flags"]; flags != nil {
		values := []string{}
		if err := json.Unmarshal(flags, &values); err != nil || len(values) == 0 || len(values) > 2 {
			return errors.New("firewall: reviewed collection flags invalid")
		}
		slices.Sort(values)
		for index, flag := range values {
			if flag != "constant" && flag != "interval" {
				return errors.New("firewall: unqualified dynamic collection")
			}
			if index > 0 && values[index-1] == flag {
				return errors.New("firewall: duplicate collection flag")
			}
		}
		encoded, err := json.Marshal(values)
		if err != nil {
			return errors.New("firewall: collection flags encoding failed")
		}
		object.fields["flags"] = encoded
	}
	if size := object.fields["size"]; size != nil {
		var value uint64
		if err := json.Unmarshal(size, &value); err != nil || value == 0 || value > maximumTupleCount {
			return errors.New("firewall: reviewed collection size invalid")
		}
	}
	return nil
}

func normalizeRulesetExpressions(raw json.RawMessage, actual bool) (json.RawMessage, error) {
	expressions := []map[string]json.RawMessage{}
	if err := json.Unmarshal(raw, &expressions); err != nil || len(expressions) == 0 || len(expressions) > 128 {
		return nil, errors.New("firewall: bounded ruleset expressions required")
	}
	for _, expression := range expressions {
		if len(expression) != 1 {
			return nil, errors.New("firewall: exact ruleset statement required")
		}
		for kind, value := range expression {
			switch kind {
			case "counter":
				if bytes.HasPrefix(value, []byte(`"`)) {
					if _, err := rulesetString(value); err != nil {
						return nil, err
					}
					continue
				}
				statistics := map[string]json.RawMessage{}
				if err := json.Unmarshal(value, &statistics); err != nil || statistics == nil {
					return nil, errors.New("firewall: ruleset counter object required")
				}
				if actual {
					if len(statistics) != 2 {
						return nil, errors.New("firewall: exact counter statistics required")
					}
					if err := checkCounterStatistics(statistics); err != nil {
						return nil, err
					}
				} else if len(statistics) != 0 {
					return nil, errors.New("firewall: reviewed counters cannot contain statistics")
				}
				expression[kind] = json.RawMessage(`{}`)
			case "accept", "drop", "return", "continue", "notrack":
				if !bytes.Equal(value, []byte("null")) {
					return nil, errors.New("firewall: invalid ruleset verdict")
				}
			case "match", "reject", "jump", "goto", "mangle", "limit", "log", "dnat", "snat", "masquerade", "redirect":
				// Exact reviewed expression data is retained, not interpreted as
				// a semantic floor proof. Only counter statistics are discarded.
			default:
				return nil, errors.New("firewall: unsupported ruleset statement")
			}
		}
	}
	encoded, err := json.Marshal(expressions)
	if err != nil {
		return nil, errors.New("firewall: ruleset expression encoding failed")
	}
	return encoded, nil
}

func checkCounterStatistics(fields map[string]json.RawMessage) error {
	for _, name := range []string{"packets", "bytes"} {
		var value uint64
		if err := json.Unmarshal(fields[name], &value); err != nil || bytes.Equal(fields[name], []byte("null")) {
			return errors.New("firewall: unsigned counter statistic required")
		}
	}
	return nil
}

func rulesetRuleTargets(raw json.RawMessage) ([]string, error) {
	expressions := []map[string]json.RawMessage{}
	if err := json.Unmarshal(raw, &expressions); err != nil {
		return nil, errors.New("firewall: invalid reviewed rule expressions")
	}
	targets := []string{}
	for _, expression := range expressions {
		for _, kind := range []string{"jump", "goto"} {
			value := expression[kind]
			if value == nil {
				continue
			}
			if err := strictjson.Object(value, []string{"target"}, nil, maximumOutput); err != nil {
				return nil, err
			}
			fields := map[string]json.RawMessage{}
			if err := json.Unmarshal(value, &fields); err != nil {
				return nil, errors.New("firewall: invalid reviewed jump target")
			}
			target, err := rulesetString(fields["target"])
			if err != nil {
				return nil, err
			}
			targets = append(targets, target)
		}
	}
	return targets, nil
}
