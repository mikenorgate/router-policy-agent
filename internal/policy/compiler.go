package policy

import (
	"cmp"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/netip"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/mikenorgate/router-policy-agent/internal/binding"
)

// Device is an active-account decision and its individually enumerated groups.
// MAC is a credential identifier, not by itself a trustworthy network binding.
type Device struct {
	ID       string   `json:"id"`
	MAC      string   `json:"mac"`
	Active   bool     `json:"active"`
	GroupIDs []string `json:"group_ids"`
}

// DirectorySnapshot starts its lease at collection start, not at apply time.
// Complete is false for truncated paging, missing memberships or reader errors.
type DirectorySnapshot struct {
	ObservedAt time.Time `json:"observed_at"`
	Complete   bool      `json:"complete"`
	Groups     []Group   `json:"groups"`
	Devices    []Device  `json:"devices"`
}

// Ledger is applier-owned durable state. It never stores renewable firewall
// permits, only clock, first-seen deadlines and alias-resolution anchors.
type Ledger struct {
	LastValidated time.Time             `json:"last_validated"`
	FirstSeen     map[string]time.Time  `json:"first_seen"`
	AliasPeers    map[string]netip.Addr `json:"alias_peers"`
	NetworkGroups map[string]bool       `json:"network_groups"`
}

// Contributor records each independent source of permission for a tuple.
type Contributor struct {
	GroupID   string    `json:"group_id"`
	RuleID    string    `json:"rule_id"`
	ExpiresAt time.Time `json:"expires_at"`
}

// Grant is a logical, floor-checked connection initiation permission. Endpoint
// variants are representations of those same hosts, not independent peers.
type Grant struct {
	DeviceID     string        `json:"device_id"`
	MAC          string        `json:"mac"`
	Interface    string        `json:"interface"`
	VLAN         uint16        `json:"vlan"`
	Direction    Direction     `json:"direction"`
	Device       Endpoint      `json:"device"`
	Peer         Endpoint      `json:"peer"`
	Protocol     string        `json:"protocol"`
	Port         uint16        `json:"port"`
	Contributors []Contributor `json:"contributors"`
}

// ExpiresAt is the last still-valid contributor, preserving union semantics.
func (grant Grant) ExpiresAt() time.Time {
	var latest time.Time
	for _, contributor := range grant.Contributors {
		if contributor.ExpiresAt.After(latest) {
			latest = contributor.ExpiresAt
		}
	}
	return latest
}

// Denial is a bounded diagnostic without raw directory values or credentials.
type Denial struct {
	DeviceID string `json:"device_id"`
	Code     string `json:"code"`
}

// Candidate is all-or-nothing at the router quota boundary. Invalid device
// policy contributes no grants; persistent cohort state is managed separately.
type Candidate struct {
	BaselineHash      string    `json:"baseline_hash"`
	BindingGeneration string    `json:"binding_generation"`
	CompiledAt        time.Time `json:"compiled_at"`
	Grants            []Grant   `json:"grants"`
	Denials           []Denial  `json:"denials"`
	Ledger            Ledger    `json:"ledger"`
}

// Compiler contains only an immutable, independently reviewed router baseline.
type Compiler struct {
	baseline Baseline
	hash     string
}

// New validates and copies configuration so the caller cannot mutate the floor.
func New(baseline Baseline) (*Compiler, error) {
	if err := validateBaseline(baseline); err != nil {
		return nil, err
	}
	owned, err := cloneBaseline(baseline)
	if err != nil {
		return nil, err
	}
	for index := range owned.RetainedBlocks {
		if owned.RetainedBlocks[index].SourceMAC != "" {
			mac, err := CanonicalMAC(owned.RetainedBlocks[index].SourceMAC)
			if err != nil {
				return nil, err
			}
			owned.RetainedBlocks[index].SourceMAC = mac
		}
	}
	data, err := json.Marshal(owned)
	if err != nil {
		return nil, errors.New("policy: baseline digest failed")
	}
	hash := sha256.Sum256(data)
	return &Compiler{baseline: owned, hash: hex.EncodeToString(hash[:])}, nil
}

// Input deliberately includes raw group policies rather than caller-generated
// grants. The privileged applier recompiles with its own bindings and ledger.
type Input struct {
	Directory DirectorySnapshot
	Bindings  binding.Snapshot
	Now       time.Time
	Ledger    Ledger
}

// Compile is the offline wrapper for CompileContext.
func (compiler *Compiler) Compile(input Input) (Candidate, error) {
	return compiler.CompileContext(context.Background(), input)
}

// CompileContext enforces role, identity, floor, translation, expiry and quotas.
// Cancellation discards the whole candidate without mutating caller state.
func (compiler *Compiler) CompileContext(ctx context.Context, input Input) (Candidate, error) {
	groups, ledger, err := compiler.observeDirectory(ctx, input.Directory, input.Now, input.Ledger)
	if err != nil {
		return Candidate{}, err
	}
	lease := time.Duration(compiler.baseline.LeaseSeconds) * time.Second
	if err := binding.Validate(input.Bindings, input.Now, lease, compiler.baseline.MaximumDevices); err != nil {
		return Candidate{}, err
	}
	if !identifier.MatchString(input.Bindings.Generation) {
		return Candidate{}, errors.New("policy: invalid binding generation")
	}
	bindings := map[string]binding.Record{}
	for _, record := range input.Bindings.Records {
		if err := ctx.Err(); err != nil {
			return Candidate{}, err
		}
		mac, err := CanonicalMAC(record.MAC)
		if err != nil || mac != record.MAC || bindings[mac].MAC != "" {
			return Candidate{}, errors.New("policy: invalid or duplicate binding identity")
		}
		bindings[mac] = record
	}
	result := Candidate{
		BaselineHash: compiler.hash, BindingGeneration: input.Bindings.Generation,
		CompiledAt: input.Now, Grants: []Grant{}, Denials: []Denial{}, Ledger: ledger,
	}
	tupleCount := 0
	for _, device := range input.Directory.Devices {
		if err := ctx.Err(); err != nil {
			return Candidate{}, err
		}
		edits := ledgerEdits{ledger: &result.Ledger}
		grants, code := compiler.compileDevice(ctx, device, groups, bindings[device.MAC], input, &edits)
		if err := ctx.Err(); err != nil {
			return Candidate{}, err
		}
		if code == "device_quota_exceeded" {
			return Candidate{}, errors.New("policy: expanded router quota exceeded")
		}
		if code != "" {
			edits.rollback()
			result.Denials = append(result.Denials, Denial{DeviceID: device.ID, Code: code})
			continue
		}
		result.Grants = append(result.Grants, grants...)
		tupleCount += expandedTuples(grants)
		if tupleCount > compiler.baseline.MaximumTuples {
			return Candidate{}, errors.New("policy: expanded router quota exceeded")
		}
	}
	result.Grants = mergeGrants(result.Grants)
	if expandedTuples(result.Grants) > compiler.baseline.MaximumTuples {
		return Candidate{}, errors.New("policy: expanded router quota exceeded")
	}
	result.Ledger.LastValidated = input.Now
	slices.SortFunc(result.Denials, func(left, right Denial) int { return cmp.Compare(left.DeviceID, right.DeviceID) })
	if err := ctx.Err(); err != nil {
		return Candidate{}, err
	}
	return result, nil
}

// ObserveDirectory validates a complete observation and retains classifications
// even when independent binding collection later fails. It never grants access
// or starts a temporary-rule deadline; only successful compilation does that.
func (compiler *Compiler) ObserveDirectory(ctx context.Context, snapshot DirectorySnapshot,
	now time.Time, current Ledger,
) (Ledger, error) {
	_, ledger, err := compiler.observeDirectory(ctx, snapshot, now, current)
	return ledger, err
}

func (compiler *Compiler) observeDirectory(ctx context.Context, snapshot DirectorySnapshot,
	now time.Time, current Ledger,
) (map[string]Group, Ledger, error) {
	if ctx == nil || compiler == nil || now.IsZero() || now.Before(current.LastValidated) {
		return nil, Ledger{}, errors.New("policy: missing compiler/context or unsafe clock")
	}
	if err := ctx.Err(); err != nil {
		return nil, Ledger{}, err
	}
	groups, err := compiler.validateDirectory(ctx, snapshot, now, leaseDuration(compiler.baseline))
	if err != nil {
		return nil, Ledger{}, err
	}
	ledger, err := copyLedger(current)
	if err != nil {
		return nil, Ledger{}, err
	}
	if err := ctx.Err(); err != nil {
		return nil, Ledger{}, err
	}
	ledger.LastValidated = now
	for id, group := range groups {
		if err := ctx.Err(); err != nil {
			return nil, Ledger{}, err
		}
		if ledger.NetworkGroups[id] {
			group.IsNetwork = true
			groups[id] = group
		}
		if group.Policy != nil || group.IsNetwork {
			ledger.NetworkGroups[id] = true
		}
	}
	if ledgerSize(ledger) > maximumLedgerEntries {
		return nil, Ledger{}, errors.New("policy: durable ledger quota exceeded")
	}
	if err := ctx.Err(); err != nil {
		return nil, Ledger{}, err
	}
	return groups, ledger, nil
}

func (compiler *Compiler) validateDirectory(ctx context.Context, snapshot DirectorySnapshot, now time.Time, lease time.Duration) (
	map[string]Group, error,
) {
	if !snapshot.Complete || !binding.Fresh(snapshot.ObservedAt, now, lease) ||
		len(snapshot.Devices) > compiler.baseline.MaximumDevices || len(snapshot.Groups) > 8192 {
		return nil, errors.New("policy: incomplete, stale or oversized directory")
	}
	groups := map[string]Group{}
	for _, group := range snapshot.Groups {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		if !identifier.MatchString(group.ID) || !validText(group.Name, 128) || groups[group.ID].ID != "" ||
			group.Policy != nil && len(*group.Policy) > AttributeLimit {
			return nil, errors.New("policy: invalid or duplicate group identity")
		}
		groups[group.ID] = group
	}
	ids, macs := map[string]bool{}, map[string]bool{}
	for _, device := range snapshot.Devices {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		mac, err := CanonicalMAC(device.MAC)
		if !identifier.MatchString(device.ID) || ids[device.ID] || err != nil ||
			mac != device.MAC || macs[mac] || len(device.GroupIDs) > 256 {
			return nil, errors.New("policy: invalid or duplicate device identity")
		}
		ids[device.ID], macs[mac] = true, true
	}
	return groups, nil
}

func (compiler *Compiler) compileDevice(ctx context.Context, device Device, groups map[string]Group, record binding.Record,
	input Input, edits *ledgerEdits,
) ([]Grant, string) {
	if !device.Active {
		return nil, "inactive_account"
	}
	placement, access, code := selectGroups(device, groups)
	if code != "" {
		return nil, code
	}
	if placement != Untrusted {
		return nil, "role_not_qualified"
	}
	if !compiler.validBinding(record, placement) {
		return nil, "unqualified_binding"
	}
	grants := []Grant{}
	grantIndex := map[string]int{}
	tupleCount := 0
	for _, group := range access {
		if ctx.Err() != nil {
			return nil, "compilation_canceled"
		}
		document, err := ParseGroup(*group.Policy)
		if err != nil { // selectGroups already checks this; do not trust that across refactors.
			return nil, "malformed_group"
		}
		for _, rule := range document.Rules {
			expires, err := edits.ruleExpiry(group.ID, rule, input, compiler.baseline.LeaseSeconds)
			if err != nil {
				return nil, "invalid_expiry"
			}
			if !input.Now.Before(expires) {
				continue
			}
			for _, rawPeer := range rule.Peer.Addresses {
				if ctx.Err() != nil {
					return nil, "compilation_canceled"
				}
				peerIP, err := ParseHost(rawPeer)
				if err != nil {
					return nil, "malformed_peer"
				}
				peer, err := resolveEndpoint(compiler.baseline, peerIP)
				if err != nil || !edits.anchorPeer(group.ID, rule.ID, rawPeer, peerIP, peer.Real) {
					return nil, "unready_or_changed_alias"
				}
				for _, port := range rule.DestinationPorts {
					if ctx.Err() != nil {
						return nil, "compilation_canceled"
					}
					for _, address := range record.Addresses {
						flow := floorFlow{mac: device.MAC, placement: placement, rule: rule,
							device: address.IP, peer: peer.Real, port: port}
						if code := compiler.floor(flow); code != "" {
							return nil, code
						}
						endpoint, err := resolveEndpoint(compiler.baseline, address.IP)
						if err != nil || endpoint.Real != address.IP {
							return nil, "invalid_device_alias"
						}
						grantExpiry := earliest(expires, input.Bindings.ObservedAt.Add(leaseDuration(compiler.baseline)),
							record.AssociatedAt.Add(leaseDuration(compiler.baseline)),
							address.ObservedAt.Add(leaseDuration(compiler.baseline)), address.ValidUntil)
						grant := Grant{
							DeviceID: device.ID, MAC: device.MAC, Interface: record.Interface, VLAN: record.VLAN,
							Direction: rule.Direction, Device: endpoint, Peer: peer, Protocol: rule.Protocol, Port: port,
							Contributors: []Contributor{{GroupID: group.ID, RuleID: rule.ID, ExpiresAt: grantExpiry}},
						}
						key := grantKey(grant)
						if index, exists := grantIndex[key]; exists {
							grants[index].Contributors = append(grants[index].Contributors, grant.Contributors...)
						} else {
							grantIndex[key] = len(grants)
							grants = append(grants, grant)
							tupleCount += expandedTuples([]Grant{grant})
						}
						if tupleCount > compiler.baseline.MaximumTuples {
							return nil, "device_quota_exceeded"
						}
					}
				}
			}
		}
	}
	return mergeGrants(grants), ""
}

func selectGroups(device Device, groups map[string]Group) (Role, []Group, string) {
	placement, placements, networkCount := Unknown, 0, 0
	access := []Group{}
	seen := map[string]bool{}
	for _, id := range device.GroupIDs {
		group, exists := groups[id]
		if !exists || seen[id] {
			return Unknown, nil, "missing_or_duplicate_membership"
		}
		seen[id] = true
		if group.Policy == nil {
			if group.IsNetwork {
				return Unknown, nil, "missing_network_attribute"
			}
			continue
		}
		networkCount++
		document, err := ParseGroup(*group.Policy)
		if err != nil {
			return Unknown, nil, "malformed_group"
		}
		if document.Kind == "placement" {
			placement, placements = document.VLANRole, placements+1
		} else {
			access = append(access, group)
		}
	}
	if placements != 1 || networkCount > 16 {
		return Unknown, nil, "ambiguous_placement_or_group_quota"
	}
	for _, group := range access {
		document, err := ParseGroup(*group.Policy)
		if err != nil || document.VLANRole != placement {
			return Unknown, nil, "conflicting_access_role"
		}
	}
	slices.SortFunc(access, func(left, right Group) int { return cmp.Compare(left.ID, right.ID) })
	return placement, access, ""
}

func (compiler *Compiler) validBinding(record binding.Record, role Role) bool {
	if record.MAC == "" || len(record.Addresses) == 0 {
		return false
	}
	for _, zone := range compiler.baseline.Zones {
		if zone.Role != role || zone.VLAN != record.VLAN || !slices.Contains(zone.Interfaces, record.Interface) {
			continue
		}
		for _, address := range record.Addresses {
			if !validAddress(address.IP) || !inPrefixes(address.IP, zone.Networks) ||
				reservedZoneHost(compiler.baseline, address.IP) {
				return false
			}
		}
		return true
	}
	return false
}

func leaseDuration(baseline Baseline) time.Duration {
	return time.Duration(baseline.LeaseSeconds) * time.Second
}

func expandedTuples(grants []Grant) int {
	count := 0
	for _, grant := range grants {
		device4, device6, peer4, peer6 := 0, 0, 0, 0
		for _, device := range grant.Device.Variants {
			if device.Is4() {
				device4++
			} else {
				device6++
			}
		}
		for _, peer := range grant.Peer.Variants {
			if peer.Is4() {
				peer4++
			} else {
				peer6++
			}
		}
		count += device4*peer4 + device6*peer6
		// Only comparisons against the hard quota need the result. Saturation
		// bounds arithmetic and avoids walking a Cartesian product of aliases.
		if count > 16384 {
			return 16385
		}
	}
	return count
}

func mergeGrants(grants []Grant) []Grant {
	merged := map[string]Grant{}
	for _, grant := range grants {
		key := grantKey(grant)
		if prior, exists := merged[key]; exists {
			prior.Contributors = append(prior.Contributors, grant.Contributors...)
			merged[key] = prior
		} else {
			merged[key] = grant
		}
	}
	keys := make([]string, 0, len(merged))
	for key := range merged {
		keys = append(keys, key)
	}
	slices.Sort(keys)
	result := make([]Grant, 0, len(keys))
	for _, key := range keys {
		grant := merged[key]
		slices.SortFunc(grant.Contributors, func(left, right Contributor) int {
			if compared := cmp.Compare(left.GroupID, right.GroupID); compared != 0 {
				return compared
			}
			return cmp.Compare(left.RuleID, right.RuleID)
		})
		grant.Contributors = slices.CompactFunc(grant.Contributors, func(left, right Contributor) bool {
			return left.GroupID == right.GroupID && left.RuleID == right.RuleID && left.ExpiresAt.Equal(right.ExpiresAt)
		})
		result = append(result, grant)
	}
	return result
}

func grantKey(grant Grant) string {
	return strings.Join([]string{grant.DeviceID, grant.Device.Real.String(), grant.Peer.Real.String(),
		string(grant.Direction), grant.Protocol, strconv.Itoa(int(grant.Port))}, "/")
}
