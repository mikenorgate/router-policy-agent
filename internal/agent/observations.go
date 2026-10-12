package agent

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"github.com/mikenorgate/router-policy-agent/internal/binding"
	"github.com/mikenorgate/router-policy-agent/internal/ipc"
	"github.com/mikenorgate/router-policy-agent/internal/policy"
	"slices"
)

// rememberProvenance runs after successful processing. It retains a bounded,
// sanitized immutable copy: no raw LDAP values, policy reason text or credentials.
// Truncation is explicit and never changes the enforcement candidate.
func (engine *Engine) rememberProvenance(candidate policy.Candidate, directory policy.DirectorySnapshot, bindings binding.Snapshot) {
	revisions := map[string]string{}
	for _, group := range directory.Groups {
		if group.Policy == nil {
			continue
		}
		doc, err := policy.ParseGroup(*group.Policy)
		if err != nil {
			continue
		}
		for _, rule := range doc.Rules {
			rule.Reason = ""
			b, _ := json.Marshal(rule)
			sum := sha256.Sum256(b)
			revisions[group.ID+"/"+rule.ID] = hex.EncodeToString(sum[:])
		}
	}
	report := ipc.ObservationSnapshot{SchemaVersion: 1, BaselineHash: candidate.BaselineHash, BaselineGeneration: engine.observation.report.BaselineGeneration, BindingGeneration: candidate.BindingGeneration, CompiledAt: candidate.CompiledAt, DirectoryObservedAt: directory.ObservedAt, Mode: string(engine.options.Mode), Complete: len(candidate.Grants) <= ipc.MaximumObservationGrants, Total: len(candidate.Grants), Grants: []ipc.ObservationGrant{}}
	residentBytes := 0
	for _, g := range candidate.Grants[:min(len(candidate.Grants), ipc.MaximumObservationGrants)] {
		grant := ipc.ObservationGrant{DeviceID: g.DeviceID, MAC: g.MAC, Interface: g.Interface, VLAN: g.VLAN, DeviceAddress: g.Device.Real.String(), PeerAddress: g.Peer.Real.String(), Direction: string(g.Direction), Protocol: g.Protocol, Port: g.Port, DeviceVariants: []string{}, PeerVariants: []string{}, Contributors: []ipc.ObservationContributor{}}
		for _, b := range bindings.Records {
			if b.MAC != g.MAC || b.Interface != g.Interface || b.VLAN != g.VLAN {
				continue
			}
			grant.AssociatedAt = b.AssociatedAt
			for _, address := range b.Addresses {
				if address.IP == g.Device.Real {
					bindingBody, _ := json.Marshal([]string{b.AssociationID, address.OwnershipID, address.IP.String()})
					bindingSum := sha256.Sum256(bindingBody)
					grant.BindingRef = hex.EncodeToString(bindingSum[:])
					grant.OwnershipObservedAt = address.ObservedAt
					grant.OwnershipValidUntil = address.ValidUntil
					break
				}
			}
			break
		}
		for _, a := range g.Device.Variants {
			grant.DeviceVariants = append(grant.DeviceVariants, a.String())
		}
		for _, a := range g.Peer.Variants {
			grant.PeerVariants = append(grant.PeerVariants, a.String())
		}
		for _, c := range g.Contributors[:min(len(g.Contributors), 32)] {
			grant.Contributors = append(grant.Contributors, ipc.ObservationContributor{GroupID: c.GroupID, RuleID: c.RuleID, Revision: revisions[c.GroupID+"/"+c.RuleID], ExpiresAt: c.ExpiresAt})
		}
		if len(g.Contributors) > 32 {
			report.Complete = false
		}
		encoded, _ := json.Marshal(grant)
		residentBytes += len(encoded)
		if residentBytes > 8<<20 {
			report.Complete = false
			break
		}
		report.Grants = append(report.Grants, grant)
	}
	body, _ := json.Marshal(report)
	sum := sha256.Sum256(body)
	report.Generation = hex.EncodeToString(sum[:])
	engine.provenance.Store(&report)
}

// Observations uses an immutable atomic snapshot and never acquires the engine
// transaction gate, samples its clock, reads persistence, or invokes enforcement.
// Installation must be independently joined with a current kernel observation.
func (engine *Engine) Observations(ctx context.Context, request ipc.ObservationRequest) (ipc.ObservationResponse, error) {
	if err := ctx.Err(); err != nil {
		return ipc.ObservationResponse{}, err
	}
	report := engine.provenance.Load()
	if report == nil {
		return ipc.ObservationResponse{Code: "unobserved"}, nil
	}
	if request.Generation != "" && request.Generation != report.Generation {
		return ipc.ObservationResponse{Code: "generation_changed"}, nil
	}
	if request.Offset < 0 || request.Offset > len(report.Grants) {
		return ipc.ObservationResponse{Code: "invalid_request"}, nil
	}
	out := *report
	end := min(request.Offset+128, len(report.Grants))
	out.Grants = slices.Clone(report.Grants[request.Offset:end])
	for i := range out.Grants {
		out.Grants[i].DeviceVariants = slices.Clone(out.Grants[i].DeviceVariants)
		out.Grants[i].PeerVariants = slices.Clone(out.Grants[i].PeerVariants)
		out.Grants[i].Contributors = slices.Clone(out.Grants[i].Contributors)
	}
	response := ipc.ObservationResponse{Snapshot: &out}
	if end < len(report.Grants) {
		response.NextOffset = &end
	}
	for len(out.Grants) > 1 {
		encoded, _ := json.Marshal(response)
		if len(encoded) <= 480<<10 {
			break
		}
		out.Grants = out.Grants[:len(out.Grants)/2]
		end = request.Offset + len(out.Grants)
		response.NextOffset = &end
	}
	return response, ctx.Err()
}
