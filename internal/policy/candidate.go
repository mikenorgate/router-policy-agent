package policy

import (
	"context"
	"errors"
	"slices"
	"time"
)

// BaselineHash identifies this compiler's immutable, normalized configuration.
// A digest identifies configuration; it is not proof of authorization.
func (compiler *Compiler) BaselineHash() string {
	if compiler == nil {
		return ""
	}
	return compiler.hash
}

// CheckCandidate rechecks geometry, protections, counterpart completeness and
// bounded deadlines before rendering trusted compiler output. It does not
// authenticate directory data or bindings, or verify kernel/mapping ownership.
// Only the helper's independent compilation may supply an application candidate.
func (compiler *Compiler) CheckCandidate(ctx context.Context, candidate Candidate) error {
	if compiler == nil || ctx == nil {
		return errors.New("policy: missing candidate checker or context")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	validIdentity := candidate.BaselineHash == compiler.hash && identifier.MatchString(candidate.BindingGeneration)
	validBounds := !candidate.CompiledAt.IsZero() && len(candidate.Grants) <= compiler.baseline.MaximumTuples
	if !validIdentity || !validBounds {
		return errors.New("policy: candidate configuration or bounds differ")
	}
	for _, grant := range candidate.Grants {
		if err := ctx.Err(); err != nil {
			return err
		}
		if err := compiler.checkGrant(ctx, grant, candidate.CompiledAt); err != nil {
			return err
		}
	}
	if expandedTuples(candidate.Grants) > compiler.baseline.MaximumTuples {
		return errors.New("policy: candidate expanded quota exceeded")
	}
	return ctx.Err()
}

func (compiler *Compiler) checkGrant(ctx context.Context, grant Grant, compiledAt time.Time) error {
	canonical, err := CanonicalMAC(grant.MAC)
	validIdentity := err == nil && canonical == grant.MAC && identifier.MatchString(grant.DeviceID)
	validProtocol := grant.Protocol == "tcp" || grant.Protocol == "udp"
	validDirection := grant.Direction == FromDevice || grant.Direction == ToDevice
	if !validIdentity || !validProtocol || !validDirection || grant.Port == 0 {
		return errors.New("policy: invalid candidate grant identity or scope")
	}
	if !compiler.grantGeometry(grant) {
		return errors.New("policy: candidate grant differs from untrusted geometry")
	}
	endpoints := []Endpoint{grant.Device}
	if grant.Internet {
		if err := compiler.checkInternetGrant(grant); err != nil {
			return err
		}
	} else if grant.PeerScope == nil {
		if grant.PortEnd != 0 {
			return errors.New("policy: exact grant has interval fields")
		}
		endpoints = append(endpoints, grant.Peer)
	} else if err := compiler.checkScopeGrant(ctx, grant); err != nil {
		return err
	}
	for _, endpoint := range endpoints {
		expected, err := resolveEndpoint(compiler.baseline, endpoint.Real)
		if err != nil || expected.Real != endpoint.Real || !slices.Equal(expected.Variants, endpoint.Variants) {
			return errors.New("policy: candidate counterpart set differs")
		}
	}
	if !grant.Internet && grant.PeerScope == nil {
		flow := floorFlow{
			mac: grant.MAC, placement: Untrusted, device: grant.Device.Real, peer: grant.Peer.Real, port: grant.Port,
			rule: Rule{Direction: grant.Direction, Protocol: grant.Protocol},
		}
		if code := compiler.floor(flow); code != "" {
			return errors.New("policy: candidate violates protected floor")
		}
	}
	// Up to sixteen groups with thirty-two rules may overlap one logical flow.
	if len(grant.Contributors) == 0 || len(grant.Contributors) > 16*32 {
		return errors.New("policy: candidate contributor count outside bounds")
	}
	deadline := compiledAt.Add(leaseDuration(compiler.baseline))
	for _, contributor := range grant.Contributors {
		validIdentity := identifier.MatchString(contributor.GroupID) && identifier.MatchString(contributor.RuleID)
		validDeadline := contributor.ExpiresAt.After(compiledAt) && !contributor.ExpiresAt.After(deadline)
		if !validIdentity || !validDeadline {
			return errors.New("policy: candidate contributor identity or deadline invalid")
		}
	}
	return nil
}

func (compiler *Compiler) checkInternetGrant(grant Grant) error {
	invalidPeer := grant.Peer.Real.IsValid() || len(grant.Peer.Variants) != 0 || grant.PeerScope != nil
	if grant.Direction != FromDevice || invalidPeer || grant.PortEnd < grant.Port {
		return errors.New("policy: invalid Internet grant geometry")
	}
	ports := PortRange{First: grant.Port, Last: grant.PortEnd}
	allowed := compiler.internetDevicePorts(grant.MAC, grant.Device.Real, grant.Protocol, []PortRange{ports})
	if len(allowed) != 1 || allowed[0] != ports {
		return errors.New("policy: Internet grant violates protected floor")
	}
	return nil
}

func (compiler *Compiler) checkScopeGrant(ctx context.Context, grant Grant) error {
	scope := grant.PeerScope
	if grant.Peer.Real.IsValid() || len(grant.Peer.Variants) != 0 || grant.PortEnd < grant.Port ||
		!scope.Real.IsValid() || scope.Real != scope.Real.Masked() || scope.Real.Bits() == 0 {
		return errors.New("policy: invalid scoped grant geometry")
	}
	expected := compiler.resolveScope(scope.Real)
	if !slices.Equal(expected.Variants, scope.Variants) {
		return errors.New("policy: scoped candidate counterpart set differs")
	}
	regions, err := compiler.clipScope(ctx, scope.Real,
		PortRange{First: grant.Port, Last: grant.PortEnd}, grant.MAC, grant.Device.Real,
		Rule{Direction: grant.Direction, Protocol: grant.Protocol})
	if err != nil {
		return err
	}
	if len(regions) != 1 || regions[0].network != scope.Real ||
		regions[0].ports.First != grant.Port || regions[0].ports.Last != grant.PortEnd {
		return errors.New("policy: scoped candidate violates protected floor")
	}
	return nil
}

func (compiler *Compiler) grantGeometry(grant Grant) bool {
	for _, zone := range compiler.baseline.Zones {
		if zone.Role == Untrusted && zone.VLAN == grant.VLAN &&
			slices.Contains(zone.Interfaces, grant.Interface) && inPrefixes(grant.Device.Real, zone.Networks) {
			return true
		}
	}
	return false
}
