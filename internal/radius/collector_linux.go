package radius

import (
	"bytes"
	"context"
	"errors"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"github.com/mikenorgate/router-policy-agent/internal/binding"
	"github.com/mikenorgate/router-policy-agent/internal/kea"
)

// CollectorOptions is root-owned local configuration. There are no directory
// supplied sources, commands, clocks, device credentials or controller clients.
// Timeout bounds the entire serial collection, not each individual source read.
type CollectorOptions struct {
	Journal        JournalOptions
	Kea            kea.Options
	VLAN           uint16
	MaximumDevices int
	Timeout        time.Duration
	Placement      *PlacementOptions
}

// Collection contains shadow consistency results only. It is not an ownership
// qualification, directory authorization, binding snapshot or atomic transaction
// across RADIUS and DHCP. Original evidence times bound every candidate.
// Optional ProposedBindings are shadow-only records, not an accepted helper feed.
type Collection struct {
	ObservedAt        time.Time        `json:"observed_at"`
	Generation        string           `json:"generation"`
	Candidates        []IPv4Candidate  `json:"candidates"`
	Withheld          int              `json:"withheld"`
	PlacementChecked  bool             `json:"placement_checked,omitempty"`
	PlacementWithheld int              `json:"placement_withheld,omitempty"`
	ProposedBindings  []binding.Record `json:"proposed_bindings,omitempty"`
}

type collectionSources struct {
	history   func(context.Context) (history, error)
	lease     func(context.Context, string) (kea.Observation, error)
	now       func() time.Time
	placement func(context.Context) (placementObservation, error)
}

// CollectIPv4 brackets two authoritative lease passes with three authenticated
// local journal captures. History must remain an append-only prefix after JSON
// object order is normalized. The current session cohort must stay identical;
// leases must retain owner, renewal and expiry. A Stop, roam, renewal,
// reassignment, clock/source failure or quota
// breach returns no collection. Later changes remain possible: this detects
// observed races, not a cross-daemon lock. No firewall operation is performed.
// Optional host-placement reads bracket the lease recheck; both must agree.
func CollectIPv4(ctx context.Context, options CollectorOptions) (Collection, error) {
	if ctx == nil || os.Geteuid() != 0 || !validCollectorOptions(options) {
		return Collection{}, errors.New("radius: invalid privileged collector options")
	}
	// Configuration remains owned by this operation even if the caller later
	// replaces its prefix slice. Concurrent mutation by a caller is not supported.
	options.Journal.NASPrefixes = slices.Clone(options.Journal.NASPrefixes)
	if options.Placement != nil {
		placement := *options.Placement
		options.Placement = &placement
	}
	ctx, cancel := context.WithTimeout(ctx, options.Timeout)
	defer cancel()
	return collectIPv4(ctx, options, collectionSources{
		history: func(ctx context.Context) (history, error) { return captureHistory(ctx, options.Journal) },
		lease: func(ctx context.Context, mac string) (kea.Observation, error) {
			return kea.ReadIPv4(ctx, options.Kea, mac)
		},
		now: time.Now,
		placement: func(ctx context.Context) (placementObservation, error) {
			return capturePlacement(ctx, *options.Placement)
		},
	})
}

func validCollectorOptions(options CollectorOptions) bool {
	validBudget := options.Timeout > 0 && options.Timeout <= 30*time.Second
	validJournal := options.Journal.Timeout > 0 && options.Journal.Timeout <= 10*time.Second
	validQuota := options.MaximumDevices > 0 && options.MaximumDevices <= 256
	validVLAN := options.VLAN > 0 && options.VLAN <= 4094
	validKea := options.Kea.Timeout > 0 && options.Kea.Timeout <= 10*time.Second && options.Kea.SubnetID != 0
	validPrefix := options.Kea.Prefix.IsValid() && options.Kea.Prefix.Addr().Is4() && options.Kea.Prefix == options.Kea.Prefix.Masked()
	validSocket := filepath.IsAbs(options.Kea.Socket) && filepath.Clean(options.Kea.Socket) == options.Kea.Socket &&
		len(options.Kea.Socket) <= 107 && !strings.ContainsRune(options.Kea.Socket, '\x00')
	scope := Scope{BootID: strings.Repeat("0", 32), NASPrefixes: options.Journal.NASPrefixes}
	validPlacement := options.Placement == nil || validPlacementOptions(*options.Placement) && options.Placement.VLAN == options.VLAN
	return validBudget && validJournal && validQuota && validVLAN && validKea && validPrefix && validSocket && validScope(scope) && validPlacement
}

func collectIPv4(ctx context.Context, options CollectorOptions, sources collectionSources) (Collection, error) {
	if ctx == nil || sources.history == nil || sources.lease == nil || sources.now == nil {
		return Collection{}, errors.New("radius: missing collector dependency")
	}
	if options.Placement != nil && (sources.placement == nil || !validPlacementOptions(*options.Placement) || options.Placement.VLAN != options.VLAN) {
		return Collection{}, errors.New("radius: missing or invalid placement dependency")
	}
	if err := ctx.Err(); err != nil {
		return Collection{}, err
	}
	started := sources.now()
	first, err := sources.history(ctx)
	if err != nil {
		return Collection{}, errors.Join(errors.New("radius: accounting source unavailable"), ctx.Err())
	}
	observation, err := Replay(first.data, first.scope, first.observedAt)
	if err != nil || len(observation.Sessions) > options.MaximumDevices {
		return Collection{}, errors.New("radius: accounting source invalid or device quota exceeded")
	}
	scope := LeaseScope{SubnetID: options.Kea.SubnetID, Prefix: options.Kea.Prefix, VLAN: options.VLAN}
	leases := make([]kea.Observation, 0, len(observation.Sessions))
	for _, session := range observation.Sessions {
		lease, err := sources.lease(ctx, session.MAC)
		if err != nil {
			return Collection{}, errors.Join(errors.New("radius: lease source unavailable"), ctx.Err())
		}
		if _, err := MatchIPv4(session, lease, scope, sources.now().UTC()); err != nil {
			return Collection{}, err
		}
		leases = append(leases, lease)
	}
	var firstPlacement placementObservation
	if options.Placement != nil {
		firstPlacement, err = sources.placement(ctx)
		if err != nil {
			return Collection{}, errors.Join(errors.New("radius: placement source unavailable"), ctx.Err())
		}
	}
	second, err := sources.history(ctx)
	if err != nil || !steadyHistory(first, second, observation) {
		return Collection{}, errors.Join(errors.New("radius: accounting changed during lease collection"), ctx.Err())
	}
	for index, session := range observation.Sessions {
		lease, err := sources.lease(ctx, session.MAC)
		if err != nil {
			return Collection{}, errors.Join(errors.New("radius: lease recheck unavailable"), ctx.Err())
		}
		current, currentErr := MatchIPv4(session, lease, scope, sources.now().UTC())
		previous, previousErr := MatchIPv4(session, leases[index], scope, sources.now().UTC())
		if currentErr != nil || previousErr != nil || current.OwnershipID != previous.OwnershipID || current.IP != previous.IP {
			return Collection{}, errors.New("radius: lease changed during collection")
		}
	}
	var lastPlacement placementObservation
	if options.Placement != nil {
		lastPlacement, err = sources.placement(ctx)
		if err != nil || lastPlacement.identity != firstPlacement.identity || lastPlacement.observedAt.Before(firstPlacement.observedAt) {
			return Collection{}, errors.Join(errors.New("radius: placement source changed or unavailable"), ctx.Err())
		}
	}
	last, err := sources.history(ctx)
	if err != nil || !steadyHistory(second, last, observation) {
		return Collection{}, errors.Join(errors.New("radius: accounting changed during lease recheck"), ctx.Err())
	}
	now := sources.now()
	if err := ctx.Err(); err != nil {
		return Collection{}, err
	}
	wallElapsed := now.UTC().Sub(started.UTC())
	if now.Before(started) || wallElapsed < 0 || !near(started.UTC().Add(now.Sub(started)), now.UTC()) {
		return Collection{}, errors.New("radius: collector clock conflict")
	}
	result := Collection{ObservedAt: now.UTC(), Candidates: []IPv4Candidate{}, Withheld: observation.Withheld}
	if options.Placement != nil {
		result.PlacementChecked, result.ProposedBindings = true, []binding.Record{}
	}
	identities := []string{last.scope.BootID, digest(string(last.data))}
	owners := make(map[netip.Addr]bool)
	for index, session := range observation.Sessions {
		candidate, err := MatchIPv4(session, leases[index], scope, result.ObservedAt)
		if err != nil || owners[candidate.IP] {
			return Collection{}, errors.New("radius: expired or duplicate ownership at collection end")
		}
		owners[candidate.IP] = true
		result.Candidates = append(result.Candidates, candidate)
		identities = append(identities, candidate.Session.AssociationID, candidate.OwnershipID)
		if options.Placement != nil {
			first, firstErr := bindPlacement(candidate, firstPlacement, scope, options.Placement.Interface, result.ObservedAt)
			last, lastErr := bindPlacement(candidate, lastPlacement, scope, options.Placement.Interface, result.ObservedAt)
			if firstErr != nil || lastErr != nil {
				result.PlacementWithheld++
				continue
			}
			if last.Addresses[0].ValidUntil.Before(first.Addresses[0].ValidUntil) {
				first.Addresses[0].ValidUntil = last.Addresses[0].ValidUntil
			}
			result.ProposedBindings = append(result.ProposedBindings, first)
			identities = append(identities, first.Addresses[0].OwnershipID, first.Addresses[0].ValidUntil.UTC().Format(time.RFC3339Nano))
		}
	}
	result.Generation = digest(identities...)
	return result, nil
}

func steadyHistory(previous, next history, expected Observation) bool {
	if previous.scope.BootID != next.scope.BootID || previous.scope.ServiceUID != next.scope.ServiceUID ||
		!slices.Equal(previous.scope.NASPrefixes, next.scope.NASPrefixes) || next.observedAt.Before(previous.observedAt) ||
		!bytes.HasPrefix(next.data, previous.data) {
		return false
	}
	observation, err := Replay(next.data, next.scope, next.observedAt)
	return err == nil && observation.Withheld == expected.Withheld && slices.Equal(observation.Sessions, expected.Sessions)
}
