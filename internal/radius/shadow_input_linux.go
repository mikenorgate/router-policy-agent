package radius

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/netip"
	"os"
	"strings"
	"time"

	"github.com/mikenorgate/router-policy-agent/internal/binding"
	"github.com/mikenorgate/router-policy-agent/internal/hostfs"
	"github.com/mikenorgate/router-policy-agent/internal/policy"
	"github.com/mikenorgate/router-policy-agent/internal/strictjson"
)

var errShadowInput = errors.New("radius: shadow proposal input unavailable")

// LoadShadowProposals reads the collector's private, atomic report for a
// shadow-only helper. It does not publish authoritative bindings or qualify
// the producer for enforcement. Original timestamps and deadlines are retained;
// the normal binding.Load schema continues to reject this report.
func LoadShadowProposals(ctx context.Context, directory string) (binding.Snapshot, error) {
	return loadShadowProposals(ctx, directory, time.Now)
}

func loadShadowProposals(
	ctx context.Context,
	directory string,
	now func() time.Time,
) (binding.Snapshot, error) {
	if ctx == nil || now == nil || os.Geteuid() != 0 {
		return binding.Snapshot{}, errShadowInput
	}
	root, err := hostfs.OpenDirectory(ctx, hostfs.DirectoryOptions{Path: directory, OwnerUID: 0, Private: true})
	if err != nil {
		return binding.Snapshot{}, errors.Join(errShadowInput, ctx.Err())
	}
	file, err := hostfs.OpenRegular(ctx, root, hostfs.FileOptions{
		Name: shadowFilename, OwnerUID: 0, MaximumSize: maximumShadow,
	})
	if err != nil {
		return binding.Snapshot{}, errors.Join(errShadowInput, root.Close(), ctx.Err())
	}
	before, statErr := file.Stat()
	data, readErr := io.ReadAll(io.LimitReader(file, maximumShadow+1))
	after, afterErr := file.Stat()
	metadataErr := hostfs.CheckPrivateFile(file, 0, maximumShadow)
	closeErr := errors.Join(file.Close(), root.Close())
	if err := errors.Join(statErr, readErr, afterErr, metadataErr, closeErr, ctx.Err()); err != nil {
		return binding.Snapshot{}, errors.Join(errShadowInput, ctx.Err())
	}
	if before.Size() != after.Size() || !before.ModTime().Equal(after.ModTime()) {
		return binding.Snapshot{}, errShadowInput
	}
	return decodeShadowProposals(data, now().UTC())
}

func decodeShadowProposals(data []byte, now time.Time) (binding.Snapshot, error) {
	var report shadowReport
	if err := strictjson.Decode(data, &report, maximumShadow); err != nil {
		return binding.Snapshot{}, errShadowInput
	}
	// The producer writes json.Marshal bytes. Requiring that exact encoding
	// rejects noncanonical field names and encodings without silently
	// converting an operator-edited document into collector evidence.
	canonical, err := json.Marshal(report)
	if err != nil || !bytes.Equal(data, canonical) {
		return binding.Snapshot{}, errShadowInput
	}
	collection := report.Collection
	validEnvelope := report.Kind == "radius_ipv4_shadow_v1" && report.Mode == "shadow" &&
		report.Complete && !report.EnforcementReady
	validTimes := binding.Fresh(report.SampledAt, now, Freshness) &&
		!collection.ObservedAt.After(report.SampledAt)
	validPlacement := collection.PlacementChecked && validPlacementMode(collection.PlacementMode)
	validCounts := len(collection.Candidates) <= 256 && collection.Withheld >= 0 && collection.Withheld <= 4096 &&
		collection.PlacementWithheld >= 0 && len(collection.ProposedBindings)+collection.PlacementWithheld == len(collection.Candidates)
	if !validEnvelope || !validTimes || !validPlacement || !validCounts || !shadowHash(collection.Generation) {
		return binding.Snapshot{}, errShadowInput
	}
	snapshot := binding.Snapshot{
		SchemaVersion: 1, Generation: collection.Generation, ObservedAt: collection.ObservedAt,
		Complete: true, Records: append([]binding.Record{}, collection.ProposedBindings...),
	}
	if err := binding.Validate(snapshot, now, Freshness, 256); err != nil {
		return binding.Snapshot{}, errShadowInput
	}
	candidates := make(map[string]IPv4Candidate, len(collection.Candidates))
	owners := make(map[netip.Addr]bool, len(collection.Candidates))
	for _, candidate := range collection.Candidates {
		_, duplicate := candidates[candidate.Session.MAC]
		if duplicate || owners[candidate.IP] || !validShadowCandidate(candidate, collection.ObservedAt, now) {
			return binding.Snapshot{}, errShadowInput
		}
		candidates[candidate.Session.MAC], owners[candidate.IP] = candidate, true
	}
	for _, record := range snapshot.Records {
		candidate, found := candidates[record.MAC]
		if !found || !shadowProposalMatches(record, candidate, collection.PlacementMode) {
			return binding.Snapshot{}, errShadowInput
		}
	}
	return snapshot, nil
}

func validShadowCandidate(candidate IPv4Candidate, observed, now time.Time) bool {
	session := candidate.Session
	mac, err := policy.CanonicalMAC(session.MAC)
	validMAC := err == nil && mac == session.MAC
	validNAS := session.NAS.IsGlobalUnicast() && !session.NAS.Is4In6() && session.NAS.Zone() == ""
	validIP := candidate.IP.Is4() && candidate.IP.IsGlobalUnicast() && candidate.IP == session.IPv4
	validIDs := shadowHash(session.AssociationID) && shadowHash(candidate.OwnershipID)
	validSession := !session.StartedAt.IsZero() && !session.StartedAt.After(session.ObservedAt) &&
		binding.Fresh(session.ObservedAt, now, Freshness) && !session.ObservedAt.After(observed) &&
		session.ValidUntil.Equal(session.ObservedAt.Add(Freshness))
	validLease := binding.Fresh(candidate.LeaseObservedAt, now, Freshness) && !candidate.LeaseObservedAt.After(observed) &&
		!candidate.LeaseUpdatedAt.IsZero() && !candidate.LeaseUpdatedAt.After(candidate.LeaseObservedAt) &&
		candidate.LeaseUpdatedAt.Before(candidate.LeaseValidUntil)
	deadline := candidate.LeaseValidUntil
	if session.ValidUntil.Before(deadline) {
		deadline = session.ValidUntil
	}
	validDeadline := candidate.ValidUntil.Equal(deadline) && now.Before(deadline)
	return validMAC && validNAS && validIP && validIDs && validSession && validLease && validDeadline
}

func shadowProposalMatches(record binding.Record, candidate IPv4Candidate, mode string) bool {
	session := candidate.Session
	validAssociation := record.NAS == session.NAS.String() && record.AssociationID == session.AssociationID &&
		record.AssociatedAt.Equal(session.ObservedAt)
	validPlacement := placementInterface(record.Interface) && record.VLAN > 0 && record.VLAN <= 4094 &&
		(session.ReportedVLAN == 0 || session.ReportedVLAN == record.VLAN)
	if !validAssociation || !validPlacement || len(record.Addresses) != 1 {
		return false
	}
	address := record.Addresses[0]
	validAddress := address.IP == candidate.IP && address.Source == "kea_dhcp4" && shadowHash(address.OwnershipID) &&
		address.ObservedAt.Equal(candidate.LeaseObservedAt)
	validDeadline := !address.ValidUntil.After(candidate.ValidUntil)
	if mode == placementGuarded {
		validDeadline = address.ValidUntil.Equal(candidate.ValidUntil)
	}
	return validAddress && validDeadline
}

func shadowHash(value string) bool {
	decoded, err := hex.DecodeString(value)
	return err == nil && len(decoded) == 32 && strings.ToLower(value) == value
}
