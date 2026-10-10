package radius

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"slices"
	"time"

	"github.com/mikenorgate/router-policy-agent/internal/binding"
	"github.com/mikenorgate/router-policy-agent/internal/policy"
)

// BindingPublisherOptions is root-owned enrollment and local collector scope.
// ManagedMACs selects the explicitly enrolled cohort, not directory membership.
// The helper must independently verify the installed DHCP/MAC packet guards,
// protected floor and generation before accepting any exported record.
type BindingPublisherOptions struct {
	Collector   CollectorOptions
	Directory   string
	ManagedMACs []string
}

// PublishBindingsIPv4 collects fresh native evidence and atomically publishes
// bindings.json. It never reads or promotes a shadow report. Only guarded DHCP
// placement is admitted; original association, ownership and expiry times are
// retained. Source failure leaves an incomplete export, not the last success.
// This function installs no firewall rules and confers no directory permission.
func PublishBindingsIPv4(ctx context.Context, options BindingPublisherOptions) (Collection, error) {
	if ctx == nil || os.Getuid() != 0 || os.Geteuid() != 0 || !validBindingPublisher(options) {
		return Collection{}, errors.New("radius: invalid binding publisher configuration")
	}
	options.ManagedMACs = slices.Clone(options.ManagedMACs)
	return withExportRoot(ctx, options.Directory, func(root *os.Root) (Collection, error) {
		return publishBindings(ctx, root, options, func(ctx context.Context) (Collection, error) {
			return CollectIPv4(ctx, options.Collector)
		})
	})
}

func validManagedMACs(macs []string, maximum int) bool {
	if len(macs) == 0 || len(macs) > maximum {
		return false
	}
	seen := make(map[string]bool, len(macs))
	for _, mac := range macs {
		canonical, err := policy.CanonicalMAC(mac)
		if err != nil || canonical != mac || seen[mac] {
			return false
		}
		seen[mac] = true
	}
	return true
}

func validBindingPublisher(options BindingPublisherOptions) bool {
	isCollector := validCollectorOptions(options.Collector)
	isGuarded := options.Collector.Placement != nil && options.Collector.Placement.BindingMode == placementGuarded
	isScope := validManagedMACs(options.ManagedMACs, options.Collector.MaximumDevices)
	return isCollector && isGuarded && isScope && runtimePath(options.Directory, 4096)
}

func publishBindings(
	ctx context.Context,
	root *os.Root,
	options BindingPublisherOptions,
	collect func(context.Context) (Collection, error),
) (Collection, error) {
	if ctx == nil || root == nil || collect == nil || !validBindingPublisher(options) {
		return Collection{}, errors.New("radius: incomplete binding publisher inputs")
	}
	incomplete := binding.Snapshot{SchemaVersion: 1, Records: []binding.Record{}}
	if err := writeBindings(ctx, root, incomplete); err != nil {
		return Collection{}, err
	}
	collected, err := collect(ctx)
	if err != nil {
		return Collection{}, err
	}
	snapshot, err := collectedBindings(collected, options, time.Now().UTC())
	if err != nil {
		return Collection{}, err
	}
	if err := writeBindings(ctx, root, snapshot); err != nil {
		return Collection{}, err
	}
	return collected, nil
}

func collectedBindings(collected Collection, options BindingPublisherOptions, now time.Time) (binding.Snapshot, error) {
	if !validBindingPublisher(options) || !collected.PlacementChecked || collected.PlacementMode != placementGuarded ||
		len(collected.ProposedBindings) > options.Collector.MaximumDevices {
		return binding.Snapshot{}, errors.New("radius: guarded native collection required")
	}
	snapshot := binding.Snapshot{
		SchemaVersion: 1, Generation: collected.Generation, ObservedAt: collected.ObservedAt,
		Complete: true, Records: []binding.Record{},
	}
	for _, record := range collected.ProposedBindings {
		if !slices.Contains(options.ManagedMACs, record.MAC) {
			continue
		}
		validScope := record.Interface == options.Collector.Placement.Interface && record.VLAN == options.Collector.VLAN
		validAddress := len(record.Addresses) == 1 && record.Addresses[0].Source == "kea_dhcp4" &&
			options.Collector.Kea.Prefix.Contains(record.Addresses[0].IP)
		if !validScope || !validAddress {
			return binding.Snapshot{}, errors.New("radius: binding escaped enrolled scope")
		}
		record.Addresses = slices.Clone(record.Addresses)
		snapshot.Records = append(snapshot.Records, record)
	}
	if err := binding.Validate(snapshot, now, Freshness, len(options.ManagedMACs)); err != nil {
		return binding.Snapshot{}, errors.Join(errors.New("radius: native binding evidence invalid"), err)
	}
	return snapshot, nil
}

func writeBindings(ctx context.Context, root *os.Root, snapshot binding.Snapshot) error {
	data, err := json.Marshal(snapshot)
	if err != nil {
		return errors.New("radius: binding serialization failed")
	}
	return writeExport(ctx, root, "bindings.json", data)
}
