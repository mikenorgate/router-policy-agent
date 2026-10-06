package policy

import (
	"context"
	"errors"
	"net/netip"
	"slices"
	"time"

	"github.com/mikenorgate/router-policy-agent/internal/binding"
)

// ClassifyBindings derives deny-only native/NAT device representations from the
// helper's qualified source and immutable geometry, independently of grants.
// Cohort members may be inactive, lack access groups or have disappeared from
// the current directory. Unmanaged or unqualified bindings supply no addresses.
// A historical classifier is never evidence of current ownership or permission.
func (compiler *Compiler) ClassifyBindings(
	ctx context.Context,
	snapshot binding.Snapshot,
	cohort []string,
	now time.Time,
) ([]netip.Addr, error) {
	if compiler == nil || ctx == nil || cohort == nil || len(cohort) > 4096 {
		return nil, errors.New("policy: missing classification dependencies or cohort capacity")
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	previousMAC := ""
	for _, mac := range cohort {
		canonical, err := CanonicalMAC(mac)
		isUnordered := previousMAC != "" && previousMAC >= mac
		if err != nil || canonical != mac || isUnordered {
			return nil, errors.New("policy: classification cohort is not canonical and unique")
		}
		previousMAC = mac
	}
	if err := binding.Validate(snapshot, now, leaseDuration(compiler.baseline), compiler.baseline.MaximumDevices); err != nil {
		return nil, err
	}
	if !identifier.MatchString(snapshot.Generation) {
		return nil, errors.New("policy: invalid classification binding generation")
	}
	addresses := map[netip.Addr]bool{}
	counts := [2]int{}
	for _, record := range snapshot.Records {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		canonical, err := CanonicalMAC(record.MAC)
		if err != nil || canonical != record.MAC {
			return nil, errors.New("policy: invalid classification binding identity")
		}
		if _, exists := slices.BinarySearch(cohort, record.MAC); !exists || !compiler.validBinding(record, Untrusted) {
			continue
		}
		for _, address := range record.Addresses {
			endpoint, err := resolveEndpoint(compiler.baseline, address.IP)
			if err != nil || endpoint.Real != address.IP {
				return nil, errors.New("policy: classification requires a real device address")
			}
			for _, variant := range endpoint.Variants {
				if addresses[variant] {
					continue
				}
				family := 1
				if variant.Is4() {
					family = 0
				}
				counts[family]++
				if counts[family] > 16384 {
					return nil, errors.New("policy: device classification capacity exceeded")
				}
				addresses[variant] = true
			}
		}
	}
	result := make([]netip.Addr, 0, len(addresses))
	for address := range addresses {
		result = append(result, address)
	}
	slices.SortFunc(result, func(left, right netip.Addr) int { return left.Compare(right) })
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return result, nil
}
