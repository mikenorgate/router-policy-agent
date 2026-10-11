package firewall

import (
	"context"
	"errors"

	"github.com/mikenorgate/router-policy-agent/internal/policy"
)

// RenderImageGuards renders code-owned guard objects for offline image assembly.
// It performs no I/O or activation, learns no live policy, and declares no floor
// or writer readiness. The image owner must audit, pin and install the result
// with its protected policy, bootstrap paths and closed boot restoration.
func RenderImageGuards(ctx context.Context, data []byte) ([]byte, error) {
	if ctx == nil {
		return nil, errors.New("firewall: missing image rendering context")
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	baseline, err := policy.DecodeBaseline(data)
	if err != nil {
		return nil, err
	}
	layout, err := newGuardLayout(baseline)
	if err != nil {
		return nil, err
	}
	return layout.program(ctx)
}
