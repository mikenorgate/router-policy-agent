package firewall

import (
	"context"
	"errors"
	"time"

	"github.com/mikenorgate/router-policy-agent/internal/ipc"
)

// newStatusServer has a separate non-root caller identity and no processor.
// Its supervisor owns its listener lifetime; it must join this server before
// releasing the service/backend resources. Neither construction nor a query
// initializes state, changes generations, seals or applies anything.
func (s *guardedService) newStatusServer(uid uint32, timeout time.Duration) (*ipc.Server, error) {
	if s == nil || s.engine == nil || s.backend == nil {
		return nil, errors.New("firewall: missing status service dependencies")
	}
	if uid == 0 || uid == s.readerUID {
		return nil, errors.New("firewall: status requires a distinct non-root operator")
	}
	if err := validateBackendOptions(s.backend.options); err != nil {
		return nil, err
	}
	return ipc.NewStatusServer(ipc.ServerOptions{ReaderUID: uid, Timeout: timeout}, s.status)
}

func (s *guardedService) status(ctx context.Context) (ipc.Report, error) {
	if s == nil || s.engine == nil || s.backend == nil || ctx == nil {
		return ipc.Report{}, errors.New("firewall: missing status dependencies")
	}
	if err := validateBackendOptions(s.backend.options); err != nil {
		return ipc.Report{}, err
	}
	report, err := s.engine.Status(ctx)
	if err != nil {
		return ipc.Report{}, err
	}
	// This is a separate observation, not an atomic snapshot with the engine's
	// last decision. A subsequent owning writer can invalidate it; no readiness
	// is changed and no failure triggers mutation through this read-only path.
	b := s.backend
	if err := b.options.generation.with(ctx, b.options.expected, func(bounded context.Context) error {
		p := b.options.executor
		if err := p.acquire(bounded); err != nil {
			return err
		}
		defer p.release()
		observation, err := p.observeProfile(bounded, b.options.profile)
		if err != nil {
			return err
		}
		count, sequence := observation.guards.leases, b.options.expected.Sequence
		report.FloorState = "matches_pinned_contract"
		report.KernelTupleCount, report.WriterSequence = &count, &sequence
		return nil
	}); err != nil {
		// Do not expose filenames, native listings or raw backend diagnostics.
		report.FloorState = "unverified"
		report.KernelTupleCount, report.WriterSequence = nil, nil
	}
	return report, ctx.Err()
}
