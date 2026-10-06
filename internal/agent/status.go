package agent

import (
	"cmp"
	"context"
	"slices"
	"time"

	"github.com/mikenorgate/router-policy-agent/internal/ipc"
	"github.com/mikenorgate/router-policy-agent/internal/policy"
)

// observation retains bounded diagnostics, not credentials, raw policies,
// device addresses or restorable permission. The engine's gate protects it.
type observation struct {
	report      ipc.Report
	directoryAt time.Time
	decidedAt   time.Time
	deadlines   []countdown
}

type countdown struct {
	utc  time.Time
	tick time.Time
}

// Status returns an independent read-only diagnostic snapshot. It waits for an
// in-flight transaction but does not load/save state, collect bindings, mutate
// the helper clock, invoke a firewall callback or refresh any deadline. Current
// kernel evidence is deliberately unverified until the owning backend adds a
// fresh, independent read. A usable local clock is not NTP qualification.
func (engine *Engine) Status(ctx context.Context) (ipc.Report, error) {
	if err := engine.acquire(ctx); err != nil {
		return ipc.Report{}, err
	}
	defer engine.release()
	report := engine.observation.report
	report.Rules = slices.Clone(report.Rules)
	report.DenialCodes = slices.Clone(report.DenialCodes)
	report.ClockState, report.FloorState = "unverified", "unverified"
	report.RemainingGrantCount = 0
	utc := engine.options.Clock()
	// Collecting a trusted reading also consumes time. Sample elapsed time
	// afterward so a delayed callback cannot exaggerate the remaining lifetime.
	tick := time.Now()
	clock := engine.clock // Inspect a copy; status must not advance authorization.
	now, err := clock.advance(utc, tick)
	if err != nil {
		return report, ctx.Err()
	}
	report.ClockState = "usable"
	if !engine.observation.directoryAt.IsZero() && !now.Before(engine.observation.directoryAt) {
		age := now.Sub(engine.observation.directoryAt).Milliseconds()
		report.DirectoryAgeMS = &age
	}
	if !engine.observation.decidedAt.IsZero() {
		age := max(int64(0), tick.Sub(engine.observation.decidedAt).Milliseconds())
		report.DecisionAgeMS = &age
		if engine.options.Mode == Enforce {
			appliedAge := age
			report.ApplyAgeMS = &appliedAge
		}
	}
	for _, deadline := range engine.observation.deadlines {
		if err := ctx.Err(); err != nil {
			return ipc.Report{}, err
		}
		remaining := min(deadline.utc.Sub(now), deadline.tick.Sub(tick))
		if remaining <= 0 {
			continue
		}
		report.RemainingGrantCount++
		milliseconds := remaining.Milliseconds()
		if report.NextExpiryMS == nil || milliseconds < *report.NextExpiryMS {
			report.NextExpiryMS = &milliseconds
		}
	}
	return report, ctx.Err()
}

func (engine *Engine) rememberDecision(
	candidate policy.Candidate,
	authorization policy.Authorization,
	directoryAt time.Time,
	bindings int,
) {
	tick := time.Now()
	// Advance the last trusted sample conservatively without asking the clock
	// for another sample after a successfully completed firewall transaction.
	now := engine.clock.lower.Add(tick.Sub(engine.clock.lastTick))
	report := &engine.observation.report
	report.LastFailure = ""
	report.LastCompiledAt = candidate.CompiledAt
	report.LastGrantCount, report.LastDenialCount = len(candidate.Grants), len(candidate.Denials)
	report.LastBindingCount = bindings
	report.PermitState = "last_application"
	if engine.options.Mode == Shadow {
		report.PermitState = "shadow"
	}
	engine.observation.directoryAt, engine.observation.decidedAt = directoryAt, tick
	engine.observation.deadlines = make([]countdown, 0, len(candidate.Grants))
	report.Rules, report.DenialCodes = []ipc.RuleReference{}, []string{}
	report.RulesTruncated = false
	references := map[ipc.RuleReference]bool{}
	for index, grant := range candidate.Grants {
		if remaining, err := authorization.Remaining(index, now); err == nil {
			// The tick was captured before Remaining, so diagnostic lifetime can
			// only be shortened by time spent calculating these countdowns.
			engine.observation.deadlines = append(engine.observation.deadlines,
				countdown{utc: grant.ExpiresAt(), tick: tick.Add(remaining)})
		}
		if report.RulesTruncated {
			continue
		}
		for _, contributor := range grant.Contributors {
			reference := ipc.RuleReference{GroupID: contributor.GroupID, RuleID: contributor.RuleID}
			if references[reference] {
				continue
			}
			if len(report.Rules) == ipc.MaximumRuleReferences {
				report.RulesTruncated = true
				break
			}
			references[reference] = true
			report.Rules = append(report.Rules, reference)
		}
	}
	slices.SortFunc(report.Rules, func(a, b ipc.RuleReference) int {
		return cmp.Or(cmp.Compare(a.GroupID, b.GroupID), cmp.Compare(a.RuleID, b.RuleID))
	})
	for _, denial := range candidate.Denials {
		report.DenialCodes = append(report.DenialCodes, denial.Code)
	}
	slices.Sort(report.DenialCodes)
	report.DenialCodes = slices.Compact(report.DenialCodes)
}
