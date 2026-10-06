package agent

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"
	"testing"
	"testing/synctest"
	"time"

	"github.com/mikenorgate/router-policy-agent/internal/ipc"
	"github.com/mikenorgate/router-policy-agent/internal/policy"
)

func TestStatusDoesNotInvokeEvidenceOrEnforcement(t *testing.T) {
	t.Parallel()
	for _, mode := range []Mode{Shadow, Enforce} {
		t.Run(string(mode), func(t *testing.T) {
			t.Parallel()
			f := newFixture(t)
			engine, err := New(f.baseline, f.options(mode))
			if err != nil {
				t.Fatal(err)
			}
			report, err := engine.Status(t.Context())
			if err != nil || report.HelperState != "not_started" || len(f.events) != 0 || ipc.ValidateReport(report) != nil {
				t.Fatal("initial status changed state or claimed startup")
			}
			engine = f.engine(t, f.options(mode))
			receipt, err := engine.Process(t.Context(), f.directory)
			if err != nil {
				t.Fatal(err)
			}
			events := slices.Clone(f.events)
			clock := engine.clock
			report, err = engine.Status(t.Context())
			if err != nil || ipc.ValidateReport(report) != nil {
				t.Fatalf("invalid report: %v", err)
			}
			if !slices.Equal(f.events, events) || engine.clock != clock {
				t.Fatal("status loaded/saved state, collected bindings, touched the firewall or advanced the clock")
			}
			if report.LastGrantCount != receipt.GrantCount || report.LastBindingCount != len(f.bindings.Records) ||
				report.RemainingGrantCount != receipt.GrantCount || report.NextExpiryMS == nil {
				t.Fatal("status did not preserve the successful decision and its bounded lifetime")
			}
			if (report.ApplyAgeMS != nil) != (mode == Enforce) || report.FloorState != "unverified" {
				t.Fatal("shadow/local status claimed actual kernel evidence")
			}
			if len(report.Rules) != 1 {
				t.Fatal("contributor reference missing")
			}
			report.Rules[0].GroupID = "changed-by-reader"
			again, err := engine.Status(t.Context())
			if err != nil || again.Rules[0].GroupID == "changed-by-reader" {
				t.Fatal("status returned mutable helper-owned diagnostics")
			}
			encoded, err := json.Marshal(again)
			if err != nil || strings.Contains(string(encoded), f.directory.Devices[0].MAC) ||
				strings.Contains(string(encoded), "fdca:") || strings.Contains(string(encoded), "device_id") {
				t.Fatal("status disclosed device identity or network addresses")
			}
		})
	}
}

func TestStatusCountdownCannotRefresh(t *testing.T) {
	t.Parallel()
	synctest.Test(t, func(t *testing.T) {
		f := newFixture(t)
		engine := f.engine(t, f.options(Enforce))
		if _, err := engine.Process(t.Context(), f.directory); err != nil {
			t.Fatal(err)
		}
		first, err := engine.Status(t.Context())
		if err != nil || first.NextExpiryMS == nil {
			t.Fatal("initial countdown missing")
		}
		time.Sleep(30 * time.Second)
		second, err := engine.Status(t.Context())
		if err != nil || second.NextExpiryMS == nil || *second.NextExpiryMS >= *first.NextExpiryMS ||
			second.DirectoryAgeMS == nil || *second.DirectoryAgeMS < 30000 {
			t.Fatal("status query refreshed lifetime or understated directory age")
		}
		time.Sleep(61 * time.Second)
		expired, err := engine.Status(t.Context())
		if err != nil || expired.RemainingGrantCount != 0 || expired.NextExpiryMS != nil ||
			expired.LastGrantCount != first.LastGrantCount || expired.PermitState != "last_application" {
			t.Fatal("expired diagnostics claimed a new decision or remaining grant")
		}
		f.setUTC(f.now.Add(-time.Minute))
		unsafe, err := engine.Status(t.Context())
		if err != nil || unsafe.ClockState != "unverified" || unsafe.RemainingGrantCount != 0 || unsafe.NextExpiryMS != nil {
			t.Fatal("clock rollback rejuvenated a status countdown")
		}
	})
}

func TestStatusFailureAndShutdownEvidence(t *testing.T) {
	t.Parallel()
	for _, test := range []struct {
		name, permits, state, code string
		stop, failSeal             bool
	}{
		{name: "processing failure sealed", permits: "sealed", state: "ready", code: "processing_failed"},
		{name: "processing and sealing failed", permits: "unknown", state: "failed", code: "seal_failed", failSeal: true},
		{name: "shutdown sealed", permits: "sealed", state: "stopped", stop: true},
		{
			name: "shutdown sealing failed", permits: "unknown", state: "stopped",
			code: "seal_failed", stop: true, failSeal: true,
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			f := newFixture(t)
			engine := f.engine(t, f.options(Enforce))
			if _, err := engine.Process(t.Context(), f.directory); err != nil {
				t.Fatal(err)
			}
			if test.failSeal {
				f.firewall.sealError = errFixture
			}
			if test.stop {
				if err := engine.Stop(t.Context()); (err != nil) != test.failSeal {
					t.Fatal("shutdown mismatch")
				}
			} else {
				f.store.loadError = errFixture
				if _, err := engine.Process(t.Context(), f.directory); err == nil {
					t.Fatal("failed state load succeeded")
				}
			}
			report, err := engine.Status(t.Context())
			if err != nil || ipc.ValidateReport(report) != nil || report.PermitState != test.permits ||
				report.HelperState != test.state || report.LastFailure != test.code || report.RemainingGrantCount != 0 {
				t.Fatalf("failure report disagrees: %+v, %v", report, err)
			}
			if report.LastGrantCount != 1 || report.NextExpiryMS != nil {
				t.Fatal("failure erased diagnostic history or pretended old authorization remained current")
			}
		})
	}
}

func TestStatusIsCancellableAndDoesNotRestart(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	engine := f.engine(t, f.options(Enforce))
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	for _, value := range []*Engine{nil, {}, engine} {
		if _, err := value.Status(ctx); err == nil {
			t.Fatal("invalid/canceled status succeeded")
		}
	}
	if err := engine.acquire(t.Context()); err != nil {
		t.Fatal(err)
	}
	defer engine.release()
	ctx, cancel = context.WithTimeout(t.Context(), time.Millisecond)
	defer cancel()
	if _, err := engine.Status(ctx); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatal("status waiting behind a transaction ignored its deadline")
	}
}

func TestStatusSamplingConsumesElapsedLifetime(t *testing.T) {
	t.Parallel()
	synctest.Test(t, func(t *testing.T) {
		f := newFixture(t)
		engine := f.engine(t, f.options(Enforce))
		if _, err := engine.Process(t.Context(), f.directory); err != nil {
			t.Fatal(err)
		}
		engine.options.Clock = func() time.Time {
			now := f.utc()
			time.Sleep(time.Second)
			return now
		}
		report, err := engine.Status(t.Context())
		if err != nil || report.ClockState != "unverified" || report.NextExpiryMS != nil || report.RemainingGrantCount != 0 {
			t.Fatal("slow stale UTC callback omitted elapsed time from the countdown")
		}
		ctx, cancel := context.WithTimeout(t.Context(), time.Millisecond)
		defer cancel()
		if _, err := engine.Status(ctx); !errors.Is(err, context.DeadlineExceeded) {
			t.Fatal("status sampling ignored cancellation")
		}
	})
}

func TestStatusContributorDetailHasAnExplicitBound(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	seed, err := policy.ParseGroup(*f.directory.Groups[1].Policy)
	if err != nil {
		t.Fatal(err)
	}
	f.directory.Groups = f.directory.Groups[:1]
	f.directory.Devices[0].GroupIDs = []string{"placement"}
	for groupIndex := range 5 {
		id := fmt.Sprintf("synthetic-access-%d", groupIndex)
		rules := make([]policy.Rule, 0, 32)
		for ruleIndex := range 32 {
			rule := seed.Rules[0]
			rule.ID = fmt.Sprintf("synthetic-rule-%d", ruleIndex)
			rules = append(rules, rule)
		}
		data, err := json.Marshal(map[string]any{
			"schema_version": 1, "kind": "access", "vlan_role": "untrusted", "temporary": false, "rules": rules,
		})
		if err != nil {
			t.Fatal(err)
		}
		raw := string(data)
		f.directory.Groups = append(f.directory.Groups, policy.Group{ID: id, Name: id, IsNetwork: true, Policy: &raw})
		f.directory.Devices[0].GroupIDs = append(f.directory.Devices[0].GroupIDs, id)
	}
	engine := f.engine(t, f.options(Enforce))
	if _, err := engine.Process(t.Context(), f.directory); err != nil {
		t.Fatal(err)
	}
	report, err := engine.Status(t.Context())
	if err != nil || ipc.ValidateReport(report) != nil || !report.RulesTruncated ||
		len(report.Rules) != ipc.MaximumRuleReferences || report.LastGrantCount != 1 {
		t.Fatal("overlapping contributors exceeded the status detail bound or hid truncation")
	}
}

func TestStatusDenialSummariesExcludeDeviceIdentities(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	engine := f.engine(t, f.options(Enforce))
	f.directory.Devices[0].Active = false
	if _, err := engine.Process(t.Context(), f.directory); err != nil {
		t.Fatal(err)
	}
	report, err := engine.Status(t.Context())
	if err != nil || ipc.ValidateReport(report) != nil || report.LastGrantCount != 0 ||
		report.LastDenialCount != 1 || len(report.DenialCodes) != 1 || len(report.Rules) != 0 {
		t.Fatal("inactive account did not produce bounded denial-only status")
	}
	data, err := json.Marshal(report)
	if err != nil || strings.Contains(string(data), f.directory.Devices[0].ID) ||
		strings.Contains(string(data), f.directory.Devices[0].MAC) {
		t.Fatal("denial report disclosed device identity")
	}
}
