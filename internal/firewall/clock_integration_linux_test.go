//go:build integration && linux

package firewall

import (
	"syscall"
	"testing"
	"time"
)

func TestConfiguredClockQueriesActualKernelWithoutAdjustment(t *testing.T) {
	t.Parallel()
	before := time.Now().Add(-time.Microsecond)
	queries := 0
	observed := readKernelUTC(func(reading *syscall.Timex) (int, error) {
		queries++
		if reading == nil || *reading != (syscall.Timex{}) {
			t.Fatal("actual kernel query was not read-only")
		}
		return syscall.Adjtimex(reading)
	})
	configured := kernelUTC()
	after := time.Now().Add(time.Microsecond)
	if queries != 1 {
		t.Fatal("actual kernel clock query was not exercised")
	}
	for _, sample := range []time.Time{observed, configured} {
		// A host that reports unsafe synchronization must yield the invalid zero
		// value. That rejection is tested explicitly with controlled readings;
		// this integration test never sets a clock or changes its sync flags.
		if sample.IsZero() {
			continue
		}
		validTime := !sample.Before(before) && !sample.After(after)
		if !validTime || sample.Location() != time.UTC {
			t.Fatal("usable actual kernel clock differs from its read interval")
		}
	}
}
