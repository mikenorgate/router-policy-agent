package agent

import (
	"testing"
	"time"
)

func TestHelperClockBounds(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name    string
		elapsed time.Duration
		wall    time.Duration
		want    time.Duration
		wantErr bool
	}{
		{name: "aligned", elapsed: 30 * time.Second, wall: 30 * time.Second, want: 30 * time.Second},
		{name: "small lag clamps age", elapsed: time.Second, wall: 900 * time.Millisecond, want: time.Second},
		{name: "exact lag bound", elapsed: time.Second, wall: time.Second - maximumClockLag, want: time.Second},
		{name: "above lag bound", elapsed: time.Second, wall: time.Second - maximumClockLag - 1, wantErr: true},
		{name: "rejuvenation", elapsed: 120 * time.Second, wall: 45 * time.Second, wantErr: true},
		{name: "frozen utc", elapsed: 120 * time.Second, wantErr: true},
		{name: "backward tick", elapsed: -time.Second, wantErr: true},
		{name: "forward utc is conservative", elapsed: time.Second, wall: time.Minute, want: time.Minute},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			utc := time.Date(2026, time.January, 1, 0, 0, 0, 0, time.UTC)
			tick := time.Now()
			clock := &helperClock{}
			if _, err := clock.advance(utc, tick); err != nil {
				t.Fatal(err)
			}
			got, err := clock.advance(utc.Add(test.wall), tick.Add(test.elapsed))
			if (err != nil) != test.wantErr {
				t.Fatalf("clock rejection mismatch: %v", err)
			}
			if err == nil && !got.Equal(utc.Add(test.want)) {
				t.Fatalf("authorization age = %v, want %v", got.Sub(utc), test.want)
			}
		})
	}
}

func TestHelperClockNeverResetsItsLowerBound(t *testing.T) {
	t.Parallel()
	utc := time.Date(2026, time.January, 1, 0, 0, 0, 0, time.UTC)
	tick := time.Now()
	clock := &helperClock{}
	if _, err := clock.advance(utc, tick); err != nil {
		t.Fatal(err)
	}
	if _, err := clock.advance(utc.Add(time.Minute), tick.Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	if _, err := clock.advance(utc.Add(2*time.Second), tick.Add(2*time.Second)); err == nil {
		t.Fatal("forward-then-backward utc restored its old age")
	}
	if _, err := clock.advance(utc.Add(61*time.Second), tick.Add(3*time.Second)); err == nil {
		t.Fatal("a failed sample reset the monotonic lower bound")
	}
	got, err := clock.advance(utc.Add(63*time.Second), tick.Add(4*time.Second))
	if err != nil || !got.Equal(utc.Add(63*time.Second)) {
		t.Fatalf("utc could not catch up without resetting age: %v", err)
	}
}

func TestHelperClockAccumulatesSmallLag(t *testing.T) {
	t.Parallel()
	utc := time.Date(2026, time.January, 1, 0, 0, 0, 0, time.UTC)
	tick := time.Now()
	clock := &helperClock{}
	for step := range 4 {
		got, err := clock.advance(utc, tick.Add(time.Duration(step)*100*time.Millisecond))
		if step == 3 {
			if err == nil {
				t.Fatal("successive small lags bypassed the clock limit")
			}
			continue
		}
		if err != nil || !got.Equal(utc.Add(time.Duration(step)*100*time.Millisecond)) {
			t.Fatalf("small lag did not retain elapsed age: %v", err)
		}
	}
}

func TestHelperClockRejectsMissingSamples(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name  string
		clock *helperClock
		utc   time.Time
		tick  time.Time
	}{
		{name: "nil clock", utc: time.Now(), tick: time.Now()},
		{name: "missing utc", clock: &helperClock{}, tick: time.Now()},
		{name: "missing tick", clock: &helperClock{}, utc: time.Now()},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			if got, err := test.clock.advance(test.utc, test.tick); err == nil || !got.IsZero() {
				t.Fatal("missing clock sample returned authorization time")
			}
		})
	}
}

func FuzzClock(f *testing.F) {
	f.Add(int64(45*time.Second), int64(120*time.Second))
	f.Add(int64(time.Second), int64(time.Second))
	f.Add(int64(900*time.Millisecond), int64(time.Second))
	f.Add(int64(time.Second-maximumClockLag), int64(time.Second))
	f.Add(int64(0), int64(-time.Second))
	f.Fuzz(func(t *testing.T, wallDelta, elapsedDelta int64) {
		utc := time.Date(2026, time.January, 1, 0, 0, 0, 0, time.UTC)
		tick := time.Now()
		clock := &helperClock{}
		if _, err := clock.advance(utc, tick); err != nil {
			t.Fatal(err)
		}
		wall, lower := utc.Add(time.Duration(wallDelta)), utc.Add(time.Duration(elapsedDelta))
		got, err := clock.advance(wall, tick.Add(time.Duration(elapsedDelta)))
		mustReject := elapsedDelta < 0 || wall.Before(lower) && lower.Sub(wall) > maximumClockLag
		if (err != nil) != mustReject {
			t.Fatalf("clock accepted an unsafe age or rejected a safe one: %v", err)
		}
		if err == nil && (got.Before(wall) || got.Before(lower) || got.Location() != time.UTC) {
			t.Fatal("accepted clock understated utc or elapsed authorization age")
		}
	})
}
