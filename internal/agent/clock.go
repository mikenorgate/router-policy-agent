package agent

import (
	"errors"
	"time"
)

// A small sampling/slew lag may shorten a lease, never extend it. Larger UTC
// discontinuities fail closed until UTC catches the monotonic lower bound.
const maximumClockLag = 250 * time.Millisecond

type clockReading struct {
	utc           time.Time
	authorization time.Time
}

// helperClock retains a process-local monotonic anchor independently of UTC
// directory/binding timestamps. The engine's transaction gate protects it.
// It is not persisted, reset by Start or supplied through reader IPC.
type helperClock struct {
	lastTick time.Time
	lower    time.Time
}

func (clock *helperClock) advance(utc, tick time.Time) (time.Time, error) {
	if clock == nil || utc.IsZero() || tick.IsZero() {
		return time.Time{}, errors.New("agent: missing helper clock reading")
	}
	utc = utc.Round(0).UTC()
	if clock.lastTick.IsZero() {
		clock.lastTick, clock.lower = tick, utc
		return utc, nil
	}
	elapsed := tick.Sub(clock.lastTick)
	if elapsed < 0 {
		return time.Time{}, errors.New("agent: monotonic clock regressed")
	}
	clock.lastTick = tick
	clock.lower = clock.lower.Add(elapsed)
	if utc.Before(clock.lower) {
		if clock.lower.Sub(utc) > maximumClockLag {
			return time.Time{}, errors.New("agent: utc clock lags elapsed authorization time")
		}
		return clock.lower, nil
	}
	clock.lower = utc
	return utc, nil
}

func (engine *Engine) now() (clockReading, error) {
	utc := engine.options.Clock().Round(0).UTC()
	// Sample after the trusted UTC callback: time spent collecting that reading
	// cannot be omitted from elapsed authorization age.
	authorization, err := engine.clock.advance(utc, time.Now())
	if err != nil {
		return clockReading{}, err
	}
	return clockReading{utc: utc, authorization: authorization}, nil
}
