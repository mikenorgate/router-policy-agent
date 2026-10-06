package firewall

import (
	"syscall"
	"testing"
	"time"
)

func TestKernelUTCRejectsUnsafeReadings(t *testing.T) {
	t.Parallel()
	valid := kernelClockReading{seconds: 1893456000, fraction: 123456}
	for _, test := range []struct {
		name   string
		change func(*kernelClockReading)
	}{
		{name: "inserting leap", change: func(r *kernelClockReading) { r.state = 1 }},
		{name: "deleting leap", change: func(r *kernelClockReading) { r.state = 2 }},
		{name: "during leap", change: func(r *kernelClockReading) { r.state = 3 }},
		{name: "after leap", change: func(r *kernelClockReading) { r.state = 4 }},
		{name: "not synchronized", change: func(r *kernelClockReading) { r.state = 5 }},
		{name: "negative state", change: func(r *kernelClockReading) { r.state = -1 }},
		{name: "unknown state", change: func(r *kernelClockReading) { r.state = 17 }},
		{name: "nonzero mode", change: func(r *kernelClockReading) { r.modes = 1 }},
		{name: "negative status", change: func(r *kernelClockReading) { r.status = -1 }},
		{name: "unsafe status", change: func(r *kernelClockReading) { r.status = 0x0040 }},
		{name: "hardware fault", change: func(r *kernelClockReading) { r.status = 0x1000 }},
		{name: "pending insertion flag", change: func(r *kernelClockReading) { r.status = 0x0010 }},
		{name: "pending deletion flag", change: func(r *kernelClockReading) { r.status = 0x0020 }},
		{name: "unset timestamp", change: func(r *kernelClockReading) { r.seconds = 0 }},
		{name: "negative timestamp", change: func(r *kernelClockReading) { r.seconds = -1 }},
		{name: "calendar overflow", change: func(r *kernelClockReading) { r.seconds = maximumKernelSeconds + 1 }},
		{name: "negative fraction", change: func(r *kernelClockReading) { r.fraction = -1 }},
		{name: "microsecond overflow", change: func(r *kernelClockReading) { r.fraction = 1000000 }},
		{name: "nanosecond overflow", change: func(r *kernelClockReading) {
			r.status, r.fraction = kernelStatusNano, 1000000000
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			reading := valid
			test.change(&reading)
			if got := decodeKernelUTC(reading); !got.IsZero() {
				t.Fatal("unsafe kernel reading became an authorization clock")
			}
		})
	}
}

func TestKernelUTCDecodesResolutionWithoutNormalizingInvalidFields(t *testing.T) {
	t.Parallel()
	for _, test := range []struct {
		name     string
		reading  kernelClockReading
		expected time.Time
	}{
		{
			name: "microseconds", reading: kernelClockReading{seconds: 1893456000, fraction: 123456},
			expected: time.Unix(1893456000, 123456000).UTC(),
		},
		{
			name:     "nanoseconds",
			reading:  kernelClockReading{seconds: 1893456000, fraction: 123456789, status: kernelStatusNano},
			expected: time.Unix(1893456000, 123456789).UTC(),
		},
		{
			name: "minimum timestamp", reading: kernelClockReading{seconds: 1},
			expected: time.Unix(1, 0).UTC(),
		},
		{
			name: "maximum microseconds", reading: kernelClockReading{seconds: maximumKernelSeconds, fraction: 999999},
			expected: time.Unix(maximumKernelSeconds, 999999000).UTC(),
		},
		{
			name:     "maximum nanoseconds",
			reading:  kernelClockReading{seconds: maximumKernelSeconds, fraction: 999999999, status: kernelStatusNano},
			expected: time.Unix(maximumKernelSeconds, 999999999).UTC(),
		},
		{
			name: "synchronized discipline flags", reading: kernelClockReading{seconds: 1893456000, status: 0x0001 | 0x0008},
			expected: time.Unix(1893456000, 0).UTC(),
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			got := decodeKernelUTC(test.reading)
			if !got.Equal(test.expected) || got.Location() != time.UTC {
				t.Fatal("kernel timestamp resolution or utc representation changed")
			}
		})
	}
}

func TestKernelUTCQueryStartsWithNoAdjustmentFields(t *testing.T) {
	t.Parallel()
	for _, name := range []string{"success", "syscall failure", "unsafe state"} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			calls := 0
			got := readKernelUTC(func(reading *syscall.Timex) (int, error) {
				calls++
				if reading == nil || *reading != (syscall.Timex{}) {
					t.Fatal("kernel clock query could change adjustment parameters")
				}
				reading.Time.Sec, reading.Time.Usec = 1893456000, 123456
				if name == "syscall failure" {
					return kernelTimeOK, syscall.EPERM
				}
				if name == "unsafe state" {
					return 5, nil
				}
				return kernelTimeOK, nil
			})
			if calls != 1 {
				t.Fatal("clock query retried or accepted a cached observation")
			}
			if name == "success" {
				if !got.Equal(time.Unix(1893456000, 123456000)) {
					t.Fatal("successful kernel query lost its timestamp")
				}
				return
			}
			if !got.IsZero() {
				t.Fatal("failed kernel query returned a usable time")
			}
		})
	}
	if got := readKernelUTC(nil); !got.IsZero() {
		t.Fatal("missing kernel query returned a usable time")
	}
}

func FuzzKernelUTC(f *testing.F) {
	f.Add(
		0,
		uint32(0),
		int32(0),
		int64(1893456000),
		int64(123456),
	)
	f.Add(
		0,
		uint32(0),
		int32(kernelStatusNano),
		int64(maximumKernelSeconds),
		int64(999999999),
	)
	f.Add(
		5,
		uint32(0),
		int32(0),
		int64(1893456000),
		int64(0),
	)
	f.Fuzz(func(t *testing.T, state int, modes uint32, status int32, seconds, fraction int64) {
		got := decodeKernelUTC(kernelClockReading{
			state: state, modes: modes, status: status, seconds: seconds, fraction: fraction,
		})
		if got.IsZero() {
			return
		}
		validState := state == 0 && modes == 0 && status >= 0 && status&0x1070 == 0
		validSeconds := seconds > 0 && seconds <= 253402300799
		resolution := int64(1000)
		if status&0x2000 != 0 {
			resolution = 1
		}
		validFraction := fraction >= 0 && fraction < 1000000000/resolution
		if !validState || !validSeconds || !validFraction {
			t.Fatal("accepted kernel clock violates synchronization or timestamp bounds")
		}
		exactTime := got.Unix() == seconds && int64(got.Nanosecond()) == fraction*resolution
		if !exactTime || got.Location() != time.UTC {
			t.Fatal("accepted kernel clock changed its exact represented utc instant")
		}
	})
}
