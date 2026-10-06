package firewall

import (
	"syscall"
	"time"
)

// These ABI values are defined by Linux's sys/timex.h. The query always uses
// modes=0: it neither sets time nor requires CAP_SYS_TIME.
const (
	kernelTimeOK         = 0
	kernelStatusLeap     = 0x0010 | 0x0020
	kernelStatusUnsafe   = 0x0040 | 0x1000
	kernelStatusNano     = 0x2000
	maximumKernelSeconds = 253402300799 // Last second in year 9999.
)

// This narrow projection keeps native long widths out of timestamp validation.
// It is not an input protocol or a serialized synchronization attestation.
type kernelClockReading struct {
	state    int
	modes    uint32
	status   int32
	seconds  int64
	fraction int64
}

// kernelUTC is the configured helper's fixed, read-only clock source. A zero
// value makes existing engine/render checks reject authorization. It does not
// qualify the synchronization daemon, its reference, accuracy or suspend paths.
func kernelUTC() time.Time {
	return readKernelUTC(syscall.Adjtimex)
}

// The query dependency is private testing/composition plumbing, not a runtime
// option. No file, environment value or reader request can select it or a mode.
func readKernelUTC(query func(*syscall.Timex) (int, error)) time.Time {
	if query == nil {
		return time.Time{}
	}
	var reading syscall.Timex
	state, err := query(&reading)
	if err != nil {
		return time.Time{}
	}
	return decodeKernelUTC(kernelClockReading{
		state: state, modes: reading.Modes, status: reading.Status,
		//nolint:unconvert // Linux timeval uses native longs; widening also supports 32-bit ABIs.
		seconds: int64(reading.Time.Sec), fraction: int64(reading.Time.Usec),
	})
}

func decodeKernelUTC(reading kernelClockReading) time.Time {
	// Check the returned flags too; an asynchronous state observation is not a
	// reason to accept an explicitly unsafe or leap-adjusting reading.
	isUnsafe := reading.status < 0 || reading.status&(kernelStatusLeap|kernelStatusUnsafe) != 0
	isSynchronized := reading.state == kernelTimeOK && reading.modes == 0
	if !isSynchronized || isUnsafe {
		return time.Time{}
	}
	validSeconds := reading.seconds > 0 && reading.seconds <= maximumKernelSeconds
	if !validSeconds || reading.fraction < 0 {
		return time.Time{}
	}
	unit := int64(time.Microsecond)
	if reading.status&kernelStatusNano != 0 {
		unit = int64(time.Nanosecond)
	}
	if reading.fraction >= int64(time.Second)/unit {
		return time.Time{}
	}
	return time.Unix(reading.seconds, reading.fraction*unit).UTC()
}
