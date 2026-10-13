package radius

import (
	"errors"
	"math"
	"slices"
	"strconv"
	"strings"
	"time"
)

type sessionState struct {
	first       event
	last        event
	epoch       time.Time
	stoppedAt   time.Time
	hasStart    bool
	hasRecovery bool
	isClosed    bool
	hasConflict bool
}

// applyEvent keeps closed generations until the capture ends. A delayed Stop
// belongs to its duration-derived generation, not every reuse of the NAS ID.
func applyEvent(states map[string][]*sessionState, item event, count *int) error {
	if item.duration > uint64(math.MaxInt64/int64(time.Second)) {
		return errors.New("radius: session duration out of range")
	}
	elapsed := time.Duration(item.duration) * time.Second
	epoch := item.original.Add(-elapsed)
	if epoch.Unix() <= 0 {
		return errors.New("radius: invalid session time anchor")
	}
	var matches []*sessionState
	closest := clockTolerance
	for _, state := range states[item.key] {
		if state.first.mac != item.mac {
			return errors.New("radius: session identity has conflicting owners")
		}
		if !near(epoch, state.epoch) || state.isClosed && epoch.After(state.stoppedAt) {
			continue
		}
		distance := epoch.Sub(state.epoch)
		if distance < 0 {
			distance = -distance // near bounds this difference to five seconds.
		}
		if distance < closest {
			closest, matches = distance, nil
		}
		if distance == closest {
			matches = append(matches, state)
		}
	}
	if len(matches) > 1 {
		for _, state := range matches {
			state.hasConflict = true
		}
		return nil
	}
	if len(matches) == 1 {
		matches[0].apply(item, elapsed)
		return nil
	}
	if *count >= maximumSessions {
		return errors.New("radius: session limit exceeded")
	}
	*count++
	for _, older := range states[item.key] {
		if older.epoch.Before(epoch) && item.status != "Start" {
			// An unexplained counter reset must not leave an earlier Start
			// authorized. An older delayed Stop cannot affect a newer epoch.
			if item.status == "Stop" {
				older.close(item.original)
			} else {
				older.hasConflict = true
			}
		}
	}
	state := &sessionState{
		first: item, last: item, epoch: epoch,
		hasStart:    item.status == "Start" && item.duration == 0,
		hasConflict: item.status == "Start" && item.duration != 0,
	}
	if item.status == "Stop" {
		state.close(item.original)
	}
	states[item.key] = append(states[item.key], state)
	return nil
}

func (state *sessionState) apply(item event, elapsed time.Duration) {
	if item.status == "Stop" {
		state.close(item.original)
		return
	}
	if state.isClosed {
		return
	}
	if item.status == "Start" {
		if item.duration != 0 || state.hasStart &&
			(item.original != state.first.original || !samePlacement(item, state.first)) {
			state.hasConflict = true
		}
		// A late Start cannot turn one orphan interim into qualified evidence.
		return
	}
	if item.duration < state.last.duration {
		return
	}
	if item.duration == state.last.duration {
		if !samePlacement(item, state.last) {
			state.hasConflict = true
		}
		return
	}
	if item.port != state.first.port || item.vlan != state.last.vlan {
		state.hasConflict = true
		return
	}
	// Duration was bounded before this state was selected. Preserve the earliest
	// anchor rather than extending freshness for small NAS clock differences.
	anchored := state.epoch.Add(elapsed)
	if anchored.Before(item.original) {
		item.original = anchored
	}
	if !state.hasStart && !state.hasRecovery && state.last.canRecover && item.canRecover &&
		item.original.After(state.last.original) && item.original.Before(state.last.original.Add(Freshness)) &&
		samePlacement(item, state.last) {
		state.hasRecovery = true
	}
	state.last = item
}

func (state *sessionState) close(at time.Time) {
	if !state.isClosed || at.Before(state.stoppedAt) {
		state.stoppedAt = at
	}
	state.isClosed = true
}

func current(states map[string][]*sessionState, now time.Time) Observation {
	byMAC := make(map[string][]*sessionState)
	for _, generations := range states {
		for _, state := range generations {
			if !state.isClosed && !state.last.original.After(now) && now.Before(state.last.original.Add(Freshness)) {
				byMAC[state.first.mac] = append(byMAC[state.first.mac], state)
			}
		}
	}
	result := Observation{ObservedAt: now, Sessions: []Session{}}
	for mac, active := range byMAC {
		if len(active) != 1 || active[0].hasConflict || !active[0].hasStart && !active[0].hasRecovery {
			result.Withheld++
			continue
		}
		state := active[0]
		result.Sessions = append(result.Sessions, Session{
			MAC: mac, NAS: state.last.nas,
			AssociationID: digest(state.first.key, strconv.FormatInt(state.epoch.Unix(), 10)),
			StartedAt:     state.epoch, ObservedAt: state.last.original,
			ValidUntil: state.last.original.Add(Freshness), IPv4: state.last.ip,
			ReportedVLAN: state.last.vlan, IPv6Reported: state.last.ipv6,
		})
	}
	slices.SortFunc(result.Sessions, func(a, b Session) int { return strings.Compare(a.MAC, b.MAC) })
	return result
}
