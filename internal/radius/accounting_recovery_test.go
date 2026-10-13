package radius

import (
	"strconv"
	"testing"
	"time"
)

func recoveryHistory(t testing.TB, bootAt time.Time, events ...accountingEvent) []byte {
	t.Helper()
	entries := make([]map[string]any, 0, len(events))
	for _, event := range events {
		entry := fixtureEntry(t, event)
		elapsed := time.Unix(event.ReceivedAt, 0).Sub(bootAt)
		entry["__MONOTONIC_TIMESTAMP"] = strconv.FormatInt(elapsed.Microseconds()+100, 10)
		entries = append(entries, entry)
	}
	return encodeEntries(t, entries...)
}

func sessionEvent(status string, received, duration int) accountingEvent {
	event := fixtureEvent(status, received)
	event.SessionSeconds = strconv.Itoa(duration)
	return event
}

func TestReplayRecoversWithoutStartAfterRouterRestart(t *testing.T) {
	t.Parallel()
	data := recoveryHistory(
		t,
		fixtureTime().Add(550*time.Second),
		sessionEvent("Interim-Update", 600, 600),
		sessionEvent("Interim-Update", 660, 660),
	)
	result, err := Replay(data, fixtureScope(), fixtureTime().Add(675*time.Second))
	if err != nil || len(result.Sessions) != 1 || result.Withheld != 0 {
		t.Fatalf("fresh post-restart evidence did not recover: %+v, %v", result, err)
	}
	session := result.Sessions[0]
	if session.StartedAt != fixtureTime() || session.ObservedAt != fixtureTime().Add(660*time.Second) ||
		session.ValidUntil != fixtureTime().Add(750*time.Second) {
		t.Fatal("recovery changed the original association or refreshed its lifetime")
	}
	for _, seconds := range []int{700, 749, 750} {
		again, err := Replay(data, fixtureScope(), fixtureTime().Add(time.Duration(seconds)*time.Second))
		if err != nil {
			t.Fatal(err)
		}
		if seconds < 750 && (len(again.Sessions) != 1 || again.Sessions[0] != session) {
			t.Fatal("rereading recovery evidence changed its identity or deadline")
		}
		if seconds == 750 && len(again.Sessions) != 0 {
			t.Fatal("recovery evidence survived its expiry")
		}
	}
}

func TestReplayWithholdsUnsafeRecovery(t *testing.T) {
	t.Parallel()
	for _, name := range []string{
		"single update", "no boot evidence", "duplicate duration", "stale corroboration",
		"before restart", "counter changed", "port changed", "address changed", "stop observed",
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			first, second := sessionEvent("Alive", 600, 600), sessionEvent("Alive", 660, 660)
			bootAt := fixtureTime().Add(550 * time.Second)
			now := fixtureTime().Add(675 * time.Second)
			events := []accountingEvent{first, second}
			switch name {
			case "single update":
				events = events[:1]
			case "duplicate duration":
				second.SessionSeconds, second.DelaySeconds = "600", "60"
				events[1] = second
			case "stale corroboration":
				events[1] = sessionEvent("Alive", 720, 720)
				now = fixtureTime().Add(735 * time.Second)
			case "before restart":
				first.ReceivedAt, first.DelaySeconds = fixtureTime().Unix()+680, "80"
				second.ReceivedAt, second.DelaySeconds = fixtureTime().Unix()+690, "30"
				bootAt, now = fixtureTime().Add(670*time.Second), fixtureTime().Add(695*time.Second)
				events = []accountingEvent{first, second}
			case "counter changed":
				events[1].SessionSeconds = "620"
			case "port changed":
				events[1].NASPort = "2"
			case "address changed":
				events[1].IPv4 = "192.0.2.81"
			case "stop observed":
				events = []accountingEvent{first, sessionEvent("Stop", 620, 620), second}
			}
			data := recoveryHistory(t, bootAt, events...)
			if name == "no boot evidence" {
				data = fixtureHistory(t, events...)
			}
			result, err := Replay(data, fixtureScope(), now)
			if err != nil || len(result.Sessions) != 0 {
				t.Fatalf("unsafe recovery became current: %+v, %v", result, err)
			}
		})
	}
}

func TestReplaySessionIDReuseSeparatesConnectionGenerations(t *testing.T) {
	t.Parallel()
	oldStop := sessionEvent("Stop", 70, 70)
	oldStop.ReceivedAt, oldStop.DelaySeconds = fixtureTime().Unix()+185, "115"
	data := fixtureHistory(
		t,
		sessionEvent("Start", 0, 0),
		sessionEvent("Alive", 60, 60),
		sessionEvent("Stop", 70, 70),
		sessionEvent("Start", 120, 0),
		sessionEvent("Alive", 180, 60),
		oldStop,
	)
	result, err := Replay(data, fixtureScope(), fixtureTime().Add(190*time.Second))
	if err != nil || len(result.Sessions) != 1 || result.Withheld != 0 {
		t.Fatalf("closed previous generation blocked a fresh association: %+v, %v", result, err)
	}
	if result.Sessions[0].StartedAt != fixtureTime().Add(120*time.Second) ||
		result.Sessions[0].ObservedAt != fixtureTime().Add(180*time.Second) ||
		result.Sessions[0].AssociationID == currentSession(t).AssociationID {
		t.Fatal("reused session id retained the previous generation")
	}
}

func TestReplayRejectsMalformedMonotonicRecoveryEvidence(t *testing.T) {
	t.Parallel()
	for _, test := range []struct {
		name  string
		value any
	}{
		{name: "text", value: "invalid"},
		{name: "negative", value: "-1"},
		{name: "overflow", value: "18446744073709551615"},
		{name: "multiple values", value: []string{"1", "2"}},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			entry := fixtureEntry(t, fixtureEvent("Alive", 60))
			entry["__MONOTONIC_TIMESTAMP"] = test.value
			if _, err := Replay(encodeEntries(t, entry), fixtureScope(), fixtureTime().Add(75*time.Second)); err == nil {
				t.Fatal("malformed trusted clock metadata accepted")
			}
		})
	}
}

func TestReplayRejectsMonotonicClockConflicts(t *testing.T) {
	t.Parallel()
	for _, test := range []struct {
		name  string
		value string
	}{
		{name: "backwards", value: "49000000"},
		{name: "wall clock disagreement", value: "80000000"},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			first := fixtureEntry(t, sessionEvent("Alive", 600, 600))
			first["__MONOTONIC_TIMESTAMP"] = "50000100"
			second := fixtureEntry(t, sessionEvent("Alive", 660, 660))
			second["__MONOTONIC_TIMESTAMP"] = test.value
			if _, err := Replay(encodeEntries(t, first, second), fixtureScope(), fixtureTime().Add(675*time.Second)); err == nil {
				t.Fatal("inconsistent clock evidence accepted")
			}
		})
	}
}

func TestReplayRecoveryNeverRevivesStoppedGeneration(t *testing.T) {
	t.Parallel()
	data := recoveryHistory(t, fixtureTime().Add(550*time.Second),
		sessionEvent("Alive", 600, 600), sessionEvent("Alive", 660, 660),
		sessionEvent("Stop", 670, 670), sessionEvent("Alive", 720, 720), sessionEvent("Alive", 780, 780))
	result, err := Replay(data, fixtureScope(), fixtureTime().Add(790*time.Second))
	if err != nil || len(result.Sessions) != 0 {
		t.Fatalf("later interims revived stopped generation: %+v, %v", result, err)
	}
}

func TestReplayRecoveryUsesNewGenerationWithoutStart(t *testing.T) {
	t.Parallel()
	data := recoveryHistory(t, fixtureTime().Add(-10*time.Second),
		sessionEvent("Start", 0, 0), sessionEvent("Stop", 70, 70),
		sessionEvent("Alive", 180, 60), sessionEvent("Alive", 240, 120))
	result, err := Replay(data, fixtureScope(), fixtureTime().Add(250*time.Second))
	if err != nil || len(result.Sessions) != 1 || result.Sessions[0].StartedAt != fixtureTime().Add(120*time.Second) {
		t.Fatalf("fresh reused generation without Start did not recover: %+v, %v", result, err)
	}
}

func TestReplayBoundsReusedSessionGenerations(t *testing.T) {
	t.Parallel()
	events := make([]accountingEvent, 0, maximumSessions+1)
	for index := range maximumSessions + 1 {
		events = append(events, sessionEvent("Stop", index*10, 0))
	}
	if _, err := Replay(fixtureHistory(t, events...), fixtureScope(), fixtureTime().Add(time.Duration(maximumSessions*10+1)*time.Second)); err == nil {
		t.Fatal("reused session generations bypassed the state quota")
	}
}

func TestReplayRapidSessionIDReuse(t *testing.T) {
	t.Parallel()
	for _, hasStart := range []bool{true, false} {
		name := "interim recovery"
		if hasStart {
			name = "explicit start"
		}
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			events := []accountingEvent{sessionEvent("Start", 0, 0), sessionEvent("Stop", 1, 1)}
			if hasStart {
				events = append(events, sessionEvent("Start", 2, 0))
			}
			oldStop := sessionEvent("Stop", 1, 1)
			oldStop.ReceivedAt, oldStop.DelaySeconds = fixtureTime().Unix()+125, "124"
			events = append(events, sessionEvent("Alive", 62, 60), sessionEvent("Alive", 122, 120), oldStop)
			data := recoveryHistory(t, fixtureTime().Add(-10*time.Second), events...)
			result, err := Replay(data, fixtureScope(), fixtureTime().Add(130*time.Second))
			if err != nil || len(result.Sessions) != 1 || result.Sessions[0].StartedAt != fixtureTime().Add(2*time.Second) {
				t.Fatalf("rapid reconnect retained the old tombstone: %+v, %v", result, err)
			}
		})
	}
}
