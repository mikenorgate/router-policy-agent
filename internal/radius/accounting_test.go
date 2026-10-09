package radius

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"net/netip"
	"strconv"
	"strings"
	"testing"
	"time"
)

const fixtureBoot = "0123456789abcdef0123456789abcdef"

func fixtureScope() Scope {
	return Scope{BootID: fixtureBoot, ServiceUID: 123,
		NASPrefixes: []netip.Prefix{netip.MustParsePrefix("198.51.100.0/24")}}
}

func fixtureTime() time.Time { return time.Unix(1760000000, 0).UTC() }

func fixtureEvent(status string, duration int) accountingEvent {
	return accountingEvent{
		ReceivedAt: fixtureTime().Unix() + int64(duration), MAC: "02AABBCCDDEE",
		NASSource: "198.51.100.10", NASReportedIPv4: "198.51.100.10",
		NASPort: "1", NASPortType: "Wireless-802.11", NASPortIDHex: "776c616e30",
		SessionIDHex: "73657373696f6e2d31", Status: status,
		DelaySeconds: "0", SessionSeconds: strconv.Itoa(duration), IPv4: "192.0.2.80",
		VLANReportedHex: hex.EncodeToString([]byte("22")),
	}
}

func fixtureEntry(t testing.TB, event accountingEvent) map[string]any {
	t.Helper()
	payload, err := json.Marshal(event)
	if err != nil {
		t.Fatal(err)
	}
	return map[string]any{
		"MESSAGE": marker + string(payload), "_SYSTEMD_UNIT": "freeradius.service",
		"SYSLOG_IDENTIFIER": "freeradius", "_BOOT_ID": fixtureBoot, "_UID": "123",
		"__REALTIME_TIMESTAMP": strconv.FormatInt(event.ReceivedAt*1000000+100, 10),
		"__CURSOR":             "synthetic-local-journal-cursor",
	}
}

func encodeEntries(t testing.TB, entries ...map[string]any) []byte {
	t.Helper()
	var data bytes.Buffer
	for _, entry := range entries {
		encoded, err := json.Marshal(entry)
		if err != nil {
			t.Fatal(err)
		}
		data.Write(encoded)
		data.WriteByte('\n')
	}
	return data.Bytes()
}

func fixtureHistory(t testing.TB, events ...accountingEvent) []byte {
	t.Helper()
	entries := make([]map[string]any, 0, len(events))
	for _, event := range events {
		entries = append(entries, fixtureEntry(t, event))
	}
	return encodeEntries(t, entries...)
}

func currentSession(t testing.TB) Session {
	t.Helper()
	result, err := Replay(fixtureHistory(t, fixtureEvent("Start", 0), fixtureEvent("Interim-Update", 60)),
		fixtureScope(), fixtureTime().Add(75*time.Second))
	if err != nil || len(result.Sessions) != 1 || result.Withheld != 0 {
		t.Fatalf("current session missing: %v", err)
	}
	return result.Sessions[0]
}

func TestReplayPreservesOriginalEvidenceAndIdentity(t *testing.T) {
	t.Parallel()
	first := currentSession(t)
	duplicateStart := fixtureEvent("Start", 0)
	duplicateStart.ReceivedAt += 70
	duplicateStart.DelaySeconds = "70"
	duplicateInterim := fixtureEvent("Interim-Update", 60)
	duplicateInterim.ReceivedAt += 15
	duplicateInterim.DelaySeconds = "15"
	data := fixtureHistory(t, fixtureEvent("Start", 0), fixtureEvent("Interim-Update", 60), duplicateStart, duplicateInterim)
	for _, seconds := range []int{76, 100, 149} {
		observation, err := Replay(data, fixtureScope(), fixtureTime().Add(time.Duration(seconds)*time.Second))
		if err != nil || len(observation.Sessions) != 1 || observation.Sessions[0] != first {
			t.Fatalf("reread or duplicate renewed evidence: %v", err)
		}
	}
	if first.MAC != "02:aa:bb:cc:dd:ee" || first.StartedAt != fixtureTime() ||
		first.ObservedAt != fixtureTime().Add(60*time.Second) ||
		first.ValidUntil != fixtureTime().Add(150*time.Second) || len(first.AssociationID) != 64 {
		t.Fatal("original session identity or lifetime changed")
	}
	if strings.Contains(first.AssociationID, "session-1") {
		t.Fatal("raw session identity escaped")
	}
	atExpiry, err := Replay(data, fixtureScope(), first.ValidUntil)
	if err != nil || len(atExpiry.Sessions) != 0 {
		t.Fatal("expiry boundary extended session")
	}
}

func TestReplayWithholdsStoppedReusedOrConflictingSessions(t *testing.T) {
	t.Parallel()
	for _, name := range []string{"stop", "stop before start", "late start after stop", "late interim after stop",
		"missing start", "orphan then start", "reuse", "start duration", "duration clock", "duplicate address",
		"port change", "vlan change", "roaming overlap"} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			start, interim := fixtureEvent("Start", 0), fixtureEvent("Interim-Update", 60)
			events := []accountingEvent{start, interim}
			switch name {
			case "stop":
				events = append(events, fixtureEvent("Stop", 70))
			case "stop before start", "late start after stop":
				delayed := start
				delayed.ReceivedAt += 74
				delayed.DelaySeconds = "74"
				if name == "stop before start" {
					events = nil
				}
				events = append(events, fixtureEvent("Stop", 70), delayed)
			case "late interim after stop":
				events = append(events, fixtureEvent("Stop", 70), fixtureEvent("Alive", 74))
			case "missing start":
				events = []accountingEvent{interim}
			case "orphan then start":
				start.ReceivedAt += 70
				start.DelaySeconds = "70"
				events = []accountingEvent{interim, start}
			case "reuse":
				start.ReceivedAt += 70
				events = append(events, start)
			case "start duration":
				start.SessionSeconds = "5"
				events = []accountingEvent{start, interim}
			case "duration clock":
				interim.SessionSeconds = "20"
				events = []accountingEvent{start, interim}
			case "duplicate address":
				duplicate := interim
				duplicate.ReceivedAt++
				duplicate.IPv4 = "192.0.2.81"
				events = append(events, duplicate)
			case "port change":
				interim.NASPort = "2"
				events = []accountingEvent{start, interim}
			case "vlan change":
				interim.VLANReportedHex = hex.EncodeToString([]byte("33"))
				events = []accountingEvent{start, interim}
			case "roaming overlap":
				other := fixtureEvent("Start", 65)
				other.SessionSeconds = "0"
				other.NASSource, other.NASReportedIPv4 = "198.51.100.11", "198.51.100.11"
				events = append(events, other)
			}
			result, err := Replay(fixtureHistory(t, events...), fixtureScope(), fixtureTime().Add(75*time.Second))
			if err != nil || len(result.Sessions) != 0 {
				t.Fatalf("unsafe session became current: %v", err)
			}
		})
	}
}

func TestReplayRoamingAndDelayedOlderDuration(t *testing.T) {
	t.Parallel()
	oldStart, oldInterim := fixtureEvent("Start", 0), fixtureEvent("Alive", 60)
	newStart := fixtureEvent("Start", 65)
	newStart.SessionSeconds = "0"
	newStart.NASSource, newStart.NASReportedIPv4 = "198.51.100.11", "198.51.100.11"
	stop := fixtureEvent("Stop", 70)
	late := fixtureEvent("Alive", 30)
	late.ReceivedAt += 44
	late.DelaySeconds = "44"
	late.IPv4 = "192.0.2.79"
	data := fixtureHistory(t, oldStart, oldInterim, newStart, stop, late)
	result, err := Replay(data, fixtureScope(), fixtureTime().Add(75*time.Second))
	if err != nil || len(result.Sessions) != 1 || result.Withheld != 0 || result.Sessions[0].NAS != netip.MustParseAddr("198.51.100.11") {
		t.Fatalf("stopped old NAS affected new association: %v", err)
	}
	result, err = Replay(fixtureHistory(t, oldStart, oldInterim, late), fixtureScope(), fixtureTime().Add(75*time.Second))
	if err != nil || len(result.Sessions) != 1 || result.Sessions[0].IPv4.String() != "192.0.2.80" ||
		result.Sessions[0].ObservedAt != fixtureTime().Add(60*time.Second) {
		t.Fatal("reordered older duration changed current evidence")
	}
}

func TestReplayRejectsSourceSchemaAndTimingFailures(t *testing.T) {
	t.Parallel()
	for _, name := range []string{"boot", "uid", "unit", "identifier", "future receipt", "journal clock", "nas", "nas claim",
		"session hex", "session limit", "port hex", "missing delay", "delay overflow", "delay beyond receipt",
		"missing duration", "ambiguous timestamp", "conflicting timestamp", "unsupported status", "vlan", "mapped ip", "field limit", "unknown field", "duplicate key"} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			event := fixtureEvent("Interim-Update", 60)
			switch name {
			case "future receipt":
				event.ReceivedAt += 60
			case "nas":
				event.NASSource = "203.0.113.10"
			case "nas claim":
				event.NASReportedIPv4 = "198.51.100.11"
			case "session hex":
				event.SessionIDHex = "not hex"
			case "session limit":
				event.SessionIDHex = strings.Repeat("ff", 129)
			case "port hex":
				event.NASPortIDHex = "odd"
			case "missing delay":
				event.DelaySeconds = ""
			case "delay overflow":
				event.DelaySeconds = "4294967296"
			case "delay beyond receipt":
				event.DelaySeconds = "1760000060"
			case "missing duration":
				event.SessionSeconds = ""
			case "ambiguous timestamp":
				event.EventTime = "Oct 09 2025 08:54:20 BST"
			case "conflicting timestamp":
				event.EventTime = strconv.FormatInt(event.ReceivedAt-30, 10)
			case "unsupported status":
				event.Status = "Accounting-On"
			case "vlan":
				event.VLANReportedHex = hex.EncodeToString([]byte("4095"))
			case "mapped ip":
				event.IPv4 = "::ffff:192.0.2.80"
			case "field limit":
				event.NASPortType = strings.Repeat("x", 2049)
			}
			entry := fixtureEntry(t, event)
			message, ok := entry["MESSAGE"].(string)
			if !ok {
				t.Fatal("fixture message is not a string")
			}
			switch name {
			case "boot":
				entry["_BOOT_ID"] = "fedcba9876543210fedcba9876543210"
			case "uid":
				entry["_UID"] = "124"
			case "unit":
				entry["_SYSTEMD_UNIT"] = "other.service"
			case "identifier":
				entry["SYSLOG_IDENTIFIER"] = "other"
			case "journal clock":
				entry["__REALTIME_TIMESTAMP"] = strconv.FormatInt((event.ReceivedAt+11)*1000000, 10)
			case "unknown field":
				entry["MESSAGE"] = strings.TrimSuffix(message, "}") + `,"allow":true}`
			case "duplicate key":
				entry["MESSAGE"] = strings.TrimSuffix(message, "}") + `,"status":"Start"}`
			}
			result, err := Replay(encodeEntries(t, entry), fixtureScope(), fixtureTime().Add(75*time.Second))
			if err == nil || len(result.Sessions) != 0 || !result.ObservedAt.IsZero() {
				t.Fatal("bad provenance or input returned partial evidence")
			}
		})
	}
}

func TestReplayRejectsPartialOversizedAndReorderedHistory(t *testing.T) {
	t.Parallel()
	valid := fixtureHistory(t, fixtureEvent("Start", 0), fixtureEvent("Alive", 60))
	for _, data := range [][]byte{
		valid[:len(valid)-1], append(bytes.Clone(valid), []byte("{\n")...),
		bytes.Repeat([]byte("x"), maximumHistory+1),
		append(bytes.Repeat([]byte(" "), maximumEntry), '\n'),
		fixtureHistory(t, fixtureEvent("Alive", 60), fixtureEvent("Start", 0)),
	} {
		if result, err := Replay(data, fixtureScope(), fixtureTime().Add(75*time.Second)); err == nil || len(result.Sessions) != 0 {
			t.Fatal("invalid complete-history envelope accepted")
		}
	}
	otherOwner := fixtureEvent("Alive", 60)
	otherOwner.MAC = "02AABBCCDDFF"
	if _, err := Replay(fixtureHistory(t, fixtureEvent("Start", 0), otherOwner), fixtureScope(), fixtureTime().Add(75*time.Second)); err == nil {
		t.Fatal("session reused by a different MAC accepted")
	}
	for _, scope := range []Scope{{}, {BootID: fixtureBoot, NASPrefixes: []netip.Prefix{netip.MustParsePrefix("198.51.100.1/24")}}} {
		if _, err := Replay(valid, scope, fixtureTime().Add(75*time.Second)); err == nil {
			t.Fatal("invalid local scope accepted")
		}
	}
	if result, err := Replay(nil, fixtureScope(), fixtureTime()); err != nil || len(result.Sessions) != 0 {
		t.Fatal("empty history granted evidence or failed")
	}
}

func TestReplayAcceptsUTCOriginalTimestampAndIPv6ClaimWithoutQualification(t *testing.T) {
	t.Parallel()
	for _, format := range []string{"epoch", "Jan 02 2006 15:04:05 MST", "Jan _2 2006 15:04:05 MST"} {
		interim := fixtureEvent("Alive", 60)
		interim.EventTime = strconv.FormatInt(interim.ReceivedAt, 10)
		if format != "epoch" {
			interim.EventTime = time.Unix(interim.ReceivedAt, 0).UTC().Format(format)
		}
		interim.IPv6Addresses = "2001:db8::80"
		result, err := Replay(fixtureHistory(t, fixtureEvent("Start", 0), interim), fixtureScope(), fixtureTime().Add(75*time.Second))
		if err != nil || len(result.Sessions) != 1 || !result.Sessions[0].IPv6Reported ||
			result.Sessions[0].ObservedAt != time.Unix(interim.ReceivedAt, 0).UTC() {
			t.Fatalf("original UTC event rejected or refreshed: %v", err)
		}
	}
}

func FuzzReplay(f *testing.F) {
	f.Add(fixtureHistory(f, fixtureEvent("Start", 0), fixtureEvent("Alive", 60)))
	f.Add([]byte("{}\n"))
	f.Fuzz(func(t *testing.T, data []byte) {
		result, err := Replay(data, fixtureScope(), fixtureTime().Add(75*time.Second))
		if err != nil && (!result.ObservedAt.IsZero() || len(result.Sessions) != 0) {
			t.Fatal("error exposed partial evidence")
		}
	})
}
