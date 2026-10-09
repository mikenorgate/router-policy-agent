// Package radius correlates authenticated accounting history without granting
// firewall authority. Its observations lack independent VLAN placement and
// packet-source ownership evidence and are not binding snapshots.
package radius

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"net/netip"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/mikenorgate/router-policy-agent/internal/policy"
	"github.com/mikenorgate/router-policy-agent/internal/strictjson"
)

const (
	marker          = "radius-policy-accounting-v1 "
	maximumHistory  = 16 << 20
	maximumEntry    = 32 << 10
	maximumEvents   = 16384
	maximumSessions = 4096
	clockTolerance  = 5 * time.Second
	// Freshness bounds session evidence; rereading the journal cannot renew it.
	Freshness = 90 * time.Second
)

// Scope pins the current boot and authenticated local RADIUS service identity.
// NASPrefixes admit authenticated NAS sources, not device addresses or VLANs.
type Scope struct {
	BootID      string
	ServiceUID  uint32
	NASPrefixes []netip.Prefix
}

// Observation contains only unambiguous, fresh sessions from one replay.
// Withheld counts MACs with conflicting current sessions, including roaming.
// ObservedAt is the caller's collection time, not a session heartbeat.
type Observation struct {
	ObservedAt time.Time
	Sessions   []Session
	Withheld   int
}

// Session retains original accounting times and an opaque boot-scoped identity.
// ReportedVLAN is a NAS claim, not independently verified physical placement.
// IPv6Reported does not qualify any native IPv6 or privacy address.
type Session struct {
	MAC           string     `json:"mac"`
	NAS           netip.Addr `json:"nas"`
	AssociationID string     `json:"association_id"`
	StartedAt     time.Time  `json:"started_at"`
	ObservedAt    time.Time  `json:"observed_at"`
	ValidUntil    time.Time  `json:"valid_until"`
	IPv4          netip.Addr `json:"ipv4"`
	ReportedVLAN  uint16     `json:"reported_vlan"`
	IPv6Reported  bool       `json:"ipv6_reported"`
}

type accountingEvent struct {
	ReceivedAt      int64  `json:"received_at"`
	MAC             string `json:"mac"`
	NASSource       string `json:"nas_source"`
	NASReportedIPv4 string `json:"nas_reported_ipv4"`
	NASPort         string `json:"nas_port"`
	NASPortType     string `json:"nas_port_type"`
	NASPortIDHex    string `json:"nas_port_id_hex"`
	SessionIDHex    string `json:"session_id_hex"`
	Status          string `json:"status"`
	EventTime       string `json:"event_time"`
	DelaySeconds    string `json:"delay_seconds"`
	SessionSeconds  string `json:"session_seconds"`
	IPv4            string `json:"ipv4"`
	IPv6Addresses   string `json:"ipv6_addresses"`
	IPv6Prefixes    string `json:"ipv6_prefixes"`
	InterfaceID     string `json:"interface_id"`
	VLANReportedHex string `json:"vlan_reported_hex"`
}

type event struct {
	mac       string
	nas       netip.Addr
	key       string
	status    string
	original  time.Time
	journalAt time.Time
	duration  uint64
	ip        netip.Addr
	vlan      uint16
	port      string
	ipv6      bool
}

type sessionState struct {
	first    event
	last     event
	started  bool
	closed   bool
	conflict bool
}

// Replay consumes a bounded, chronological journal JSON capture, preserving
// Stop tombstones and original Start/session-duration anchors. The caller must
// authenticate the journal source and supply complete current-boot history;
// JSON metadata alone cannot authenticate arbitrary input or prove completeness.
// Do not use a tail, reverse-order capture or previously filtered active list.
// Missing Starts, reused IDs and overlapping sessions withhold candidates.
// Malformed, oversized, wrong-source or out-of-order input returns no result.
// This is a correlation core, not an installed collector or enforcement feed.
func Replay(data []byte, scope Scope, now time.Time) (Observation, error) {
	if !validScope(scope) || now.IsZero() || len(data) > maximumHistory ||
		(len(data) != 0 && data[len(data)-1] != '\n') {
		return Observation{}, errors.New("radius: invalid scope or incomplete history")
	}
	states := make(map[string]*sessionState)
	previous := time.Time{}
	count := 0
	for line := range bytes.Lines(data) {
		count++
		if count > maximumEvents {
			return Observation{}, errors.New("radius: event limit exceeded")
		}
		item, err := decodeEntry(bytes.TrimSuffix(line, []byte{'\n'}), scope, now)
		if err != nil {
			return Observation{}, err
		}
		if item.journalAt.Before(previous) {
			return Observation{}, errors.New("radius: journal clock or order conflict")
		}
		previous = item.journalAt
		state, exists := states[item.key]
		if !exists {
			if len(states) >= maximumSessions {
				return Observation{}, errors.New("radius: session limit exceeded")
			}
			state = &sessionState{first: item, last: item}
			states[item.key] = state
		}
		if state.first.mac != item.mac {
			return Observation{}, errors.New("radius: session identity has conflicting owners")
		}
		state.apply(item)
	}
	return current(states, now), nil
}

func validScope(scope Scope) bool {
	boot, err := hex.DecodeString(scope.BootID)
	if err != nil || len(boot) != 16 || len(scope.NASPrefixes) == 0 || len(scope.NASPrefixes) > 64 {
		return false
	}
	for _, prefix := range scope.NASPrefixes {
		if !prefix.IsValid() || prefix != prefix.Masked() || prefix.Addr().Is4In6() || prefix.Addr().Zone() != "" {
			return false
		}
	}
	return true
}

func decodeEntry(data []byte, scope Scope, now time.Time) (event, error) {
	entry := make(map[string]json.RawMessage)
	if err := strictjson.Decode(data, &entry, maximumEntry); err != nil {
		return event{}, errors.New("radius: invalid journal entry")
	}
	fields := []string{"MESSAGE", "_SYSTEMD_UNIT", "SYSLOG_IDENTIFIER", "_BOOT_ID", "_UID", "__REALTIME_TIMESTAMP"}
	values := make(map[string]string, len(fields))
	for _, field := range fields {
		var value string
		if err := json.Unmarshal(entry[field], &value); err != nil || value == "" {
			return event{}, errors.New("radius: missing journal provenance")
		}
		values[field] = value
	}
	if values["_SYSTEMD_UNIT"] != "freeradius.service" || values["SYSLOG_IDENTIFIER"] != "freeradius" ||
		values["_BOOT_ID"] != scope.BootID || values["_UID"] != strconv.FormatUint(uint64(scope.ServiceUID), 10) ||
		!strings.HasPrefix(values["MESSAGE"], marker) {
		return event{}, errors.New("radius: journal source or boot mismatch")
	}
	micros, err := unsigned(values["__REALTIME_TIMESTAMP"], 9999999999999999)
	if err != nil || micros > math.MaxInt64 {
		return event{}, errors.New("radius: invalid journal timestamp")
	}
	journalAt := time.UnixMicro(int64(micros)).UTC()
	payload := []byte(strings.TrimPrefix(values["MESSAGE"], marker))
	required := []string{"received_at", "mac", "nas_source", "nas_reported_ipv4", "nas_port", "nas_port_type",
		"nas_port_id_hex", "session_id_hex", "status", "event_time", "delay_seconds", "session_seconds",
		"ipv4", "ipv6_addresses", "ipv6_prefixes", "interface_id", "vlan_reported_hex"}
	if err := strictjson.Object(payload, required, nil, maximumEntry); err != nil {
		return event{}, errors.New("radius: invalid accounting schema")
	}
	var raw accountingEvent
	if err := strictjson.Decode(payload, &raw, maximumEntry); err != nil {
		return event{}, errors.New("radius: invalid accounting fields")
	}
	item, err := normalize(raw, scope, now)
	if err != nil {
		return event{}, err
	}
	receipt := time.Unix(raw.ReceivedAt, 0).UTC()
	if journalAt.Before(receipt) || journalAt.After(receipt.Add(10*time.Second)) || journalAt.After(now) {
		return event{}, errors.New("radius: journal receipt clock conflict")
	}
	item.journalAt = journalAt
	return item, nil
}

func normalize(raw accountingEvent, scope Scope, now time.Time) (event, error) {
	stringsToCheck := []string{raw.MAC, raw.NASSource, raw.NASReportedIPv4, raw.NASPort, raw.NASPortType,
		raw.NASPortIDHex, raw.SessionIDHex, raw.Status, raw.EventTime, raw.DelaySeconds, raw.SessionSeconds,
		raw.IPv4, raw.IPv6Addresses, raw.IPv6Prefixes, raw.InterfaceID, raw.VLANReportedHex}
	for _, value := range stringsToCheck {
		if len(value) > 2048 || strings.ContainsAny(value, "\x00\r\n") {
			return event{}, errors.New("radius: invalid accounting field")
		}
	}
	mac, macErr := policy.CanonicalMAC(raw.MAC)
	nas, nasErr := netip.ParseAddr(raw.NASSource)
	if macErr != nil || nasErr != nil || nas.Is4In6() || nas.Zone() != "" || !nas.IsGlobalUnicast() ||
		!slices.ContainsFunc(scope.NASPrefixes, func(prefix netip.Prefix) bool { return prefix.Contains(nas) }) ||
		(raw.NASReportedIPv4 != "" && raw.NASReportedIPv4 != nas.String()) {
		return event{}, errors.New("radius: invalid identity or unapproved NAS")
	}
	sessionID, err := hex.DecodeString(raw.SessionIDHex)
	if err != nil || len(sessionID) == 0 || len(sessionID) > 128 {
		return event{}, errors.New("radius: invalid session identity")
	}
	portID, err := hex.DecodeString(raw.NASPortIDHex)
	if err != nil || len(portID) > 128 {
		return event{}, errors.New("radius: invalid port identity")
	}
	if raw.Status != "Start" && raw.Status != "Stop" && raw.Status != "Alive" && raw.Status != "Interim-Update" {
		return event{}, errors.New("radius: unsupported accounting status")
	}
	delay, err := unsigned(raw.DelaySeconds, 0xffffffff)
	if err != nil {
		return event{}, err
	}
	durationText := raw.SessionSeconds
	if durationText == "" && raw.Status == "Start" {
		durationText = "0"
	}
	duration, err := unsigned(durationText, 0xffffffff)
	if err != nil {
		return event{}, err
	}
	if raw.ReceivedAt <= 0 || raw.ReceivedAt > now.Unix() || delay > math.MaxInt64 || delay >= uint64(raw.ReceivedAt) {
		return event{}, errors.New("radius: invalid accounting receipt or delay")
	}
	original := time.Unix(raw.ReceivedAt-int64(delay), 0).UTC() // delay < positive int64 receipt.
	if raw.EventTime != "" {
		stamp, err := eventTime(raw.EventTime)
		if err != nil || stamp.After(time.Unix(raw.ReceivedAt, 0)) || !near(stamp, original) {
			return event{}, errors.New("radius: inconsistent event timestamp")
		}
		if stamp.Before(original) {
			original = stamp
		}
	}
	var ip netip.Addr
	if raw.IPv4 != "" {
		ip, err = netip.ParseAddr(raw.IPv4)
		if err != nil || !ip.Is4() || !ip.IsGlobalUnicast() {
			return event{}, errors.New("radius: invalid reported IPv4")
		}
	}
	vlan, err := reportedVLAN(raw.VLANReportedHex)
	if err != nil {
		return event{}, err
	}
	return event{
		mac: mac, nas: nas, key: digest(scope.BootID, nas.String(), hex.EncodeToString(sessionID)),
		status: raw.Status, original: original, duration: duration, ip: ip, vlan: vlan,
		port: digest(raw.NASPort, raw.NASPortType, hex.EncodeToString(portID)),
		ipv6: raw.IPv6Addresses != "" || raw.IPv6Prefixes != "" || raw.InterfaceID != "",
	}, nil
}

// apply never removes a tombstone. Newer durations remain anchored to the
// original Start, so a delayed duplicate cannot become a new heartbeat.
func (state *sessionState) apply(item event) {
	if item.status == "Stop" {
		state.closed = true
		return
	}
	if state.closed {
		return
	}
	if item.status == "Start" {
		switch {
		case item.duration != 0:
			state.conflict = true
		case !state.started:
			state.first, state.last, state.started = item, item, true
		case item.original != state.first.original || !samePlacement(item, state.first):
			state.conflict = true
		}
		return
	}
	if !state.started {
		state.conflict = true
		state.last = item
		return
	}
	if item.duration < state.last.duration {
		return
	}
	if item.duration == state.last.duration {
		if !samePlacement(item, state.last) {
			state.conflict = true
		}
		return
	}
	if item.duration > uint64(math.MaxInt64/int64(time.Second)) {
		state.conflict = true
		return
	}
	anchored := state.first.original.Add(time.Duration(item.duration) * time.Second)
	if !near(anchored, item.original) || item.port != state.first.port || item.vlan != state.last.vlan {
		state.conflict = true
		return
	}
	if anchored.Before(item.original) {
		item.original = anchored
	}
	state.last = item
}

func current(states map[string]*sessionState, now time.Time) Observation {
	byMAC := make(map[string][]*sessionState)
	for _, state := range states {
		if !state.closed && !state.last.original.After(now) && now.Before(state.last.original.Add(Freshness)) {
			byMAC[state.first.mac] = append(byMAC[state.first.mac], state)
		}
	}
	result := Observation{ObservedAt: now, Sessions: []Session{}}
	for mac, active := range byMAC {
		if len(active) != 1 || active[0].conflict || !active[0].started {
			result.Withheld++
			continue
		}
		state := active[0]
		result.Sessions = append(result.Sessions, Session{
			MAC: mac, NAS: state.last.nas,
			AssociationID: digest(state.first.key, strconv.FormatInt(state.first.original.Unix(), 10)),
			StartedAt:     state.first.original, ObservedAt: state.last.original,
			ValidUntil: state.last.original.Add(Freshness), IPv4: state.last.ip,
			ReportedVLAN: state.last.vlan, IPv6Reported: state.last.ipv6,
		})
	}
	slices.SortFunc(result.Sessions, func(a, b Session) int { return strings.Compare(a.MAC, b.MAC) })
	return result
}

func samePlacement(a, b event) bool {
	return a.ip == b.ip && a.vlan == b.vlan && a.port == b.port && a.ipv6 == b.ipv6
}

func unsigned(value string, maximum uint64) (uint64, error) {
	if len(value) == 0 || len(value) > 20 || strings.IndexFunc(value, func(r rune) bool { return r < '0' || r > '9' }) >= 0 {
		return 0, errors.New("radius: invalid unsigned field")
	}
	parsed, err := strconv.ParseUint(value, 10, 64)
	if err != nil || parsed > maximum {
		return 0, errors.New("radius: unsigned field out of range")
	}
	return parsed, nil
}

func eventTime(value string) (time.Time, error) {
	if seconds, err := unsigned(value, 9999999999); err == nil && seconds != 0 && seconds <= math.MaxInt64 {
		return time.Unix(int64(seconds), 0).UTC(), nil
	}
	stamp, err := time.Parse("Jan _2 2006 15:04:05 MST", value)
	if err != nil || !strings.HasSuffix(value, " UTC") || stamp.Unix() <= 0 {
		return time.Time{}, errors.New("radius: unqualified timestamp format")
	}
	return stamp.UTC(), nil
}

func reportedVLAN(value string) (uint16, error) {
	if value == "" {
		return 0, nil
	}
	decoded, err := hex.DecodeString(value)
	if err != nil || len(decoded) > 4 {
		return 0, errors.New("radius: invalid reported VLAN")
	}
	number, err := unsigned(string(decoded), 4094)
	if err != nil || number == 0 || number > math.MaxUint16 {
		return 0, errors.New("radius: invalid reported VLAN")
	}
	return uint16(number), nil // Bounded to the VLAN range above.
}

func near(a, b time.Time) bool {
	return !a.Before(b.Add(-clockTolerance)) && !a.After(b.Add(clockTolerance))
}

func digest(parts ...string) string {
	hash := sha256.New()
	for _, part := range parts {
		// Length framing avoids concatenation collisions without retaining raw IDs.
		_, _ = fmt.Fprintf(hash, "%d:%s", len(part), part)
	}
	return hex.EncodeToString(hash.Sum(nil))
}
