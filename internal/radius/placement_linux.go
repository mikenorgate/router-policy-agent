package radius

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/netip"
	"os"
	"os/exec"
	"runtime"
	"slices"
	"strconv"
	"syscall"
	"time"

	"github.com/mikenorgate/router-policy-agent/internal/binding"
	"github.com/mikenorgate/router-policy-agent/internal/hostfs"
	"github.com/mikenorgate/router-policy-agent/internal/kea"
	"github.com/mikenorgate/router-policy-agent/internal/policy"
	"github.com/mikenorgate/router-policy-agent/internal/strictjson"
)

const maximumPlacement = 4 << 20

const (
	placementReachable = "reachable_neighbor"
	placementGuarded   = "dhcp_packet_guarded"
)

// PlacementOptions pins the actual host VLAN and its parent. It is privileged
// local configuration, never a device/directory claim. Timeout covers all reads.
type PlacementOptions struct {
	Interface string
	Parent    string
	VLAN      uint16
	Timeout   time.Duration

	// BindingMode defaults to reachable_neighbor. dhcp_packet_guarded permits
	// absent or matching idle ARP evidence for shadow proposals only.
	BindingMode string
}

type ipv4Neighbor struct {
	ip          netip.Addr
	mac         string
	confirmedAt time.Time
	conflict    bool
}

type placementObservation struct {
	observedAt time.Time
	identity   string
	neighbors  []ipv4Neighbor
}

type placementLink struct {
	index  int
	parent int
	mac    string
}

func validPlacementOptions(options PlacementOptions) bool {
	validNames := placementInterface(options.Interface) && placementInterface(options.Parent) && options.Interface != options.Parent
	validScope := options.VLAN > 0 && options.VLAN <= 4094
	validTimeout := options.Timeout > 0 && options.Timeout <= 5*time.Second
	return validNames && validScope && validTimeout && validPlacementMode(options.BindingMode)
}

func validPlacementMode(mode string) bool {
	return mode == "" || mode == placementReachable || mode == placementGuarded
}

func placementInterface(name string) bool {
	if name == "" || len(name) > 15 || name == "lo" {
		return false
	}
	for _, ch := range name {
		isLetter := ch >= 'a' && ch <= 'z' || ch >= 'A' && ch <= 'Z'
		isOther := ch >= '0' && ch <= '9' || ch == '-' || ch == '_' || ch == '.'
		if !isLetter && !isOther {
			return false
		}
	}
	return name[0] != '-' && name != "." && name != ".."
}

// capturePlacement reads only pinned iproute2 show operations in the caller's
// network namespace. No probes, neighbor writes, arbitrary argv or cache files
// are used. A deployment must explicitly qualify its host namespace boundary.
func capturePlacement(ctx context.Context, options PlacementOptions) (observed placementObservation, result error) {
	if ctx == nil || os.Geteuid() != 0 || !validPlacementOptions(options) {
		return placementObservation{}, errors.New("radius: invalid privileged placement options")
	}
	ctx, cancel := context.WithTimeout(ctx, options.Timeout)
	defer cancel()
	started := time.Now()
	boot, err := currentBootID()
	if err != nil {
		return placementObservation{}, err
	}
	root, err := hostfs.OpenDirectory(ctx, hostfs.DirectoryOptions{Path: "/usr/bin", OwnerUID: 0})
	if err != nil {
		return placementObservation{}, errors.New("radius: placement executable directory unavailable")
	}
	executable, openErr := hostfs.OpenExecutable(ctx, root, "ip", 0)
	if err := errors.Join(openErr, root.Close()); err != nil {
		if executable != nil {
			return placementObservation{}, errors.Join(errors.New("radius: placement executable unavailable"), executable.Close())
		}
		return placementObservation{}, errors.New("radius: placement executable unavailable")
	}
	defer func() {
		if err := executable.Close(); err != nil {
			result = errors.Join(result, errors.New("radius: placement executable close failed"))
		}
		if result != nil {
			observed = placementObservation{}
		}
	}()
	before, err := runPlacementIP(ctx, executable, false)
	if err != nil {
		return placementObservation{}, err
	}
	first, err := decodePlacementLinks(before, options)
	if err != nil {
		return placementObservation{}, err
	}
	neighborStarted := time.Now()
	data, err := runPlacementIP(ctx, executable, true)
	if err != nil {
		return placementObservation{}, err
	}
	neighbors, err := decodePlacementNeighbors(data, options.Interface, neighborStarted.UTC(), options.BindingMode)
	if err != nil {
		return placementObservation{}, err
	}
	after, err := runPlacementIP(ctx, executable, false)
	if err != nil {
		return placementObservation{}, err
	}
	last, err := decodePlacementLinks(after, options)
	if err != nil || last != first {
		return placementObservation{}, errors.New("radius: host vlan changed during observation")
	}
	now := time.Now()
	clockConflict := now.Before(started) || !near(started.UTC().Add(now.Sub(started)), now.UTC())
	if afterBoot, err := currentBootID(); err != nil || afterBoot != boot || clockConflict || ctx.Err() != nil {
		return placementObservation{}, errors.Join(errors.New("radius: placement boot or clock conflict"), ctx.Err())
	}
	return placementObservation{
		observedAt: started.UTC(), neighbors: neighbors,
		identity: digest(boot, options.Interface, options.Parent, strconv.Itoa(first.index), strconv.Itoa(first.parent), first.mac),
	}, nil
}

func runPlacementIP(ctx context.Context, executable *os.File, neighbors bool) ([]byte, error) {
	if ctx == nil || executable == nil {
		return nil, errors.New("radius: invalid placement invocation")
	}
	arguments := []string{"ip", "-j", "-d", "link", "show"}
	if neighbors {
		arguments = []string{"ip", "-j", "-s", "-4", "neigh", "show"}
	}
	command := exec.CommandContext(ctx, "/proc/self/fd/3")
	command.Args, command.ExtraFiles = arguments, []*os.File{executable}
	command.Env = []string{"LC_ALL=C", "TZ=UTC", "PATH=/usr/bin"}
	command.SysProcAttr = &syscall.SysProcAttr{Pdeathsig: syscall.SIGKILL}
	command.WaitDelay = 250 * time.Millisecond
	stdout, stderr := journalOutput{maximum: maximumPlacement}, journalOutput{maximum: 8 << 10}
	command.Stdout, command.Stderr = &stdout, &stderr
	// Keep the creating thread alive through the bounded child and copy waits.
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	if err := command.Run(); err != nil {
		return nil, errors.Join(errors.New("radius: host placement read failed"), ctx.Err())
	}
	if stdout.exceeded || stderr.exceeded || stderr.buffer.Len() != 0 || ctx.Err() != nil {
		return nil, errors.Join(errors.New("radius: host placement read incomplete"), ctx.Err())
	}
	return slices.Clone(stdout.buffer.Bytes()), nil
}

func placementRows(data []byte, maximum int) ([]map[string]json.RawMessage, error) {
	rows := []map[string]json.RawMessage{}
	if err := strictjson.Decode(data, &rows, maximumPlacement); err != nil || rows == nil || len(rows) > maximum {
		return nil, errors.New("radius: invalid or oversized placement response")
	}
	for _, row := range rows {
		if row == nil {
			return nil, errors.New("radius: null placement row")
		}
	}
	return rows, nil
}

func placementField(row map[string]json.RawMessage, key string, target any) bool {
	data, exists := row[key]
	return exists && !bytes.Equal(bytes.TrimSpace(data), []byte("null")) && strictjson.Decode(data, target, maximumPlacement) == nil
}

func decodePlacementLinks(data []byte, options PlacementOptions) (placementLink, error) {
	rows, err := placementRows(data, 256)
	if err != nil {
		return placementLink{}, err
	}
	links := make(map[string]map[string]json.RawMessage)
	indices := make(map[int]bool)
	for _, row := range rows {
		var name string
		var index int
		if !placementField(row, "ifname", &name) || !placementField(row, "ifindex", &index) || index <= 0 ||
			links[name] != nil || indices[index] {
			return placementLink{}, errors.New("radius: ambiguous host link identity")
		}
		links[name], indices[index] = row, true
	}
	child, parent := links[options.Interface], links[options.Parent]
	for _, row := range []map[string]json.RawMessage{child, parent} {
		flags := []string{}
		var kind string
		if !placementField(row, "flags", &flags) || !slices.Contains(flags, "UP") || !slices.Contains(flags, "LOWER_UP") ||
			!placementField(row, "link_type", &kind) || kind != "ether" || row["master"] != nil || row["link_netnsid"] != nil {
			return placementLink{}, errors.New("radius: unavailable or unsupported host vlan path")
		}
	}
	var info map[string]json.RawMessage
	var attributes map[string]json.RawMessage
	var parentName, kind, protocol, mac, state string
	var vlan uint16
	var selected placementLink
	validIdentity := placementField(child, "ifindex", &selected.index) && placementField(parent, "ifindex", &selected.parent) &&
		placementField(child, "link", &parentName) && parentName == options.Parent &&
		placementField(child, "address", &mac) && placementField(child, "operstate", &state) && state == "UP"
	validVLAN := placementField(child, "linkinfo", &info) && placementField(info, "info_kind", &kind) && kind == "vlan" &&
		placementField(info, "info_data", &attributes) && placementField(attributes, "id", &vlan) && vlan == options.VLAN &&
		placementField(attributes, "protocol", &protocol) && protocol == "802.1Q"
	canonical, macErr := policy.CanonicalMAC(mac)
	if !validIdentity || !validVLAN || macErr != nil || canonical != mac {
		return placementLink{}, errors.New("radius: host vlan does not match pinned scope")
	}
	selected.mac = mac
	return selected, nil
}

func decodePlacementNeighbors(data []byte, iface string, sampled time.Time, mode string) ([]ipv4Neighbor, error) {
	if !validPlacementMode(mode) {
		return nil, errors.New("radius: invalid placement mode")
	}
	rows, err := placementRows(data, 4096)
	if err != nil {
		return nil, err
	}
	neighbors := []ipv4Neighbor{}
	seen := make(map[string]bool)
	for _, row := range rows {
		var address, dev string
		if !placementField(row, "dst", &address) || !placementField(row, "dev", &dev) {
			return nil, errors.New("radius: missing neighbor identity")
		}
		ip, err := netip.ParseAddr(address)
		key := dev + "/" + address
		if err != nil || !ip.Is4() || ip.String() != address || dev == "" || seen[key] {
			return nil, errors.New("radius: invalid or conflicting neighbor identity")
		}
		seen[key] = true
		if mode == placementGuarded {
			neighbors = append(neighbors, guardedNeighbor(row, ip, dev == iface))
			continue
		}
		if dev != iface {
			continue
		}
		state := []string{}
		var mac string
		var age uint32
		if !placementField(row, "state", &state) || !slices.Equal(state, []string{"REACHABLE"}) ||
			!placementField(row, "lladdr", &mac) || !placementField(row, "confirmed", &age) {
			continue // Unresolved, idle/stale and permanent entries provide no current placement.
		}
		canonical, err := policy.CanonicalMAC(mac)
		if unsupportedNeighbor(row) || err != nil || canonical != mac || !ip.IsGlobalUnicast() || age >= uint32(Freshness/time.Second) {
			continue
		}
		// iproute2 truncates kernel confirmation age to seconds. Subtract one
		// additional second from query START, never use cache reread as a heartbeat.
		confirmed := sampled.Add(-(time.Duration(age) + 1) * time.Second)
		neighbors = append(neighbors, ipv4Neighbor{ip: ip, mac: mac, confirmedAt: confirmed})
	}
	return neighbors, nil
}

func unsupportedNeighbor(row map[string]json.RawMessage) bool {
	for _, field := range []string{"proxy", "managed", "extern_learn", "offload", "extern_valid", "router", "deleted", "miss"} {
		if row[field] != nil {
			return true
		}
	}
	return false
}

// guardedNeighbor preserves contradictions rather than discarding them as an
// absent cache entry. ARP is a conflict check here, not an ownership heartbeat.
func guardedNeighbor(row map[string]json.RawMessage, ip netip.Addr, selectedInterface bool) ipv4Neighbor {
	neighbor := ipv4Neighbor{ip: ip, conflict: true}
	state := []string{}
	var mac string
	var age uint32
	validState := placementField(row, "state", &state) && len(state) == 1 &&
		slices.Contains([]string{"REACHABLE", "STALE", "DELAY", "PROBE"}, state[0])
	validAge := row["confirmed"] == nil || placementField(row, "confirmed", &age)
	validMAC := placementField(row, "lladdr", &mac)
	canonical, err := policy.CanonicalMAC(mac)
	if !selectedInterface || !ip.IsGlobalUnicast() || unsupportedNeighbor(row) || !validState || !validAge ||
		!validMAC || err != nil || canonical != mac {
		return neighbor
	}
	neighbor.mac, neighbor.conflict = mac, false
	return neighbor
}

func bindPlacement(
	candidate IPv4Candidate,
	observed placementObservation,
	scope LeaseScope,
	options PlacementOptions,
	now time.Time,
) (binding.Record, error) {
	lease := kea.Observation{ObservedAt: candidate.LeaseObservedAt, Leases: []kea.Lease{{
		IP: candidate.IP, MAC: candidate.Session.MAC, SubnetID: scope.SubnetID,
		UpdatedAt: candidate.LeaseUpdatedAt, ValidUntil: candidate.LeaseValidUntil,
	}}}
	checked, err := MatchIPv4(candidate.Session, lease, scope, now)
	validObservation := binding.Fresh(observed.observedAt, now, Freshness) && len(observed.identity) == 64 &&
		validPlacementOptions(options) && options.VLAN == scope.VLAN
	if err != nil || checked != candidate || !validObservation {
		return binding.Record{}, errors.New("radius: unqualified placement candidate")
	}
	matches := []ipv4Neighbor{}
	for _, neighbor := range observed.neighbors {
		if neighbor.ip == candidate.IP {
			matches = append(matches, neighbor)
		}
	}
	conflict := len(matches) > 1 || len(matches) == 1 && (matches[0].conflict || matches[0].mac != candidate.Session.MAC)
	if conflict {
		return binding.Record{}, errors.New("radius: conflicting placement")
	}
	until := candidate.ValidUntil
	ownership := digest(candidate.OwnershipID, observed.identity)
	if options.BindingMode == placementGuarded {
		ownership = digest(ownership, placementGuarded)
	} else {
		if len(matches) != 1 || !binding.Fresh(matches[0].confirmedAt, now, Freshness) {
			return binding.Record{}, errors.New("radius: missing or stale placement")
		}
		if matches[0].confirmedAt.Before(candidate.Session.StartedAt) {
			return binding.Record{}, errors.New("radius: placement predates current session")
		}
		if deadline := matches[0].confirmedAt.Add(Freshness); deadline.Before(until) {
			until = deadline
		}
	}
	return binding.Record{
		MAC: candidate.Session.MAC, NAS: candidate.Session.NAS.String(), Interface: options.Interface, VLAN: scope.VLAN,
		AssociatedAt: candidate.Session.ObservedAt, AssociationID: candidate.Session.AssociationID,
		Addresses: []binding.Address{{IP: candidate.IP, Source: "kea_dhcp4", ObservedAt: candidate.LeaseObservedAt,
			OwnershipID: ownership, ValidUntil: until}},
	}, nil
}
