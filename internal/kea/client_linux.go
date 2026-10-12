// Package kea reads current IPv4 lease evidence from a local Kea daemon.
// It does not establish NAS association, VLAN placement or anti-spoofing, and
// cannot produce a qualified binding snapshot on its own.
package kea

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"math"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/mikenorgate/router-policy-agent/internal/hostfs"
	"github.com/mikenorgate/router-policy-agent/internal/strictjson"
)

const (
	maximumResponse = 256 << 10
	maximumLeases   = 16
)

// Options comes from trusted local configuration, never directory attributes.
// The socket's parent belongs to ServerUID; ancestors belong to that UID or
// root and cannot be writable by other identities. The control socket must not
// be exposed to the directory reader: Kea also accepts administrative commands.
type Options struct {
	Socket    string
	ServerUID uint32
	Timeout   time.Duration
	SubnetID  uint32
	Prefix    netip.Prefix
}

// Observation is one current daemon query, not a cache or a binding snapshot.
// ObservedAt is conservatively sampled before the query; repeated queries do
// not change each lease's original renewal time or expiry. Queries for multiple
// devices are not a cross-device transaction.
type Observation struct {
	ObservedAt time.Time
	Leases     []Lease
}

// Lease records active DHCP ownership, without granting firewall authority.
type Lease struct {
	IP         netip.Addr
	MAC        string
	SubnetID   uint32
	UpdatedAt  time.Time
	ValidUntil time.Time
}

// ReadIPv4 sends only lease4-get-by-hw-address to a filesystem Unix socket.
// It authenticates the daemon using SO_PEERCRED before sending the query,
// bounds the complete EOF-terminated response, and returns no partial evidence
// on failure. Missing, expired or reclaimed leases produce an empty observation.
// There is no network endpoint, arbitrary command, CSV fallback or cache.
func ReadIPv4(ctx context.Context, options Options, mac string) (observation Observation, result error) {
	if ctx == nil || !validOptions(options) {
		return Observation{}, errors.New("kea: invalid local query options")
	}
	canonical, hardware, err := canonicalMAC(mac)
	if err != nil {
		return Observation{}, err
	}
	ctx, cancel := context.WithTimeout(ctx, options.Timeout)
	defer cancel()
	observedAt := time.Now().UTC()
	if err := checkSocket(ctx, options); err != nil {
		return Observation{}, err
	}
	dialer := net.Dialer{}
	raw, err := dialer.DialContext(ctx, "unix", options.Socket)
	if err != nil {
		return Observation{}, errors.Join(errors.New("kea: daemon unavailable"), ctx.Err())
	}
	defer func() {
		result = errors.Join(result, closeConnection(raw))
		if result != nil {
			observation = Observation{}
		}
	}()
	connection, ok := raw.(*net.UnixConn)
	if !ok {
		return Observation{}, errors.New("kea: unix connection required")
	}
	if err := checkPeer(connection, options.ServerUID); err != nil {
		return Observation{}, err
	}
	deadline, ok := ctx.Deadline()
	if !ok {
		return Observation{}, errors.New("kea: missing query deadline")
	}
	if err := connection.SetDeadline(deadline); err != nil {
		return Observation{}, errors.New("kea: cannot set query deadline")
	}
	// Join the cancellation callback before releasing the descriptor. Merely
	// stopping an AfterFunc does not join a callback already running.
	done := make(chan error, 1)
	stop := context.AfterFunc(ctx, func() { done <- closeConnection(connection) })
	defer func() {
		if !stop() {
			result = errors.Join(result, <-done)
		}
		result = errors.Join(result, ctx.Err())
	}()
	request := `{"command":"lease4-get-by-hw-address","arguments":{"hw-address":"` + hardware + `"}}`
	if _, err := io.Copy(connection, strings.NewReader(request)); err != nil {
		return Observation{}, errors.Join(errors.New("kea: query write failed"), ctx.Err())
	}
	// Kea terminates the connection after sending the entire response. Waiting
	// for EOF also rejects a valid prefix followed by another JSON value.
	data, err := io.ReadAll(io.LimitReader(connection, maximumResponse+1))
	if err != nil {
		return Observation{}, errors.Join(errors.New("kea: query read failed"), ctx.Err())
	}
	leases, err := decodeLeases(data, options, canonical, time.Now().UTC())
	if err != nil {
		return Observation{}, err
	}
	return Observation{ObservedAt: observedAt, Leases: leases}, nil
}

func validOptions(options Options) bool {
	isPath := filepath.IsAbs(options.Socket) && filepath.Clean(options.Socket) == options.Socket
	isSocketName := len(options.Socket) <= 107 && !strings.ContainsRune(options.Socket, '\x00')
	isTimeout := options.Timeout > 0 && options.Timeout <= 10*time.Second
	isPrefix := options.Prefix.IsValid() && options.Prefix.Addr().Is4() && options.Prefix == options.Prefix.Masked()
	return isPath && isSocketName && isTimeout && isPrefix && options.SubnetID != 0
}

func canonicalMAC(mac string) (string, string, error) {
	// Only these two forms are accepted; punctuation cannot reach JSON syntax.
	if len(mac) == 17 {
		parts := strings.Split(mac, ":")
		if len(parts) != 6 {
			return "", "", errors.New("kea: invalid mac")
		}
		for _, part := range parts {
			if len(part) != 2 {
				return "", "", errors.New("kea: invalid mac")
			}
		}
		mac = strings.Join(parts, "")
	}
	decoded, err := hex.DecodeString(mac)
	if err != nil || len(decoded) != 6 {
		return "", "", errors.New("kea: invalid mac")
	}
	if decoded[0]&1 != 0 || strings.Trim(mac, "0") == "" {
		return "", "", errors.New("kea: invalid mac")
	}
	return strings.ToUpper(mac), net.HardwareAddr(decoded).String(), nil
}

func checkSocket(ctx context.Context, options Options) error {
	root, err := hostfs.OpenDirectory(ctx, hostfs.DirectoryOptions{
		Path: filepath.Dir(options.Socket), OwnerUID: options.ServerUID,
	})
	if err != nil {
		return errors.New("kea: unsafe socket directory")
	}
	info, statErr := root.Lstat(filepath.Base(options.Socket))
	if err := errors.Join(statErr, root.Close()); err != nil {
		return errors.New("kea: socket unavailable")
	}
	metadata, ok := info.Sys().(*syscall.Stat_t)
	isSocket := info.Mode()&os.ModeSocket != 0
	isMode := info.Mode().Perm()&0o117 == 0
	if !ok || !isSocket || !isMode || metadata.Uid != options.ServerUID || metadata.Nlink != 1 {
		return errors.New("kea: unsafe socket")
	}
	return nil
}

func checkPeer(connection *net.UnixConn, expected uint32) error {
	raw, err := connection.SyscallConn()
	if err != nil {
		return errors.New("kea: peer descriptor unavailable")
	}
	var credentials *syscall.Ucred
	var credentialErr error
	err = raw.Control(func(fd uintptr) {
		if fd > math.MaxInt {
			credentialErr = errors.New("kea: invalid peer descriptor")
			return
		}
		credentials, credentialErr = syscall.GetsockoptUcred(int(fd), syscall.SOL_SOCKET, syscall.SO_PEERCRED)
	})
	if err != nil || credentialErr != nil || credentials == nil || credentials.Uid != expected {
		return errors.New("kea: unexpected daemon identity")
	}
	return nil
}

func closeConnection(connection io.Closer) error {
	if err := connection.Close(); err != nil && !errors.Is(err, net.ErrClosed) {
		return errors.New("kea: connection cleanup failed")
	}
	return nil
}

func decodeLeases(data []byte, options Options, mac string, now time.Time) ([]Lease, error) {
	if err := strictjson.Object(data, []string{"result"}, []string{"text", "arguments"}, maximumResponse); err != nil {
		return nil, errors.New("kea: invalid response")
	}
	var response struct {
		Result    int             `json:"result"`
		Text      string          `json:"text"`
		Arguments json.RawMessage `json:"arguments"`
	}
	if err := strictjson.Decode(data, &response, maximumResponse); err != nil {
		return nil, errors.New("kea: invalid response")
	}
	if response.Result != 0 && response.Result != 3 {
		return nil, errors.New("kea: lease query rejected")
	}
	leases := []Lease{}
	if response.Result == 3 && len(response.Arguments) == 0 {
		return leases, nil
	}
	if err := strictjson.Object(response.Arguments, []string{"leases"}, nil, maximumResponse); err != nil {
		return nil, errors.New("kea: invalid lease list")
	}
	var arguments struct {
		Leases []json.RawMessage `json:"leases"`
	}
	if err := strictjson.Decode(response.Arguments, &arguments, maximumResponse); err != nil {
		return nil, errors.New("kea: invalid lease list")
	}
	isEmptyResult := response.Result == 3 && len(arguments.Leases) == 0
	isSuccess := response.Result == 0 && len(arguments.Leases) > 0 && len(arguments.Leases) <= maximumLeases
	if !isEmptyResult && !isSuccess {
		return nil, errors.New("kea: inconsistent or oversized lease list")
	}
	seen := map[netip.Addr]bool{}
	for _, raw := range arguments.Leases {
		lease, active, err := decodeLease(raw, options, mac, now)
		if err != nil {
			return nil, err
		}
		if seen[lease.IP] {
			return nil, errors.New("kea: duplicate lease address")
		}
		seen[lease.IP] = true
		if active {
			leases = append(leases, lease)
		}
	}
	return leases, nil
}

func decodeLease(data []byte, options Options, mac string, now time.Time) (Lease, bool, error) {
	required := []string{"ip-address", "hw-address", "subnet-id", "state", "cltt", "valid-lft"}
	optional := []string{"client-id", "fqdn-fwd", "fqdn-rev", "hostname", "user-context", "pool-id"}
	if err := strictjson.Object(data, required, optional, maximumResponse); err != nil {
		return Lease{}, false, errors.New("kea: invalid lease")
	}
	// Optional daemon metadata is validated as JSON but is not ownership input.
	fields := map[string]json.RawMessage{}
	if err := strictjson.Decode(data, &fields, maximumResponse); err != nil {
		return Lease{}, false, errors.New("kea: invalid lease")
	}
	for _, key := range optional {
		delete(fields, key)
	}
	core, err := json.Marshal(fields)
	if err != nil {
		return Lease{}, false, errors.New("kea: invalid lease")
	}
	var wire struct {
		IP       string `json:"ip-address"`
		MAC      string `json:"hw-address"`
		SubnetID uint32 `json:"subnet-id"`
		State    uint32 `json:"state"`
		CLTT     uint32 `json:"cltt"`
		Lifetime uint32 `json:"valid-lft"`
	}
	if err := strictjson.Decode(core, &wire, maximumResponse); err != nil {
		return Lease{}, false, errors.New("kea: invalid lease")
	}
	owner, _, err := canonicalMAC(wire.MAC)
	address, addressErr := netip.ParseAddr(wire.IP)
	isAddress := address.Is4() && address.IsGlobalUnicast() && !address.IsLoopback() && !address.IsLinkLocalUnicast()
	isPlacement := wire.SubnetID == options.SubnetID && options.Prefix.Contains(address)
	if err != nil || owner != mac || addressErr != nil || !isAddress || !isPlacement {
		return Lease{}, false, errors.New("kea: lease ownership or subnet mismatch")
	}
	updatedAt := time.Unix(int64(wire.CLTT), 0).UTC()
	if wire.CLTT == 0 || updatedAt.After(now) || wire.State > 2 {
		return Lease{}, false, errors.New("kea: invalid lease time or state")
	}
	expiresAt := time.Unix(int64(wire.CLTT)+int64(wire.Lifetime), 0).UTC()
	lease := Lease{IP: address, MAC: owner, SubnetID: wire.SubnetID, UpdatedAt: updatedAt, ValidUntil: expiresAt}
	isActive := wire.State == 0 && wire.Lifetime > 0 && now.Before(expiresAt)
	return lease, isActive, nil
}
