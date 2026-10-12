//go:build integration && linux

package kea

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"
)

// This fixture starts a disposable daemon with no DHCP interfaces and a
// non-persistent, synthetic lease database. It never uses an installed socket.
func TestKeaDaemonLeaseQueryAndReassignment(t *testing.T) {
	t.Parallel()
	binary, err := exec.LookPath("kea-dhcp4")
	if err != nil {
		t.Skip("native Kea qualification runs in the isolated Kea test image")
	}
	const hook = "/usr/lib/x86_64-linux-gnu/kea/hooks/libdhcp_lease_cmds.so"
	if _, err := os.Stat(hook); err != nil {
		t.Fatal("Kea lease query hook missing")
	}
	directory := t.TempDir()
	// #nosec G302 -- Kea 2.6.3 requires exactly 0750 on its local control directory.
	if err := os.Chmod(directory, 0o750); err != nil {
		t.Fatal(err)
	}
	socket := filepath.Join(directory, "control.sock")
	config, err := json.Marshal(map[string]any{"Dhcp4": map[string]any{
		"interfaces-config": map[string]any{"interfaces": []string{}},
		"lease-database":    map[string]any{"type": "memfile", "persist": false},
		"valid-lifetime":    3600,
		"control-socket":    map[string]any{"socket-type": "unix", "socket-name": socket},
		"hooks-libraries":   []map[string]any{{"library": hook}},
		"subnet4": []map[string]any{{
			"id": 22, "subnet": "192.0.2.0/24",
			"pools": []map[string]string{{"pool": "192.0.2.64-192.0.2.127"}},
		}},
	}})
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(directory, "kea.json")
	if err := os.WriteFile(path, config, 0o600); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()
	// #nosec G204 -- Only the installed test-image Kea binary and our synthetic config.
	command := exec.CommandContext(ctx, binary, "-c", path)
	command.Env = append(
		os.Environ(),
		"KEA_PIDFILE_DIR="+directory,
		"KEA_LOCKFILE_DIR="+directory,
		"KEA_CONTROL_SOCKET_DIR="+directory,
	)
	// Fixture output contains only synthetic leases and local startup errors.
	command.Stdout = os.Stdout
	command.Stderr = os.Stderr
	if err := command.Start(); err != nil {
		cancel()
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- command.Wait() }()
	t.Cleanup(func() {
		cancel()
		select {
		case err := <-done:
			var exit *exec.ExitError
			if err != nil && !errors.As(err, &exit) {
				t.Error(err)
			}
		case <-time.After(2 * time.Second):
			t.Error("native Kea did not stop")
		}
	})
	ticker := time.NewTicker(10 * time.Millisecond)
	defer ticker.Stop()
	for {
		if info, err := os.Lstat(socket); err == nil && info.Mode()&os.ModeSocket != 0 {
			break
		}
		select {
		case err := <-done:
			done <- err // Cleanup still owns joining the already stopped process.
			t.Fatalf("native Kea stopped before creating its socket: %v", err)
		case <-ctx.Done():
			t.Fatal("native Kea control socket did not start")
		case <-ticker.C:
		}
	}
	if err := os.Chmod(socket, 0o600); err != nil {
		t.Fatal(err)
	}
	uid := os.Geteuid()
	if uid < 0 || uid > 0xffffffff {
		t.Fatal("invalid test uid")
		return
	}
	options := fixtureOptions()
	options.Socket = socket
	options.ServerUID = uint32(uid)
	fixtureCommand(t, socket, "lease4-add", map[string]any{
		"ip-address": "192.0.2.80", "hw-address": "02:aa:bb:cc:dd:ee",
		"subnet-id": 22, "valid-lft": 3600, "cltt": time.Now().Unix() - 600,
	})
	first, err := ReadIPv4(ctx, options, fixtureMAC)
	if err != nil || len(first.Leases) != 1 {
		t.Fatalf("real Kea lease response: %v", err)
	}
	again, err := ReadIPv4(ctx, options, fixtureMAC)
	if err != nil || len(again.Leases) != 1 || again.Leases[0] != first.Leases[0] {
		t.Fatalf("real Kea reread changed original expiry: %v", err)
	}
	fixtureCommand(t, socket, "lease4-del", map[string]any{"ip-address": "192.0.2.80"})
	fixtureCommand(t, socket, "lease4-add", map[string]any{
		"ip-address": "192.0.2.80", "hw-address": "02:aa:bb:cc:dd:ff", "subnet-id": 22,
	})
	oldOwner, err := ReadIPv4(ctx, options, fixtureMAC)
	if err != nil || len(oldOwner.Leases) != 0 {
		t.Fatalf("old owner inherited a reassigned address: %v", err)
	}
	newOwner, err := ReadIPv4(ctx, options, "02AABBCCDDFF")
	if err != nil || len(newOwner.Leases) != 1 || newOwner.Leases[0].MAC != "02AABBCCDDFF" {
		t.Fatalf("new owner not independently queried: %v", err)
	}
}

func fixtureCommand(t *testing.T, socket, command string, arguments map[string]any) {
	t.Helper()
	if command != "lease4-add" && command != "lease4-del" {
		t.Fatal("unexpected fixture mutation")
	}
	dialer := net.Dialer{Timeout: time.Second}
	connection, err := dialer.DialContext(t.Context(), "unix", socket)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := closeConnection(connection); err != nil {
			t.Error(err)
		}
	}()
	if err := connection.SetDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	if err := json.NewEncoder(connection).Encode(map[string]any{"command": command, "arguments": arguments}); err != nil {
		t.Fatal(err)
	}
	var response struct {
		Result int `json:"result"`
	}
	if err := json.NewDecoder(connection).Decode(&response); err != nil || response.Result != 0 {
		t.Fatalf("synthetic fixture setup failed: %v", err)
	}
}
