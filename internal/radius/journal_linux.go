package radius

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/netip"
	"os"
	"os/exec"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/mikenorgate/router-policy-agent/internal/hostfs"
	"github.com/mikenorgate/router-policy-agent/internal/strictjson"
)

// JournalOptions pins local RADIUS provenance, not an arbitrary journal source,
// executable, filter or command. The current kernel boot ID is read locally.
type JournalOptions struct {
	ServiceUID  uint32
	NASPrefixes []netip.Prefix
	Timeout     time.Duration
}

type history struct {
	data       []byte
	scope      Scope
	observedAt time.Time
}

// captureHistory always reads the local system journal, oldest first. It has
// no tail, reverse, remote, path, shell, inherited environment or cache fallback.
// Retained journal history is not a durable accounting database: missing Starts
// deny, and retention/rotation must still be qualified for an installed service.
func captureHistory(ctx context.Context, options JournalOptions) (captured history, result error) {
	if ctx == nil || os.Geteuid() != 0 || options.Timeout <= 0 || options.Timeout > 10*time.Second {
		return history{}, errors.New("radius: invalid privileged journal options")
	}
	ctx, cancel := context.WithTimeout(ctx, options.Timeout)
	defer cancel()
	boot, err := currentBootID()
	if err != nil {
		return history{}, err
	}
	scope := Scope{BootID: boot, ServiceUID: options.ServiceUID, NASPrefixes: options.NASPrefixes}
	if !validScope(scope) {
		return history{}, errors.New("radius: invalid local journal scope")
	}
	root, err := hostfs.OpenDirectory(ctx, hostfs.DirectoryOptions{Path: "/usr/bin", OwnerUID: 0})
	if err != nil {
		return history{}, errors.New("radius: journal executable directory unavailable")
	}
	executable, openErr := hostfs.OpenExecutable(ctx, root, "journalctl", 0)
	closeErr := root.Close()
	if err := errors.Join(openErr, closeErr); err != nil {
		var cleanupErr error
		if executable != nil {
			if err := executable.Close(); err != nil {
				cleanupErr = errors.New("radius: journal executable cleanup failed")
			}
		}
		return history{}, errors.Join(errors.New("radius: trusted journal executable unavailable"), cleanupErr)
	}
	defer func() {
		if err := executable.Close(); err != nil {
			result = errors.Join(result, errors.New("radius: journal executable close failed"))
		}
		if result != nil {
			captured = history{}
		}
	}()
	data, err := runJournal(ctx, executable, scope)
	if err != nil {
		return history{}, err
	}
	data, err = canonicalHistory(data)
	if err != nil {
		return history{}, err
	}
	if after, err := currentBootID(); err != nil || after != boot {
		return history{}, errors.New("radius: kernel boot changed during collection")
	}
	observedAt := time.Now().UTC()
	if _, err := Replay(data, scope, observedAt); err != nil {
		return history{}, err
	}
	if err := ctx.Err(); err != nil {
		return history{}, err
	}
	return history{data: data, scope: scope, observedAt: observedAt}, nil
}

// journalctl emits object fields from a hash map; their order is not stable.
// Normalize only the outer object order and whitespace, retaining every field,
// raw value, cursor and entry order for append-only history comparison. Replay
// still validates provenance and payloads; normalization never repairs input.
func canonicalHistory(data []byte) ([]byte, error) {
	if len(data) > maximumHistory || len(data) != 0 && data[len(data)-1] != '\n' {
		return nil, errors.New("radius: incomplete or oversized journal history")
	}
	normalized := make([]byte, 0, len(data))
	count := 0
	for line := range bytes.Lines(data) {
		count++
		if count > maximumEvents {
			return nil, errors.New("radius: journal event limit exceeded")
		}
		entry := make(map[string]json.RawMessage)
		if err := strictjson.Decode(bytes.TrimSuffix(line, []byte{'\n'}), &entry, maximumEntry); err != nil || entry == nil {
			return nil, errors.New("radius: invalid journal object")
		}
		encoded, err := json.Marshal(entry)
		if err != nil || len(encoded) > maximumEntry || len(encoded)+1 > maximumHistory-len(normalized) {
			return nil, errors.New("radius: oversized normalized journal history")
		}
		normalized = append(normalized, encoded...)
		normalized = append(normalized, '\n')
	}
	return normalized, nil
}

func currentBootID() (string, error) {
	file, err := os.Open("/proc/sys/kernel/random/boot_id")
	if err != nil {
		return "", errors.New("radius: kernel boot identity unavailable")
	}
	data, readErr := io.ReadAll(io.LimitReader(file, 65))
	if err := errors.Join(readErr, file.Close()); err != nil || len(data) != 37 || data[36] != '\n' {
		return "", errors.New("radius: invalid kernel boot identity")
	}
	raw := string(data[:36])
	if raw[8] != '-' || raw[13] != '-' || raw[18] != '-' || raw[23] != '-' {
		return "", errors.New("radius: invalid kernel boot identity")
	}
	return strings.ReplaceAll(raw, "-", ""), nil
}

func journalArguments(scope Scope) []string {
	return []string{
		"--system", "--no-pager", "--all", "--output=json", "--boot=" + scope.BootID,
		"--output-fields=MESSAGE,_SYSTEMD_UNIT,SYSLOG_IDENTIFIER,_BOOT_ID,_UID,__REALTIME_TIMESTAMP,__CURSOR",
		"--grep=^" + marker,
		"_SYSTEMD_UNIT=freeradius.service", "SYSLOG_IDENTIFIER=freeradius",
		"_UID=" + strconv.FormatUint(uint64(scope.ServiceUID), 10),
	}
}

func runJournal(ctx context.Context, executable *os.File, scope Scope) ([]byte, error) {
	if ctx == nil || executable == nil || !validScope(scope) {
		return nil, errors.New("radius: invalid journal invocation")
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	command := exec.CommandContext(ctx, "/proc/self/fd/3")
	// This argv builder admits only a validated boot ID and numeric service UID;
	// every operation, source and filter is fixed. There is no shell or caller argv.
	command.Args = append([]string{"journalctl"}, journalArguments(scope)...)
	command.ExtraFiles = []*os.File{executable}
	command.Env = []string{"LC_ALL=C", "TZ=UTC", "PATH=/usr/bin", "SYSTEMD_COLORS=0"}
	command.SysProcAttr = &syscall.SysProcAttr{Pdeathsig: syscall.SIGKILL}
	command.WaitDelay = 250 * time.Millisecond
	stdout, stderr := journalOutput{maximum: maximumHistory}, journalOutput{maximum: 8 << 10}
	command.Stdout, command.Stderr = &stdout, &stderr
	// Pdeathsig follows the creating Linux thread; keep it until the bounded wait
	// and os/exec's output-copy work have both completed.
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	if err := command.Run(); err != nil {
		return nil, errors.Join(errors.New("radius: journal read failed"), ctx.Err())
	}
	// Even exit-zero warnings can describe inaccessible or skipped journal data.
	// Keep diagnostics payload-free and never treat the retained prefix as whole.
	if stdout.exceeded || stderr.buffer.Len() != 0 || stderr.exceeded {
		return nil, errors.New("radius: journal read incomplete or oversized")
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return bytes.Clone(stdout.buffer.Bytes()), nil
}

type journalOutput struct {
	buffer   bytes.Buffer
	maximum  int
	exceeded bool
}

func (output *journalOutput) Write(data []byte) (int, error) {
	if output == nil || output.maximum <= 0 {
		return 0, errors.New("radius: invalid output quota")
	}
	retained := min(len(data), output.maximum-output.buffer.Len())
	if retained < len(data) {
		output.exceeded = true
	}
	if n, err := output.buffer.Write(data[:retained]); err != nil || n != retained {
		return 0, errors.New("radius: output retention failed")
	}
	return len(data), nil
}
