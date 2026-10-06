// Package firewall implements restricted nftables operations. A command runner
// alone is not a guarded forwarding backend or a completed enforcement gate.
package firewall

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
	"time"

	"github.com/mikenorgate/router-policy-agent/internal/hostfs"
)

const (
	ownedTable       = "router_policy_agent"
	maximumBatch     = 16 << 20
	maximumOutput    = 16 << 20
	commandTimeout   = 2 * time.Second
	commandWaitDelay = 250 * time.Millisecond
	commandBudget    = commandTimeout + commandWaitDelay
)

type operation uint8

const (
	inspectOwned operation = iota + 1
	applyOwned
)

// process has no public arbitrary-command method. Its descriptor is acquired
// from trusted root-owned configuration, not a directory attribute or request.
// The caller closes it after all transactions. Calls and closure are serialized.
type process struct {
	executable *os.File
	gate       chan struct{}
}

type commandInput struct {
	op       operation
	payload  []byte
	prepared *preparedBatch
}

func openProcess(ctx context.Context, path string) (*process, error) {
	if ctx == nil || !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return nil, errors.New("firewall: clean absolute executable path required")
	}
	root, err := hostfs.OpenDirectory(ctx, hostfs.DirectoryOptions{Path: filepath.Dir(path), OwnerUID: 0})
	if err != nil {
		return nil, err
	}
	file, openErr := hostfs.OpenExecutable(
		ctx,
		root,
		filepath.Base(path),
		0,
	)
	closeErr := root.Close()
	if err := errors.Join(openErr, closeErr); err != nil {
		if file != nil {
			err = errors.Join(err, file.Close())
		}
		return nil, err
	}
	return &process{executable: file, gate: make(chan struct{}, 1)}, nil
}

func (process *process) execute(ctx context.Context, op operation, payload []byte) ([]byte, error) {
	if err := process.acquire(ctx); err != nil {
		return nil, err
	}
	defer process.release()
	return process.run(ctx, commandInput{op: op, payload: payload})
}

// applyPrepared checks the preparation window after acquiring the command gate.
// Queueing, slow rendering or a backward clock cannot restart an absolute lease.
func (process *process) applyPrepared(ctx context.Context, batch *preparedBatch) error {
	if err := process.acquire(ctx); err != nil {
		return err
	}
	defer process.release()
	if batch == nil || batch.preparedAt.IsZero() ||
		batch.startBefore != batch.preparedAt.Add(preparationBudget) {
		return errors.New("firewall: invalid prepared transaction")
	}
	_, err := process.run(ctx, commandInput{op: applyOwned, payload: batch.data, prepared: batch})
	return err
}

func (process *process) run(ctx context.Context, input commandInput) ([]byte, error) {
	arguments := []string{"--json", "list", "table", "inet", ownedTable}
	switch input.op {
	case inspectOwned:
		if len(input.payload) != 0 {
			return nil, errors.New("firewall: inspection cannot accept a program")
		}
	case applyOwned:
		if err := validateBatch(input.payload); err != nil {
			return nil, err
		}
		arguments = []string{"--json", "--file", "-"}
	default:
		return nil, errors.New("firewall: unknown operation")
	}
	ctx, cancel := context.WithTimeout(ctx, commandTimeout)
	defer cancel()
	// Check after validation and queueing, immediately before starting the child.
	if input.prepared != nil {
		now := time.Now()
		if now.Before(input.prepared.preparedAt) || !now.Before(input.prepared.startBefore) {
			return nil, errors.New("firewall: prepared transaction expired or clock changed")
		}
	}
	// FD 3 is the already checked executable passed through ExtraFiles. A
	// replaced pathname cannot choose a different program. The child receives
	// neither inherited loader variables nor credentials from the environment.
	command := exec.CommandContext(ctx, "/proc/self/fd/3", arguments...)
	command.Args[0] = "nft"
	command.ExtraFiles = []*os.File{process.executable}
	command.Env = []string{"LC_ALL=C", "PATH=/usr/sbin:/usr/bin"}
	command.SysProcAttr = &syscall.SysProcAttr{Pdeathsig: syscall.SIGKILL}
	command.WaitDelay = commandWaitDelay
	command.Stdin = bytes.NewReader(input.payload)
	stdout, stderr := boundedOutput{maximum: maximumOutput}, boundedOutput{maximum: 64 << 10}
	command.Stdout, command.Stderr = &stdout, &stderr
	if err := command.Run(); err != nil {
		// libnftables diagnostics can contain private endpoints or the rejected
		// program. Keep them out of errors, IPC receipts and status responses.
		return nil, errors.Join(errors.New("firewall: nftables operation failed"), ctx.Err())
	}
	if stdout.exceeded || stderr.exceeded {
		return nil, errors.New("firewall: command output quota exceeded")
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return bytes.Clone(stdout.buffer.Bytes()), nil
}

func (process *process) close() error {
	if process == nil || process.gate == nil {
		return errors.New("firewall: invalid command process")
	}
	process.gate <- struct{}{}
	defer process.release()
	if process.executable == nil {
		return os.ErrClosed
	}
	err := process.executable.Close()
	process.executable = nil
	return err
}

func (process *process) acquire(ctx context.Context) error {
	if process == nil || process.gate == nil || ctx == nil {
		return errors.New("firewall: invalid command process or context")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	select {
	case process.gate <- struct{}{}:
		if process.executable == nil {
			process.release()
			return os.ErrClosed
		}
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (process *process) release() {
	<-process.gate
}

// boundedOutput drains child output while retaining only a bounded prefix.
// Continuing to drain avoids deadlocking a child on a full pipe; exceeding the
// quota is still a failed operation and cannot produce an apply receipt.
type boundedOutput struct {
	buffer   bytes.Buffer
	maximum  int
	exceeded bool
}

func (output *boundedOutput) Write(data []byte) (int, error) {
	if output.maximum <= 0 {
		return 0, errors.New("firewall: invalid output quota")
	}
	count := min(len(data), output.maximum-output.buffer.Len())
	if count < len(data) {
		output.exceeded = true
	}
	if n, err := output.buffer.Write(data[:count]); err != nil || n != count {
		return 0, fmt.Errorf("firewall: retain output: %w", errors.Join(err, io.ErrShortWrite))
	}
	return len(data), nil
}
