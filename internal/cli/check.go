// Package cli implements bounded command-line entry points with explicit I/O.
package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"syscall"
	"time"

	"github.com/mikenorgate/router-policy-agent/internal/binding"
	"github.com/mikenorgate/router-policy-agent/internal/policy"
	"github.com/mikenorgate/router-policy-agent/internal/strictjson"
)

// Version is set by the release build; development builds report dev.
var Version = "dev"

// CheckIO allows tests to capture output without process-global redirection.
type CheckIO struct {
	Out io.Writer
	Err io.Writer
}

// RunCheck compiles local snapshots without contacting LDAP or changing a
// firewall. It returns Unix exit codes: 0 success, 1 runtime error, 2 usage error.
func RunCheck(ctx context.Context, args []string, streams CheckIO) int {
	if ctx == nil || streams.Out == nil || streams.Err == nil {
		return 2
	}
	var baselinePath, directoryPath, bindingsPath, ledgerPath, at string
	var version bool
	var messages bytes.Buffer
	flags := flag.NewFlagSet("router-policy-check", flag.ContinueOnError)
	flags.SetOutput(&messages)
	flags.StringVar(&baselinePath, "baseline", "", "reviewed baseline JSON (required)")
	flags.StringVar(&directoryPath, "directory", "", "complete directory snapshot JSON (required)")
	flags.StringVar(&bindingsPath, "bindings", "", "qualified binding snapshot JSON (required)")
	flags.StringVar(&ledgerPath, "ledger", "", "previous compiler ledger JSON (optional; offline checks only)")
	flags.StringVar(&at, "at", "", "RFC3339 UTC evaluation time for offline fixtures (default: now)")
	flags.BoolVar(&version, "version", false, "print build version")
	flags.Usage = func() {
		fmt.Fprintln(&messages, "Compile shadow decisions only; never changes router state.")
		fmt.Fprintln(&messages, "Usage: router-policy-check -baseline FILE -directory FILE -bindings FILE [-at TIME]")
		flags.PrintDefaults()
	}
	if err := flags.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			if _, err := io.Copy(streams.Out, &messages); err != nil {
				return 1
			}
			return 0
		}
		return diagnostic(streams.Err, "invalid flags; use -help", 2)
	}
	if flags.NArg() != 0 {
		return diagnostic(streams.Err, "unexpected positional arguments", 2)
	}
	if version {
		if _, err := fmt.Fprintln(streams.Out, Version); err != nil {
			return 1
		}
		return 0
	}
	if baselinePath == "" || directoryPath == "" || bindingsPath == "" {
		return diagnostic(streams.Err, "-baseline, -directory and -bindings are required", 2)
	}
	now := time.Now().UTC()
	if at != "" {
		var err error
		now, err = time.Parse(time.RFC3339Nano, at)
		if err != nil || len(at) == 0 || at[len(at)-1] != 'Z' {
			return diagnostic(streams.Err, "-at must be an RFC3339 UTC timestamp", 2)
		}
	}
	if err := ctx.Err(); err != nil {
		return diagnostic(streams.Err, "cancelled", 1)
	}
	baselineData, err := readBounded(baselinePath, 2*1024*1024)
	if err != nil {
		return checkError(streams.Err, err)
	}
	baseline, err := policy.DecodeBaseline(baselineData)
	if err != nil {
		return checkError(streams.Err, err)
	}
	compiler, err := policy.New(baseline)
	if err != nil {
		return checkError(streams.Err, err)
	}
	var directory policy.DirectorySnapshot
	if err := decodeFile(directoryPath, &directory); err != nil {
		return checkError(streams.Err, err)
	}
	var bindings binding.Snapshot
	if err := decodeFile(bindingsPath, &bindings); err != nil {
		return checkError(streams.Err, err)
	}
	ledger := policy.Ledger{}
	if ledgerPath != "" {
		if err := decodeFile(ledgerPath, &ledger); err != nil {
			return checkError(streams.Err, err)
		}
	}
	candidate, err := compiler.Compile(policy.Input{Directory: directory, Bindings: bindings, Now: now, Ledger: ledger})
	if err != nil {
		return checkError(streams.Err, err)
	}
	if err := ctx.Err(); err != nil {
		return checkError(streams.Err, errors.New("cancelled"))
	}
	encoder := json.NewEncoder(streams.Out)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(candidate); err != nil {
		return checkError(streams.Err, errors.New("output failed"))
	}
	return 0
}

func checkError(writer io.Writer, err error) int {
	return diagnostic(writer, err.Error(), 1)
}

func diagnostic(writer io.Writer, message string, code int) int {
	if _, err := fmt.Fprintf(writer, "router-policy-check: %s\n", message); err != nil {
		return 1
	}
	return code
}

func decodeFile(path string, target any) error {
	data, err := readBounded(path, 16*1024*1024)
	if err != nil {
		return err
	}
	return strictjson.Decode(data, target, 16*1024*1024)
}

func readBounded(path string, limit int64) (data []byte, err error) {
	// Paths come from the operator's offline CLI, never directory attributes.
	// Refuse symlinks and non-regular files without blocking on a named pipe.
	file, err := os.OpenFile(filepath.Clean(path), os.O_RDONLY|syscall.O_NONBLOCK|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return nil, errors.New("input file unavailable")
	}
	defer func() {
		if closeErr := file.Close(); closeErr != nil && err == nil {
			data, err = nil, errors.New("input close failed")
		}
	}()
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Size() > limit {
		return nil, errors.New("input must be a bounded regular file")
	}
	data, err = io.ReadAll(io.LimitReader(file, limit+1))
	if err != nil || int64(len(data)) > limit {
		return nil, errors.New("input read failed or exceeds limit")
	}
	return data, nil
}
