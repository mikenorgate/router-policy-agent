package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"math"
	"path/filepath"
	"time"

	"github.com/mikenorgate/router-policy-agent/internal/ipc"
)

// RunStatus queries only the separately authorized local status socket. It
// never submits directory data, creates sockets, asks for sudo or changes any
// router state. JSON goes to stdout; fixed diagnostics go to stderr. Exit codes
// are 0 for a valid report (including unhealthy/unverified state), 1 for failure
// and 2 for invalid arguments. It is not a firewall health acceptance gate.
func RunStatus(ctx context.Context, args []string, streams CheckIO) int {
	return runStatus(
		ctx,
		args,
		streams,
		ipc.ReadStatus,
	)
}

type readStatusFunc func(context.Context, ipc.ClientOptions) (ipc.Report, error)

func runStatus(
	ctx context.Context,
	args []string,
	streams CheckIO,
	read readStatusFunc,
) int {
	hasStreams := streams.Out != nil && streams.Err != nil
	hasDependencies := ctx != nil && read != nil && hasStreams
	if !hasDependencies {
		return 2
	}
	var path string
	var uid uint
	var timeout time.Duration
	var version bool
	var messages bytes.Buffer
	flags := flag.NewFlagSet("router-policy-status", flag.ContinueOnError)
	flags.SetOutput(&messages)
	flags.StringVar(
		&path,
		"socket",
		"",
		"clean absolute status-only Unix socket path (required)",
	)
	flags.UintVar(
		&uid,
		"server-uid",
		0,
		"expected helper UID; verified through SO_PEERCRED",
	)
	flags.DurationVar(
		&timeout,
		"timeout",
		2*time.Second,
		"query timeout, greater than zero and at most 10s",
	)
	flags.BoolVar(
		&version,
		"version",
		false,
		"print build version",
	)
	flags.Usage = func() {
		fmt.Fprintln(&messages, "Read bounded helper status only; never changes router state.")
		fmt.Fprintln(&messages, "Usage: router-policy-status -socket PATH [-server-uid UID] [-timeout DURATION]")
		flags.PrintDefaults()
	}
	if err := flags.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			if _, err := io.Copy(streams.Out, &messages); err != nil {
				return 1
			}
			return 0
		}
		return statusDiagnostic(streams.Err, "invalid flags; use -help", 2)
	}
	if flags.NArg() != 0 {
		return statusDiagnostic(streams.Err, "unexpected positional arguments", 2)
	}
	if version {
		if _, err := fmt.Fprintln(streams.Out, Version); err != nil {
			return 1
		}
		return 0
	}
	validPath := filepath.IsAbs(path) && filepath.Clean(path) == path
	validBounds := uint64(uid) <= math.MaxUint32 && timeout > 0 && timeout <= 10*time.Second
	if !validPath || !validBounds {
		return statusDiagnostic(streams.Err, "valid -socket, -server-uid and -timeout required", 2)
	}
	if err := ctx.Err(); err != nil {
		return statusDiagnostic(streams.Err, "cancelled", 1)
	}
	report, err := read(ctx, ipc.ClientOptions{Socket: path, ServerUID: uint32(uid), Timeout: timeout})
	isSuccessful := err == nil && ctx.Err() == nil
	if !isSuccessful || ipc.ValidateReport(report) != nil {
		// Errors may contain private local paths or upstream diagnostic text.
		return statusDiagnostic(streams.Err, "status unavailable", 1)
	}
	encoder := json.NewEncoder(streams.Out)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(report); err != nil {
		return statusDiagnostic(streams.Err, "output failed", 1)
	}
	return 0
}

func statusDiagnostic(writer io.Writer, message string, code int) int {
	if _, err := fmt.Fprintf(writer, "router-policy-status: %s\n", message); err != nil {
		return 1
	}
	return code
}
