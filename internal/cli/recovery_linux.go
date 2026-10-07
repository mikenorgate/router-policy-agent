package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"path/filepath"
	"strings"
	"time"
	"unicode"

	"github.com/mikenorgate/router-policy-agent/internal/firewall"
)

// RunRecover performs the fixed, root-only denial operation using checked
// helper configuration. It never invokes sudo or accepts a firewall program.
// Exit codes are 0 for verified owned sealing, 1 for unsuccessful/unverified
// recovery and 2 for invalid arguments. Success is not permission to restart
// enforcement or a verdict on the external protected floor.
func RunRecover(ctx context.Context, args []string, streams CheckIO) int {
	return runRecover(
		ctx,
		args,
		streams,
		firewall.Recover,
	)
}

type recoverFunc func(context.Context, string) error

func runRecover(
	ctx context.Context,
	args []string,
	streams CheckIO,
	recoverOwned recoverFunc,
) int {
	hasStreams := streams.Out != nil && streams.Err != nil
	hasDependencies := ctx != nil && recoverOwned != nil && hasStreams
	if !hasDependencies {
		return 2
	}
	var directory string
	var timeout time.Duration
	var version bool
	var messages bytes.Buffer
	flags := flag.NewFlagSet("router-policy-recover", flag.ContinueOnError)
	flags.SetOutput(&messages)
	flags.StringVar(
		&directory,
		"config-directory",
		"",
		"clean absolute private directory containing checked helper.json (required)",
	)
	flags.DurationVar(
		&timeout,
		"timeout",
		5*time.Second,
		"operation timeout, greater than zero and at most 10s; failure cleanup is separately bounded",
	)
	flags.BoolVar(
		&version,
		"version",
		false,
		"print build version",
	)
	flags.Usage = func() {
		fmt.Fprintln(&messages, "Revoke agent-owned application grants only; stop the helper separately first.")
		fmt.Fprintln(&messages, "Usage: router-policy-recover -config-directory PATH [-timeout DURATION]")
		flags.PrintDefaults()
	}
	if err := flags.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			if _, err := io.Copy(streams.Out, &messages); err != nil {
				return 1
			}
			return 0
		}
		return recoveryDiagnostic(streams.Err, "invalid flags; use -help", 2)
	}
	if flags.NArg() != 0 {
		return recoveryDiagnostic(streams.Err, "unexpected positional arguments", 2)
	}
	if version {
		if _, err := fmt.Fprintln(streams.Out, Version); err != nil {
			return 1
		}
		return 0
	}
	validPath := directory != "/" && filepath.IsAbs(directory) && filepath.Clean(directory) == directory
	validText := len(directory) <= 4096 && strings.IndexFunc(directory, unicode.IsControl) < 0
	validTimeout := timeout > 0 && timeout <= 10*time.Second
	if !validPath || !validText || !validTimeout {
		return recoveryDiagnostic(streams.Err, "valid -config-directory and -timeout required", 2)
	}
	if err := ctx.Err(); err != nil {
		return recoveryDiagnostic(streams.Err, "cancelled; recovery not verified", 1)
	}
	bounded, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	if err := recoverOwned(bounded, directory); err != nil || bounded.Err() != nil {
		// Never disclose local paths, state contents or upstream nft diagnostics.
		return recoveryDiagnostic(streams.Err, "recovery not verified; keep the helper stopped", 1)
	}
	report := struct {
		SchemaVersion int    `json:"schema_version"`
		Scope         string `json:"scope"`
		PermitState   string `json:"permit_state"`
		HistoryState  string `json:"history_state"`
		FloorState    string `json:"floor_state"`
	}{
		SchemaVersion: 1, Scope: "owned_application_grants", PermitState: "sealed",
		HistoryState: "retained", FloorState: "unverified",
	}
	if err := json.NewEncoder(streams.Out).Encode(report); err != nil {
		return recoveryDiagnostic(streams.Err, "output failed; do not infer unsealing", 1)
	}
	return 0
}

func recoveryDiagnostic(writer io.Writer, message string, code int) int {
	if _, err := fmt.Fprintf(writer, "router-policy-recover: %s\n", message); err != nil {
		return 1
	}
	return code
}
