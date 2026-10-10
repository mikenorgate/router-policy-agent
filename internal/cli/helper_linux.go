package cli

import (
	"bytes"
	"context"
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

// RunHelper runs the root-only configured helper using supervisor sockets.
// Initialization is explicit and separate. No flag changes enforcement mode,
// adopts live policy, supplies credentials or resets existing history.
func RunHelper(ctx context.Context, args []string, streams CheckIO) int {
	return runHelper(ctx, args, streams, firewall.RunHelper, firewall.InitializeState)
}

func runHelper(
	ctx context.Context,
	args []string,
	streams CheckIO,
	serve func(context.Context, string, string) error,
	initialize func(context.Context, string) error,
) int {
	if ctx == nil || streams.Out == nil || streams.Err == nil || serve == nil || initialize == nil {
		return 2
	}
	var directory, bindings string
	var version, firstInstall bool
	var messages bytes.Buffer
	flags := flag.NewFlagSet("router-policy-helper", flag.ContinueOnError)
	flags.SetOutput(&messages)
	flags.StringVar(&directory, "config-directory", "", "private root-owned directory containing helper.json (required)")
	flags.StringVar(&bindings, "binding-directory", "", "private root-owned directory containing atomic bindings.json exports")
	flags.BoolVar(&firstInstall, "initialize-state", false, "explicit first install only; refuses existing or corrupt history")
	flags.BoolVar(&version, "version", false, "print build version")
	flags.Usage = func() {
		fmt.Fprintln(&messages, "Run the checked root helper; deployment and source qualification are separate.")
		fmt.Fprintln(&messages, "Usage: router-policy-helper -config-directory PATH -binding-directory PATH")
		fmt.Fprintln(&messages, "First install: router-policy-helper -config-directory PATH -initialize-state")
		flags.PrintDefaults()
	}
	if err := flags.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			if _, err := io.Copy(streams.Out, &messages); err != nil {
				return 1
			}
			return 0
		}
		return helperDiagnostic(streams.Err, "invalid flags; use -help", 2)
	}
	if flags.NArg() != 0 {
		return helperDiagnostic(streams.Err, "unexpected positional arguments", 2)
	}
	if version {
		if _, err := fmt.Fprintln(streams.Out, Version); err != nil {
			return 1
		}
		return 0
	}
	validModeArguments := firstInstall && bindings == "" || !firstInstall && helperDirectory(bindings)
	if !helperDirectory(directory) || !validModeArguments {
		return helperDiagnostic(streams.Err, "valid directories and one operation required", 2)
	}
	if firstInstall {
		bounded, cancel := context.WithTimeout(ctx, 10*time.Second)
		defer cancel()
		if err := initialize(bounded, directory); err != nil || bounded.Err() != nil {
			return helperDiagnostic(streams.Err, "initialization failed; history was not reset", 1)
		}
		return 0
	}
	err := serve(ctx, directory, bindings)
	if err == nil || errors.Is(err, context.Canceled) && errors.Is(ctx.Err(), context.Canceled) {
		return 0
	}
	return helperDiagnostic(streams.Err, "runtime unavailable; enforcement not verified", 1)
}

func helperDirectory(path string) bool {
	validPath := path != "/" && filepath.IsAbs(path) && filepath.Clean(path) == path
	return validPath && len(path) <= 4096 && strings.IndexFunc(path, unicode.IsControl) < 0
}

func helperDiagnostic(writer io.Writer, message string, code int) int {
	if _, err := fmt.Fprintf(writer, "router-policy-helper: %s\n", message); err != nil {
		return 1
	}
	return code
}
