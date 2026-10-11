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

// RunHelper runs the configured root helper, renders guards for offline image
// assembly or restores denial-only history. Initialization is explicit and
// separate. No flag changes enforcement mode, adopts live policy, supplies
// credentials or resets existing history.
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
	return runHelperOperations(ctx, args, streams, helperOperations{
		serve: serve, initialize: initialize, recoverOwned: firewall.Recover,
	})
}

type helperOperations struct {
	serve        func(context.Context, string, string) error
	initialize   func(context.Context, string) error
	recoverOwned func(context.Context, string) error
}

func runHelperOperations(ctx context.Context, args []string, streams CheckIO, operations helperOperations) int {
	validOperations := operations.serve != nil && operations.initialize != nil && operations.recoverOwned != nil
	if ctx == nil || streams.Out == nil || streams.Err == nil || !validOperations {
		return 2
	}
	var directory, bindings, baseline string
	var version, firstInstall, renderGuards, restoreDenied bool
	var messages bytes.Buffer
	flags := flag.NewFlagSet("router-policy-helper", flag.ContinueOnError)
	flags.SetOutput(&messages)
	flags.StringVar(&directory, "config-directory", "", "private root-owned directory containing helper.json (required)")
	flags.StringVar(&bindings, "binding-directory", "", "private root-owned directory containing atomic bindings.json exports")
	flags.BoolVar(&firstInstall, "initialize-state", false, "explicit first install only; refuses existing or corrupt history")
	flags.BoolVar(&restoreDenied, "restore-deny-state", false, "withdraw application grants and restore existing deny history; stop helper separately first")
	flags.BoolVar(&renderGuards, "render-image-guards", false, "offline image assembly: print fixed guards; never installs or activates them")
	flags.StringVar(&baseline, "baseline", "", "reviewed baseline JSON; only with -render-image-guards")
	flags.BoolVar(&version, "version", false, "print build version")
	flags.Usage = func() {
		fmt.Fprintln(&messages, "Run the checked root helper; deployment and source qualification are separate.")
		fmt.Fprintln(&messages, "Usage: router-policy-helper -config-directory PATH -binding-directory PATH")
		fmt.Fprintln(&messages, "First install: router-policy-helper -config-directory PATH -initialize-state")
		fmt.Fprintln(&messages, "Boot recovery: router-policy-helper -config-directory PATH -restore-deny-state")
		fmt.Fprintln(&messages, "Image assembly: router-policy-helper -render-image-guards -baseline FILE")
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
	if renderGuards {
		if baseline == "" || directory != "" || bindings != "" || firstInstall || restoreDenied {
			return helperDiagnostic(streams.Err, "image rendering cannot select runtime operations", 2)
		}
		return renderHelperImageGuards(ctx, baseline, streams)
	}
	if baseline != "" {
		return helperDiagnostic(streams.Err, "-baseline requires -render-image-guards", 2)
	}
	if restoreDenied {
		if firstInstall || bindings != "" || !helperDirectory(directory) {
			return helperDiagnostic(streams.Err, "recovery cannot select another runtime operation", 2)
		}
		return runRecover(ctx, []string{"-config-directory", directory}, streams, operations.recoverOwned)
	}
	validModeArguments := firstInstall && bindings == "" || !firstInstall && helperDirectory(bindings)
	if !helperDirectory(directory) || !validModeArguments {
		return helperDiagnostic(streams.Err, "valid directories and one operation required", 2)
	}
	if firstInstall {
		bounded, cancel := context.WithTimeout(ctx, 10*time.Second)
		defer cancel()
		if err := operations.initialize(bounded, directory); err != nil || bounded.Err() != nil {
			return helperDiagnostic(streams.Err, "initialization failed; history was not reset", 1)
		}
		return 0
	}
	err := operations.serve(ctx, directory, bindings)
	if err == nil || errors.Is(err, context.Canceled) && errors.Is(ctx.Err(), context.Canceled) {
		return 0
	}
	return helperDiagnostic(streams.Err, "runtime unavailable; enforcement not verified", 1)
}

func renderHelperImageGuards(ctx context.Context, path string, streams CheckIO) int {
	bounded, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	data, err := readBounded(path, 2*1024*1024)
	if err != nil {
		return helperDiagnostic(streams.Err, "image baseline unavailable", 1)
	}
	program, err := firewall.RenderImageGuards(bounded, data)
	if err != nil || bounded.Err() != nil {
		return helperDiagnostic(streams.Err, "image guard rendering failed", 1)
	}
	if _, err := io.Copy(streams.Out, bytes.NewReader(program)); err != nil {
		return helperDiagnostic(streams.Err, "image guard output failed", 1)
	}
	return 0
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
