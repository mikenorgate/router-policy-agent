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
	"unicode"

	"github.com/mikenorgate/router-policy-agent/internal/reader"
)

// RunReader starts the non-root fresh-collection loop; only help/version write
// stdout. Fixed JSON runtime outcomes go to stderr. Exit codes are 0 for help,
// version or orderly cancellation, 1 for runtime failure and 2 for usage errors.
// It does not install/start a helper, qualify sources or authorize deployment.
func RunReader(ctx context.Context, args []string, streams CheckIO) int {
	return runReader(ctx, args, streams, reader.Run)
}

type readerFunc func(context.Context, string, io.Writer) error

func runReader(ctx context.Context, args []string, streams CheckIO, run readerFunc) int {
	if ctx == nil || streams.Out == nil || streams.Err == nil || run == nil {
		return 2
	}
	var directory string
	var version bool
	var messages bytes.Buffer
	flags := flag.NewFlagSet("router-policy-reader", flag.ContinueOnError)
	flags.SetOutput(&messages)
	flags.StringVar(
		&directory,
		"config-directory",
		"",
		"private reader-owned directory with reader.json and runtime credentials.json (required)",
	)
	flags.BoolVar(&version, "version", false, "print build version")
	flags.Usage = func() {
		fmt.Fprintln(&messages, "Collect fresh LDAPS snapshots and submit to the root helper as a non-root reader.")
		fmt.Fprintln(&messages, "Usage: router-policy-reader -config-directory PATH")
		fmt.Fprintln(&messages, "Polls every 30s; one 10s collection/submission deadline; never replays a failed snapshot.")
		flags.PrintDefaults()
	}
	if err := flags.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			if _, err := io.Copy(streams.Out, &messages); err != nil {
				return 1
			}
			return 0
		}
		return readerDiagnostic(streams.Err, "invalid flags; use -help", 2)
	}
	if flags.NArg() != 0 {
		return readerDiagnostic(streams.Err, "unexpected positional arguments", 2)
	}
	if version {
		if _, err := fmt.Fprintln(streams.Out, Version); err != nil {
			return 1
		}
		return 0
	}
	isClean := directory != "/" && filepath.IsAbs(directory) && filepath.Clean(directory) == directory
	isBounded := len(directory) <= 4096 && strings.IndexFunc(directory, unicode.IsControl) < 0
	if !isClean || !isBounded {
		return readerDiagnostic(streams.Err, "valid -config-directory required", 2)
	}
	err := run(ctx, directory, streams.Err)
	if err == nil || errors.Is(err, context.Canceled) && errors.Is(ctx.Err(), context.Canceled) {
		return 0
	}
	return readerDiagnostic(streams.Err, "runtime unavailable", 1)
}

func readerDiagnostic(writer io.Writer, message string, code int) int {
	if _, err := fmt.Fprintf(writer, "router-policy-reader: %s\n", message); err != nil {
		return 1
	}
	return code
}
