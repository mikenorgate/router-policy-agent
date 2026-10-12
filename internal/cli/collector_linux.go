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
	"unicode"

	"github.com/mikenorgate/router-policy-agent/internal/radius"
)

// RunCollector collects one root-only IPv4 shadow report or, with explicit
// opt-in and matching configuration, a native binding export. Exit codes are 0 for
// success/help/version, 1 for runtime or output failure, and 2 for invalid use.
// Only counts are printed; device and upstream payloads stay in private storage.
func RunCollector(ctx context.Context, args []string, streams CheckIO) int {
	return runCollectorModes(ctx, args, streams, radius.RunShadow, radius.RunBindings)
}

func runCollector(
	ctx context.Context,
	args []string,
	streams CheckIO,
	collect func(context.Context, string) (radius.Collection, error),
) int {
	return runCollectorModes(ctx, args, streams, collect, nil)
}

func runCollectorModes(
	ctx context.Context,
	args []string,
	streams CheckIO,
	shadow func(context.Context, string) (radius.Collection, error),
	bindings func(context.Context, string) (radius.Collection, error),
) int {
	if ctx == nil || streams.Out == nil || streams.Err == nil || shadow == nil {
		return 2
	}
	var directory string
	var version bool
	var publishBindings bool
	var messages bytes.Buffer
	flags := flag.NewFlagSet("router-policy-collector", flag.ContinueOnError)
	flags.SetOutput(&messages)
	flags.StringVar(&directory, "config-directory", "", "private root-owned directory containing collector.json (required)")
	flags.BoolVar(&version, "version", false, "print build version")
	flags.BoolVar(&publishBindings, "publish-bindings", false, "publish native bindings from explicitly enrolled guarded-DHCP configuration")
	flags.Usage = func() {
		fmt.Fprintln(&messages, "Collect local RADIUS/DHCP evidence once; no firewall writes.")
		fmt.Fprintln(&messages, "Usage: router-policy-collector -config-directory PATH")
		fmt.Fprintln(&messages, "Root required. Fixed 30s deadline. No environment overrides or credentials.")
		flags.PrintDefaults()
	}
	if err := flags.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			if _, err := io.Copy(streams.Out, &messages); err != nil {
				return 1
			}
			return 0
		}
		return collectorDiagnostic(streams.Err, "invalid flags; use -help", 2)
	}
	if flags.NArg() != 0 {
		return collectorDiagnostic(streams.Err, "unexpected positional arguments", 2)
	}
	if version {
		if _, err := fmt.Fprintln(streams.Out, Version); err != nil {
			return 1
		}
		return 0
	}
	if !collectorDirectory(directory) {
		return collectorDiagnostic(streams.Err, "valid -config-directory required", 2)
	}
	collect, mode := shadow, "shadow"
	if publishBindings {
		if bindings == nil {
			return collectorDiagnostic(streams.Err, "binding publisher unavailable", 2)
		}
		collect, mode = bindings, "bindings"
	}
	collection, err := collect(ctx, directory)
	if err != nil {
		return collectorDiagnostic(streams.Err, "collection unavailable", 1)
	}
	result := struct {
		Mode             string `json:"mode"`
		Complete         bool   `json:"complete"`
		EnforcementReady bool   `json:"enforcement_ready"`
		Candidates       int    `json:"candidates"`
		Withheld         int    `json:"withheld"`
	}{Mode: mode, Complete: true, Candidates: len(collection.Candidates), Withheld: collection.Withheld}
	if err := json.NewEncoder(streams.Out).Encode(result); err != nil {
		return 1
	}
	return 0
}

func collectorDirectory(path string) bool {
	validPath := path != "/" && filepath.IsAbs(path) && filepath.Clean(path) == path
	return validPath && len(path) <= 4096 && strings.IndexFunc(path, unicode.IsControl) < 0
}

func collectorDiagnostic(writer io.Writer, message string, code int) int {
	if _, err := fmt.Fprintf(writer, "router-policy-collector: %s\n", message); err != nil {
		return 1
	}
	return code
}
