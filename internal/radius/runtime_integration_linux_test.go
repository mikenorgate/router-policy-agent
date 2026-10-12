//go:build integration

package radius

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestRunShadowConfigurationAndDeadline(t *testing.T) {
	t.Parallel()
	directory, _ := privateExportRoot(t)
	path := filepath.Join(directory, "collector.json")
	if err := os.WriteFile(path, runtimeFixture(), 0o600); err != nil {
		t.Fatal(err)
	}
	var called bool
	result, err := runShadow(t.Context(), directory, func(ctx context.Context, options CollectorOptions, output string) (Collection, error) {
		called = true
		deadline, ok := ctx.Deadline()
		if !ok || time.Until(deadline) > 30*time.Second || options.Journal.ServiceUID == 0 || options.Kea.ServerUID == 0 {
			t.Fatal("deadline or host service identity missing")
		}
		if output != "/var/lib/router-policy-radius-shadow" || options.VLAN != 22 || options.Kea.SubnetID != 22 {
			t.Fatal("configuration was not wired to collector")
		}
		return Collection{Generation: "synthetic", Candidates: []IPv4Candidate{}}, nil
	})
	if err != nil || !called || result.Generation != "synthetic" {
		t.Fatalf("runtime wiring failed: %v", err)
	}
}

func TestRunShadowUnsafeConfigAndFailureRedaction(t *testing.T) {
	t.Parallel()
	directory, _ := privateExportRoot(t)
	path := filepath.Join(directory, "collector.json")
	if err := os.WriteFile(path, runtimeFixture(), 0o600); err != nil {
		t.Fatal(err)
	}
	fail := func(context.Context, CollectorOptions, string) (Collection, error) {
		return Collection{Generation: "must-not-escape"}, errors.New("synthetic private daemon payload")
	}
	result, err := runShadow(t.Context(), directory, fail)
	if err == nil || result.Generation != "" || strings.Contains(err.Error(), "private daemon") {
		t.Fatal("source failure exposed payload or partial result")
	}
	// #nosec G302 -- Deliberately unsafe fixture tests rejection, never production.
	if err := os.Chmod(path, 0o644); err != nil {
		t.Fatal(err)
	}
	called := false
	_, err = runShadow(t.Context(), directory, func(context.Context, CollectorOptions, string) (Collection, error) {
		called = true
		return Collection{}, nil
	})
	if err == nil || called {
		t.Fatal("unsafe config reached collection")
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if _, err := runShadow(ctx, directory, fail); !errors.Is(err, context.Canceled) {
		t.Fatal("cancellation lost")
	}
}
