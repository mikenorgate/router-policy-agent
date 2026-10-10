//go:build integration

package radius

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"

	"github.com/mikenorgate/router-policy-agent/internal/binding"
)

func TestShadowInputPrivateFileWithdrawalRecoveryAndExpiry(t *testing.T) {
	t.Parallel()
	directory, root := privateExportRoot(t)
	report := shadowInputFixture(t)
	now := report.SampledAt
	clock := func() time.Time { return now }
	if err := writeShadow(t.Context(), root, report); err != nil {
		t.Fatal(err)
	}
	first, err := loadShadowProposals(t.Context(), directory, clock)
	if err != nil || len(first.Records) != 1 {
		t.Fatal("private shadow report unavailable", err)
	}
	deadline := first.Records[0].Addresses[0].ValidUntil
	now = deadline
	if got, err := loadShadowProposals(t.Context(), directory, clock); err == nil || got.Complete {
		t.Fatal("frozen file remained usable after original deadline")
	}
	now = report.SampledAt
	report.Complete = false
	if err := writeShadow(t.Context(), root, report); err != nil {
		t.Fatal(err)
	}
	if got, err := loadShadowProposals(t.Context(), directory, clock); err == nil || got.Complete {
		t.Fatal("failed collection retained its previous evidence")
	}
	report.Complete = true
	report.Collection.Candidates = []IPv4Candidate{}
	report.Collection.ProposedBindings = []binding.Record{}
	if err := writeShadow(t.Context(), root, report); err != nil {
		t.Fatal(err)
	}
	if got, err := loadShadowProposals(t.Context(), directory, clock); err != nil || len(got.Records) != 0 {
		t.Fatal("empty withdrawal did not reach consumer")
	}
	report = shadowInputFixture(t)
	if err := writeShadow(t.Context(), root, report); err != nil {
		t.Fatal(err)
	}
	if got, err := loadShadowProposals(t.Context(), directory, clock); err != nil || len(got.Records) != 1 {
		t.Fatal("fresh complete publication did not recover")
	}
	if _, err := os.Stat(filepath.Join(directory, "bindings.json")); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("shadow loader created authoritative output")
	}
	if err := root.WriteFile("bindings.json", shadowInputBytes(t, report), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := binding.Load(t.Context(), directory); err == nil {
		t.Fatal("normal enforcement loader accepted renamed shadow input")
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if _, err := loadShadowProposals(ctx, directory, clock); !errors.Is(err, context.Canceled) {
		t.Fatal("canceled read did not preserve cancellation")
	}
}

func TestShadowInputRejectsUnsafePrivateFiles(t *testing.T) {
	t.Parallel()
	for _, name := range []string{"symlink", "hardlink", "fifo", "public file", "public directory", "missing", "nil clock"} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			directory, root := privateExportRoot(t)
			report := shadowInputFixture(t)
			clock := func() time.Time { return report.SampledAt }
			if name != "missing" {
				if err := writeShadow(t.Context(), root, report); err != nil {
					t.Fatal(err)
				}
			}
			path := filepath.Join(directory, shadowFilename)
			var err error
			switch name {
			case "symlink", "hardlink", "fifo":
				if err := root.Rename(shadowFilename, "other.json"); err != nil {
					t.Fatal(err)
				}
				switch name {
				case "symlink":
					err = os.Symlink("other.json", path)
				case "hardlink":
					err = os.Link(filepath.Join(directory, "other.json"), path)
				case "fifo":
					err = syscall.Mkfifo(path, 0o600)
				}
			case "public file":
				err = os.Chmod(path, 0o644) // #nosec G302 -- Intentionally unsafe negative fixture.
			case "public directory":
				err = os.Chmod(directory, 0o755) // #nosec G302 -- Intentionally unsafe negative fixture.
			case "nil clock":
				clock = nil
			}
			if err != nil {
				t.Fatal(err)
			}
			if got, err := loadShadowProposals(t.Context(), directory, clock); err == nil || got.Complete {
				t.Fatal("unsafe file returned shadow evidence")
			}
		})
	}
}
