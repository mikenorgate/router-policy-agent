//go:build integration

package radius

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"
)

func TestMain(m *testing.M) {
	if os.Args[0] == "journalctl" {
		os.Exit(journalFixture())
	}
	os.Exit(m.Run())
}

// The child is this test ELF, passed through the same pinned FD as journalctl.
// Fixed numeric test UIDs select synthetic I/O behavior without inherited env.
func journalFixture() int {
	if len(os.Environ()) != 4 || os.Getenv("LC_ALL") != "C" || os.Getenv("TZ") != "UTC" ||
		os.Getenv("PATH") != "/usr/bin" || os.Getenv("SYSTEMD_COLORS") != "0" {
		return 9
	}
	last := os.Args[len(os.Args)-1]
	if !strings.HasPrefix(last, "_UID=") {
		return 9
	}
	uid, err := strconv.ParseUint(strings.TrimPrefix(last, "_UID="), 10, 32)
	if err != nil {
		return 9
	}
	scope := fixtureScope()
	scope.ServiceUID = uint32(uid) // ParseUint is bounded to 32 bits above.
	expected := journalArguments(scope)
	if strings.Join(os.Args[1:], "\x00") != strings.Join(expected, "\x00") {
		return 9
	}
	switch uid {
	case 1:
		if _, err := fmt.Fprint(os.Stderr, "synthetic private upstream warning"); err != nil {
			return 8
		}
	case 2:
		if _, err := fmt.Fprint(os.Stdout, strings.Repeat("x", maximumHistory+1)); err != nil {
			return 8
		}
	case 3:
		time.Sleep(time.Hour) // Parent's bounded context must kill and join this child.
	case 4:
		if _, err := fmt.Fprint(os.Stdout, "synthetic partial prefix\n"); err != nil {
			return 8
		}
		return 7
	default:
		if _, err := fmt.Fprint(os.Stdout, "synthetic complete output\n"); err != nil {
			return 8
		}
	}
	return 0
}

func TestJournalPinnedChildOutputFailureAndCancellation(t *testing.T) {
	if testing.CoverMode() != "" {
		t.Skip("run pinned-child fixture without -cover: its fixed environment deliberately excludes GOCOVERDIR")
	}
	t.Parallel()
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		name      string
		uid       uint32
		budget    time.Duration
		wantError bool
	}{
		{name: "complete", uid: 123, budget: 5 * time.Second},
		{name: "warning", uid: 1, budget: 5 * time.Second, wantError: true},
		{name: "oversized", uid: 2, budget: 5 * time.Second, wantError: true},
		{name: "deadline", uid: 3, budget: 250 * time.Millisecond, wantError: true},
		{name: "nonzero after prefix", uid: 4, budget: 5 * time.Second, wantError: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			// #nosec G304 -- Current test ELF from os.Executable, not an external path.
			file, err := os.Open(executable)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() {
				if err := file.Close(); err != nil {
					t.Error(err)
				}
			})
			ctx, cancel := context.WithTimeout(t.Context(), test.budget)
			defer cancel()
			scope := fixtureScope()
			scope.ServiceUID = test.uid
			data, err := runJournal(ctx, file, scope)
			if (err != nil) != test.wantError {
				t.Fatalf("unexpected command result: %v", err)
			}
			if test.wantError && len(data) != 0 {
				t.Fatal("failed child exposed partial output")
			}
			if err != nil && strings.Contains(err.Error(), "private upstream") {
				t.Fatal("upstream diagnostics escaped")
			}
			if test.name == "deadline" && !errors.Is(err, context.DeadlineExceeded) {
				t.Fatal("deadline lost")
			}
			if !test.wantError && string(data) != "synthetic complete output\n" {
				t.Fatal("successful output changed")
			}
		})
	}
}

func TestJournalKernelIdentityAndInvalidOptions(t *testing.T) {
	t.Parallel()
	boot, err := currentBootID()
	scope := fixtureScope()
	scope.BootID = boot
	if err != nil || !validScope(scope) {
		t.Fatalf("kernel boot identity invalid: %v", err)
	}
	if _, err := captureHistory(t.Context(), JournalOptions{}); err == nil {
		t.Fatal("empty scope admitted")
	}
	if _, err := runJournal(t.Context(), nil, fixtureScope()); err == nil {
		t.Fatal("nil executable admitted")
	}
}
