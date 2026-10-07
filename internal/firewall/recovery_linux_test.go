package firewall

import (
	"context"
	"errors"
	"os"
	"testing"
)

func TestRecoverRejectsMissingContextCancellationAndNonRoot(t *testing.T) {
	t.Parallel()
	var missingContext context.Context
	if err := Recover(missingContext, "/synthetic/config"); err == nil {
		t.Fatal("nil recovery context accepted")
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if err := Recover(ctx, "/synthetic/config"); !errors.Is(err, context.Canceled) {
		t.Fatal("canceled recovery did not reject before opening resources")
	}
	if resources, err := openConfiguredOwner(missingContext, helperConfig{}); err == nil || resources != nil {
		t.Fatal("missing enforcement owner context accepted")
	}
	if os.Geteuid() != 0 {
		if err := Recover(t.Context(), "/synthetic/config"); err == nil {
			t.Fatal("non-root recovery accepted")
		}
		if resources, err := openConfiguredOwner(t.Context(), helperConfig{}); err == nil || resources != nil {
			t.Fatal("non-root enforcement owner accepted")
		}
	}
}
