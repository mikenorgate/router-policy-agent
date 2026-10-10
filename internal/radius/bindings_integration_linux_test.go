//go:build integration

package radius

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/mikenorgate/router-policy-agent/internal/binding"
)

func TestNativeBindingPublisherInvalidatesAndLoadsWithoutShadow(t *testing.T) {
	for _, test := range []struct {
		name string
		fail bool
	}{
		{name: "fresh native collection"},
		{name: "source failure", fail: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			directory, root := privateExportRoot(t)
			options, collected := bindingPublisherFixture(t, time.Now().UTC())
			options.Directory = directory
			if err := writeBindings(t.Context(), root, binding.Snapshot{
				SchemaVersion: 1, Complete: true, Generation: "previous", ObservedAt: time.Now().UTC(), Records: []binding.Record{},
			}); err != nil {
				t.Fatal(err)
			}
			_, err := publishBindings(t.Context(), root, options, func(context.Context) (Collection, error) {
				if _, err := binding.Load(t.Context(), directory); err == nil {
					t.Fatal("last complete export remained available during source reads")
				}
				if test.fail {
					return Collection{}, errors.New("synthetic source failure")
				}
				return collected, nil
			})
			if (err != nil) != test.fail {
				t.Fatal("unexpected publication result")
			}
			snapshot, err := binding.Load(t.Context(), directory)
			if test.fail {
				if err == nil {
					t.Fatal("source failure retained an accepted export")
				}
			} else if err != nil || len(snapshot.Records) != 1 || snapshot.Records[0].Addresses[0] != collected.ProposedBindings[0].Addresses[0] {
				t.Fatal("native binding feed did not load with original evidence")
			}
			if _, err := os.Stat(filepath.Join(directory, shadowFilename)); !errors.Is(err, os.ErrNotExist) {
				t.Fatal("native publisher read or wrote a shadow report")
			}
		})
	}
}
