package binding

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func snapshotBytes(t *testing.T) []byte {
	t.Helper()
	data, err := json.Marshal(Snapshot{
		SchemaVersion: 1, Generation: "synthetic-original-generation",
		ObservedAt: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC), Complete: true, Records: []Record{},
	})
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func TestBindingExportPreservesOldEvidence(t *testing.T) {
	t.Parallel()
	snapshot, err := decodeSnapshot(snapshotBytes(t))
	if err != nil || snapshot.Generation != "synthetic-original-generation" ||
		!snapshot.ObservedAt.Equal(time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)) {
		t.Fatal("export changed its original observation or generation")
	}
	if err := Validate(snapshot, time.Date(2026, 1, 1, 0, 2, 0, 0, time.UTC), 90*time.Second, 4096); err == nil {
		t.Fatal("loading stale evidence made it current")
	}
}

func TestBindingExportRejectsIncompleteOrAmbiguousData(t *testing.T) {
	t.Parallel()
	for _, test := range []struct{ name, old, replacement string }{
		{name: "unsupported schema", old: `"schema_version":1`, replacement: `"schema_version":2`},
		{name: "duplicate key", old: `"schema_version":1`, replacement: `"schema_version":1,"schema_version":1`},
		{name: "unknown key", old: `"schema_version":1`, replacement: `"schema_version":1,"unexpected":true`},
		{name: "wrong case", old: `"schema_version":1`, replacement: `"Schema_Version":1`},
		{name: "incomplete", old: `"complete":true`, replacement: `"complete":false`},
		{name: "null records", old: `"records":[]`, replacement: `"records":null`},
		{name: "missing generation", old: `"generation":"synthetic-original-generation",`, replacement: ``},
		{name: "empty generation", old: `synthetic-original-generation`, replacement: ``},
		{name: "trailing input", old: `"records":[]}`, replacement: `"records":[]} {}`},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			data := strings.Replace(string(snapshotBytes(t)), test.old, test.replacement, 1)
			if _, err := decodeSnapshot([]byte(data)); err == nil {
				t.Fatal("unsafe export accepted")
			}
		})
	}
}
