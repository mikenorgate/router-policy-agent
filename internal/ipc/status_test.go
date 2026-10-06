package ipc

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"
)

func fixtureReport() Report {
	return Report{SchemaVersion: 1, Mode: "enforce", HelperState: "ready", PermitState: "sealed",
		BaselineHash: fixtureReceipt().BaselineHash, BaselineGeneration: "synthetic-v1",
		Rules: []RuleReference{}, DenialCodes: []string{}, ClockState: "usable", FloorState: "unverified"}
}

func TestStatusProtocolRejectsAdditionalAuthority(t *testing.T) {
	t.Parallel()
	for _, test := range []struct {
		name, input string
		valid       bool
	}{
		{name: "fixed operation", input: `{"schema_version":1,"operation":"status"}`, valid: true},
		{name: "unknown version", input: `{"schema_version":2,"operation":"status"}`},
		{name: "directory submission", input: `{"schema_version":1,"directory":{}}`},
		{name: "state reset", input: `{"schema_version":1,"operation":"reset"}`},
		{name: "additional command", input: `{"schema_version":1,"operation":"status","command":"ignored"}`},
		{name: "duplicate operation", input: `{"schema_version":1,"operation":"status","operation":"reset"}`},
		{name: "oversized", input: strings.Repeat(" ", maximumStatusRequest) + `{}`},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			if (decodeStatusRequest([]byte(test.input)) == nil) != test.valid {
				t.Fatal("status operation authority mismatch")
			}
		})
	}
}

func TestStatusReportBounds(t *testing.T) {
	t.Parallel()
	for _, test := range []struct {
		name   string
		change func(*Report)
	}{
		{name: "schema", change: func(r *Report) { r.SchemaVersion = 2 }},
		{name: "hash", change: func(r *Report) { r.BaselineHash = "unknown" }},
		{name: "generation", change: func(r *Report) { r.BaselineGeneration = "" }},
		{name: "state", change: func(r *Report) { r.HelperState = "healthy" }},
		{name: "permit state", change: func(r *Report) { r.PermitState = "permanent" }},
		{name: "raw failure", change: func(r *Report) { r.LastFailure = "synthetic private error" }},
		{name: "negative age", change: func(r *Report) { value := int64(-1); r.ApplyAgeMS = &value }},
		{name: "shadow application", change: func(r *Report) { value := int64(0); r.Mode = "shadow"; r.ApplyAgeMS = &value }},
		{name: "binding count", change: func(r *Report) { r.LastBindingCount = 4097 }},
		{name: "grant count", change: func(r *Report) { r.LastGrantCount = 16385 }},
		{name: "remaining count", change: func(r *Report) { r.RemainingGrantCount = 1 }},
		{name: "orphan expiry", change: func(r *Report) { value := int64(1); r.NextExpiryMS = &value }},
		{name: "clock", change: func(r *Report) { r.ClockState = "synchronized" }},
		{name: "floor", change: func(r *Report) { r.FloorState = "semantically_proven" }},
		{name: "kernel assertion without observation", change: func(r *Report) { r.FloorState = "matches_pinned_contract" }},
		{name: "kernel count without floor", change: func(r *Report) { value := 0; r.KernelTupleCount = &value }},
		{name: "null references", change: func(r *Report) { r.Rules = nil }},
		{name: "null denials", change: func(r *Report) { r.DenialCodes = nil }},
		{name: "unbounded references", change: func(r *Report) { r.Rules = make([]RuleReference, MaximumRuleReferences+1) }},
		{name: "raw identifier", change: func(r *Report) {
			r.Rules = []RuleReference{{GroupID: "bad\nvalue", RuleID: "rule"}}
		}},
		{name: "duplicate reference", change: func(r *Report) {
			r.Rules = []RuleReference{{GroupID: "group", RuleID: "rule"}, {GroupID: "group", RuleID: "rule"}}
		}},
		{name: "raw denial", change: func(r *Report) { r.DenialCodes = []string{"synthetic private reason"} }},
		{name: "unsorted denials", change: func(r *Report) { r.DenialCodes = []string{"inactive", "bad_binding"} }},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			report := fixtureReport()
			test.change(&report)
			if ValidateReport(report) == nil {
				t.Fatal("invalid status report accepted")
			}
		})
	}
	valid := fixtureReport()
	count, sequence := 8, uint64(1)
	valid.KernelTupleCount, valid.WriterSequence = &count, &sequence
	valid.FloorState = "matches_pinned_contract"
	data, err := json.Marshal(reportResponse{SchemaVersion: 1, Report: &valid})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := decodeReport(data); err != nil {
		t.Fatal(err)
	}
	for _, input := range []string{
		`{"schema_version":1,"code":"status_failed","report":null}`,
		`{"schema_version":1,"code":"invalid_request","report":null}`,
	} {
		if _, err := decodeReport([]byte(input)); !errors.Is(err, ErrRejected) {
			t.Fatal("status rejection did not use the fixed error")
		}
	}
	for _, input := range []string{
		`{"schema_version":1,"code":"private detail","report":null}`,
		`{"schema_version":2,"code":"status_failed","report":null}`,
		`{"schema_version":1,"code":"","report":null}`,
		strings.Replace(string(data), `"last_binding_count":0,`, "", 1),
		strings.Replace(string(data), `"last_binding_count":0`, `"last_binding_count":0,"credentials":"synthetic"`, 1),
	} {
		if _, err := decodeReport([]byte(input)); err == nil {
			t.Fatal("incomplete or authority-bearing report accepted")
		}
	}
}

func FuzzStatus(f *testing.F) {
	report := fixtureReport()
	data, err := json.Marshal(reportResponse{SchemaVersion: 1, Report: &report})
	if err != nil {
		f.Fatal(err)
	}
	f.Add(data)
	f.Add([]byte(`{"schema_version":1,"code":"status_failed","report":null}`))
	f.Add([]byte(`{"schema_version":1,"operation":"status"}`))
	f.Add([]byte(`{"schema_version":1,"operation":"status","operation":"reset"}`))
	f.Fuzz(func(t *testing.T, data []byte) {
		if report, err := decodeReport(data); err == nil {
			if ValidateReport(report) != nil {
				t.Fatal("decoder accepted an invalid report")
			}
			encoded, err := json.Marshal(reportResponse{SchemaVersion: 1, Report: &report})
			if err != nil {
				t.Fatal(err)
			}
			if _, err := decodeReport(encoded); err != nil {
				t.Fatal("accepted status did not round trip")
			}
		}
		if decodeStatusRequest(data) == nil {
			var request map[string]json.RawMessage
			if err := json.Unmarshal(data, &request); err != nil || len(request) != 2 {
				t.Fatal("status request accepted additional authority")
			}
			var operation string
			if err := json.Unmarshal(request["operation"], &operation); err != nil || operation != "status" {
				t.Fatal("status request accepted another operation")
			}
		}
	})
}
