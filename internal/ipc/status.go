package ipc

import (
	"bytes"
	"encoding/json"
	"errors"
	"regexp"
	"slices"
	"time"

	"github.com/mikenorgate/router-policy-agent/internal/strictjson"
)

const maximumStatusRequest = 512

// MaximumRuleReferences bounds diagnostic detail independently of tuple quota.
const MaximumRuleReferences = 128

var statusIdentifier = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9._:-]{0,127}$`)
var denialCode = regexp.MustCompile(`^[a-z][a-z_]{0,63}$`)

// RuleReference identifies a contributor without returning its policy, peers,
// device identity or operator-supplied reason text.
type RuleReference struct {
	GroupID string `json:"group_id"`
	RuleID  string `json:"rule_id"`
}

// Report separates the last successful helper decision from current kernel
// evidence. RemainingGrantCount is a conservative local countdown, not an
// assertion that packets can pass. KernelTupleCount counts the primary logical
// lease-set entries at one fenced inspection, not grants or mirror copies.
// A matching pinned contract is not proof of its protected-policy semantics.
// Ages and expiry are milliseconds; null means no usable observation.
type Report struct {
	SchemaVersion       int             `json:"schema_version"`
	Mode                string          `json:"mode"`
	HelperState         string          `json:"helper_state"`
	PermitState         string          `json:"permit_state"`
	LastFailure         string          `json:"last_failure"`
	BaselineHash        string          `json:"baseline_hash"`
	BaselineGeneration  string          `json:"baseline_generation"`
	LastCompiledAt      time.Time       `json:"last_compiled_at"`
	DirectoryAgeMS      *int64          `json:"directory_age_ms"`
	DecisionAgeMS       *int64          `json:"decision_age_ms"`
	ApplyAgeMS          *int64          `json:"apply_age_ms"`
	LastGrantCount      int             `json:"last_grant_count"`
	LastDenialCount     int             `json:"last_denial_count"`
	LastBindingCount    int             `json:"last_binding_count"`
	RemainingGrantCount int             `json:"remaining_grant_count"`
	NextExpiryMS        *int64          `json:"next_expiry_ms"`
	Rules               []RuleReference `json:"rules"`
	RulesTruncated      bool            `json:"rules_truncated"`
	DenialCodes         []string        `json:"denial_codes"`
	ClockState          string          `json:"clock_state"`
	FloorState          string          `json:"floor_state"`
	KernelTupleCount    *int            `json:"kernel_tuple_count"`
	WriterSequence      *uint64         `json:"writer_sequence"`
}

type reportResponse struct {
	SchemaVersion int     `json:"schema_version"`
	Code          string  `json:"code"`
	Report        *Report `json:"report"`
}

func decodeStatusRequest(data []byte) error {
	if err := strictjson.Object(
		data,
		[]string{"schema_version", "operation"},
		nil,
		maximumStatusRequest,
	); err != nil {
		return err
	}
	var request struct {
		SchemaVersion int    `json:"schema_version"`
		Operation     string `json:"operation"`
	}
	if err := strictjson.Decode(data, &request, maximumStatusRequest); err != nil {
		return err
	}
	if request.SchemaVersion != 1 || request.Operation != "status" {
		return errors.New("ipc: invalid status operation")
	}
	return nil
}

func decodeReport(data []byte) (Report, error) {
	if err := statusObject(data, []string{"schema_version", "code", "report"}, []string{"report"}); err != nil {
		return Report{}, err
	}
	var response reportResponse
	if err := strictjson.Decode(data, &response, maximumResponse); err != nil {
		return Report{}, err
	}
	if response.SchemaVersion != 1 {
		return Report{}, errors.New("ipc: unsupported status version")
	}
	if response.Code != "" {
		isKnown := response.Code == "invalid_request" || response.Code == "status_failed"
		if !isKnown || response.Report != nil {
			return Report{}, errors.New("ipc: invalid status rejection")
		}
		return Report{}, ErrRejected
	}
	if response.Report == nil {
		return Report{}, errors.New("ipc: missing status report")
	}
	// The outer object was already checked. Enforce every report field rather
	// than interpreting a missing observation/count as its Go zero value.
	object := map[string]json.RawMessage{}
	if err := strictjson.Decode(data, &object, maximumResponse); err != nil {
		return Report{}, err
	}
	keys := []string{"schema_version", "mode", "helper_state", "permit_state", "last_failure",
		"baseline_hash", "baseline_generation", "last_compiled_at", "directory_age_ms", "decision_age_ms",
		"apply_age_ms", "last_grant_count", "last_denial_count", "last_binding_count", "remaining_grant_count",
		"next_expiry_ms", "rules", "rules_truncated", "denial_codes", "clock_state", "floor_state",
		"kernel_tuple_count", "writer_sequence"}
	nullable := []string{"directory_age_ms", "decision_age_ms", "apply_age_ms", "next_expiry_ms",
		"kernel_tuple_count", "writer_sequence"}
	if err := statusObject(object["report"], keys, nullable); err != nil {
		return Report{}, err
	}
	fields := map[string]json.RawMessage{}
	if err := strictjson.Decode(object["report"], &fields, maximumResponse); err != nil {
		return Report{}, err
	}
	references := []json.RawMessage{}
	if err := strictjson.Decode(fields["rules"], &references, maximumResponse); err != nil {
		return Report{}, err
	}
	for _, reference := range references {
		if err := statusObject(reference, []string{"group_id", "rule_id"}, nil); err != nil {
			return Report{}, err
		}
	}
	if err := validReport(*response.Report); err != nil {
		return Report{}, err
	}
	return *response.Report, nil
}

// Status explicitly represents unavailable observations as null. Unlike the
// policy parser, it permits null only for these fixed diagnostic fields while
// still requiring every field and exact case-sensitive object keys.
func statusObject(data []byte, keys, nullable []string) error {
	object := map[string]json.RawMessage{}
	if err := strictjson.Decode(data, &object, maximumResponse); err != nil {
		return err
	}
	if object == nil || len(object) != len(keys) {
		return errors.New("ipc: status object fields differ")
	}
	for _, key := range keys {
		value, exists := object[key]
		if !exists || bytes.Equal(bytes.TrimSpace(value), []byte("null")) && !slices.Contains(nullable, key) {
			return errors.New("ipc: status field missing or unexpectedly null")
		}
	}
	return nil
}

// ValidateReport checks the bounded, credential-free status contract. It does
// not authenticate the supplying helper or verify the claimed kernel evidence.
func ValidateReport(report Report) error { return validReport(report) }

func validReport(report Report) error {
	// The existing receipt checker owns the canonical configuration-hash check.
	if err := validReceipt(Receipt{SchemaVersion: report.SchemaVersion, Status: StatusShadow,
		BaselineHash: report.BaselineHash, CompiledAt: time.Unix(1, 0),
		GrantCount: report.LastGrantCount, DenialCount: report.LastDenialCount}); err != nil {
		return errors.New("ipc: invalid status identity or counts")
	}
	isMode := report.Mode == "shadow" || report.Mode == "enforce"
	isState := report.HelperState == "not_started" || report.HelperState == "ready" ||
		report.HelperState == "startup_failed" || report.HelperState == "failed" || report.HelperState == "stopped"
	isPermits := report.PermitState == "unobserved" || report.PermitState == "sealed" ||
		report.PermitState == "last_application" || report.PermitState == "shadow" || report.PermitState == "unknown"
	isFailure := report.LastFailure == "" || report.LastFailure == "processing_failed" ||
		report.LastFailure == "startup_failed" || report.LastFailure == "seal_failed"
	isValidState := isMode && isState && isPermits && isFailure
	if !isValidState || !statusIdentifier.MatchString(report.BaselineGeneration) {
		return errors.New("ipc: invalid status state")
	}
	isClock := report.ClockState == "usable" || report.ClockState == "unverified"
	isFloor := report.FloorState == "unverified" || report.FloorState == "matches_pinned_contract"
	isCounts := report.LastBindingCount >= 0 && report.LastBindingCount <= 4096 &&
		report.RemainingGrantCount >= 0 && report.RemainingGrantCount <= report.LastGrantCount
	isValidEvidence := isClock && isFloor && isCounts
	if !isValidEvidence {
		return errors.New("ipc: invalid status evidence")
	}
	for _, age := range []*int64{report.DirectoryAgeMS, report.DecisionAgeMS, report.ApplyAgeMS, report.NextExpiryMS} {
		if age != nil && *age < 0 {
			return errors.New("ipc: invalid status age")
		}
	}
	if report.Mode == "shadow" && report.ApplyAgeMS != nil {
		return errors.New("ipc: shadow status claims application")
	}
	hasObservationAge := report.DirectoryAgeMS != nil || report.DecisionAgeMS != nil || report.ApplyAgeMS != nil
	if report.ClockState == "unverified" && hasObservationAge {
		return errors.New("ipc: unverified clock claims elapsed observations")
	}
	hasRemaining := report.RemainingGrantCount > 0
	canCount := report.ClockState == "usable" && report.HelperState == "ready" &&
		(report.PermitState == "last_application" || report.PermitState == "shadow")
	if hasRemaining != (report.NextExpiryMS != nil) || hasRemaining && !canCount {
		return errors.New("ipc: inconsistent status countdown")
	}
	hasKernelEvidence := report.KernelTupleCount != nil && report.WriterSequence != nil
	if report.FloorState == "matches_pinned_contract" {
		// Short-circuit before reading optional observations.
		isBounded := hasKernelEvidence && *report.KernelTupleCount >= 0 &&
			*report.KernelTupleCount <= 65536 && *report.WriterSequence > 0
		if !isBounded {
			return errors.New("ipc: invalid kernel status evidence")
		}
	} else if report.KernelTupleCount != nil || report.WriterSequence != nil {
		return errors.New("ipc: unverified status contains kernel evidence")
	}
	hasDetail := report.Rules != nil && report.DenialCodes != nil
	isBoundedDetail := len(report.Rules) <= MaximumRuleReferences && len(report.DenialCodes) <= 64
	if !hasDetail || !isBoundedDetail {
		return errors.New("ipc: status detail quota exceeded")
	}
	seen := map[RuleReference]bool{}
	for _, reference := range report.Rules {
		isIdentifier := statusIdentifier.MatchString(reference.GroupID) && statusIdentifier.MatchString(reference.RuleID)
		if !isIdentifier || seen[reference] {
			return errors.New("ipc: invalid status contributor")
		}
		seen[reference] = true
	}
	for index, code := range report.DenialCodes {
		if !denialCode.MatchString(code) || index > 0 && report.DenialCodes[index-1] >= code {
			return errors.New("ipc: invalid status denial code")
		}
	}
	encoded, err := json.Marshal(report)
	if err != nil || len(encoded) > maximumResponse-256 {
		return errors.New("ipc: status response exceeds limit")
	}
	return nil
}
