package policy

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/netip"
	"testing"
	"testing/synctest"
	"time"
)

func TestAuthorizationRemainingUsesOriginalAge(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name    string
		delay   time.Duration
		elapsed time.Duration
		utc     time.Duration
		want    time.Duration
		wantErr bool
	}{
		{name: "fresh", want: 90 * time.Second},
		{name: "utc correction shortens", utc: 40 * time.Second, want: 50 * time.Second},
		{name: "elapsed age beats rolled back utc", elapsed: 45 * time.Second, utc: 20 * time.Second,
			want: 45 * time.Second},
		{name: "sampling and compilation delay consumes lifetime", delay: 10 * time.Second,
			want: 80 * time.Second},
		{name: "queueing consumes lifetime", elapsed: 30 * time.Second, want: 60 * time.Second},
		{name: "utc predates compilation", utc: -time.Nanosecond, wantErr: true},
		{name: "elapsed expiry despite fresh utc", elapsed: 90 * time.Second, utc: 20 * time.Second, wantErr: true},
		{name: "utc expiry despite short elapsed age", utc: 90 * time.Second, wantErr: true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			synctest.Test(t, func(t *testing.T) {
				input := testInput(t)
				anchor := CaptureAge()
				time.Sleep(test.delay)
				authorization, err := testCompiler(t, testBaseline()).CompileAuthorization(t.Context(), input, anchor)
				if err != nil {
					t.Fatal(err)
				}
				copied := authorization
				time.Sleep(test.elapsed)
				remaining, err := copied.Remaining(0, input.Now.Add(test.utc))
				if (err != nil) != test.wantErr || remaining != test.want {
					t.Fatalf("remaining=%v, error=%v, want %v, error=%v", remaining, err, test.want, test.wantErr)
				}
			})
		})
	}
}

func TestAuthorizationClipsShorterEvidenceDeadline(t *testing.T) {
	t.Parallel()
	synctest.Test(t, func(t *testing.T) {
		input := testInput(t)
		input.Bindings.Records[0].Addresses[0].ValidUntil = input.Now.Add(12 * time.Second)
		authorization, err := testCompiler(t, testBaseline()).CompileAuthorization(t.Context(), input, CaptureAge())
		if err != nil {
			t.Fatal(err)
		}
		time.Sleep(5 * time.Second)
		remaining, err := authorization.Remaining(0, input.Now.Add(time.Second))
		if err != nil || remaining != 7*time.Second {
			t.Fatalf("ownership deadline gained lifetime: remaining=%v, error=%v", remaining, err)
		}
	})
}

func TestAuthorizationSnapshotCannotMutatePermit(t *testing.T) {
	t.Parallel()
	input := testInput(t)
	rule := testRule()
	rule.Peer.Addresses = []string{"10.250.0.20/32"}
	expires := input.Now.Add(40 * time.Second)
	rule.ExpiresAt = &expires
	input.Directory.Groups[1] = accessGroup(t, "access", true, rule)
	input.Directory.Devices = append(input.Directory.Devices, Device{
		ID: "synthetic-inactive", MAC: "02:00:00:00:00:02", GroupIDs: []string{},
	})
	authorization, err := testCompiler(t, testBaseline()).CompileAuthorization(t.Context(), input, CaptureAge())
	if err != nil {
		t.Fatal(err)
	}
	snapshot, err := authorization.Snapshot(t.Context())
	if err != nil || len(snapshot.Grants) != 1 || len(snapshot.Denials) != 1 ||
		len(snapshot.Ledger.FirstSeen) != 1 || len(snapshot.Ledger.AliasPeers) != 1 {
		t.Fatalf("immutable fixture lacks the structures under test: %v", err)
	}
	before, err := json.Marshal(snapshot)
	if err != nil {
		t.Fatal(err)
	}
	snapshot.BaselineHash, snapshot.BindingGeneration = "edited", "edited"
	snapshot.CompiledAt = snapshot.CompiledAt.Add(time.Hour)
	snapshot.Grants[0].MAC = "02:00:00:00:00:03"
	snapshot.Grants[0].Device.Real = netip.MustParseAddr("10.241.0.1")
	snapshot.Grants[0].Device.Variants[0] = netip.MustParseAddr("10.241.0.1")
	snapshot.Grants[0].Peer.Real = netip.MustParseAddr("10.241.0.2")
	snapshot.Grants[0].Peer.Variants[0] = netip.MustParseAddr("10.241.0.2")
	snapshot.Grants[0].Contributors[0].ExpiresAt = input.Now.Add(time.Hour)
	snapshot.Denials[0].Code = "edited"
	snapshot.Ledger.LastValidated = input.Now.Add(time.Hour)
	for key := range snapshot.Ledger.FirstSeen {
		snapshot.Ledger.FirstSeen[key] = input.Now.Add(time.Hour)
	}
	for key := range snapshot.Ledger.AliasPeers {
		snapshot.Ledger.AliasPeers[key] = netip.MustParseAddr("10.241.0.3")
	}
	for key := range snapshot.Ledger.NetworkGroups {
		delete(snapshot.Ledger.NetworkGroups, key)
	}
	after, err := authorization.Snapshot(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := json.Marshal(after)
	if err != nil || !bytes.Equal(before, encoded) {
		t.Fatalf("diagnostic/state copy edited the enforcement result: %v", err)
	}
	remaining, err := authorization.Remaining(0, input.Now)
	if err != nil || remaining > 40*time.Second {
		t.Fatalf("copy changed the original expiry: %v, %v", remaining, err)
	}
}

func TestAuthorizationRejectsUnsafeAnchors(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name   string
		anchor func() AgeAnchor
	}{
		{name: "zero", anchor: func() AgeAnchor { return AgeAnchor{} }},
		{name: "future private reading", anchor: func() AgeAnchor { return AgeAnchor{tick: time.Now().Add(time.Hour)} }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			compiler := testCompiler(t, testBaseline())
			authorization, err := compiler.CompileAuthorization(t.Context(), testInput(t), test.anchor())
			if err == nil || authorization.data != nil {
				t.Fatal("unsafe anchor yielded authorization")
			}
		})
	}
}

func TestAuthorizationCannotBeRestoredFromJSON(t *testing.T) {
	t.Parallel()
	anchor := CaptureAge()
	if data, err := json.Marshal(anchor); err == nil || len(data) != 0 {
		t.Fatal("process-local age anchor was serialized")
	}
	if err := json.Unmarshal([]byte(`{}`), &anchor); err == nil {
		t.Fatal("persisted data restored an age anchor")
	}
	if _, err := testCompiler(t, testBaseline()).CompileAuthorization(t.Context(), testInput(t), anchor); err == nil {
		t.Fatal("failed decoding retained an age anchor")
	}
	var missingAnchor *AgeAnchor
	if err := missingAnchor.UnmarshalJSON([]byte(`{}`)); err == nil {
		t.Fatal("nil anchor decoder accepted a sample")
	}
	authorization, err := testCompiler(t, testBaseline()).CompileAuthorization(t.Context(), testInput(t), CaptureAge())
	if err != nil {
		t.Fatal(err)
	}
	if data, err := json.Marshal(authorization); err == nil || len(data) != 0 {
		t.Fatal("process-local authorization was serialized")
	}
	if err := json.Unmarshal([]byte(`{}`), &authorization); err == nil {
		t.Fatal("persisted data restored a permit")
	}
	if _, err := authorization.Remaining(0, testNow); err == nil {
		t.Fatal("failed decoding retained previous authorization")
	}
	var missing *Authorization
	if err := missing.UnmarshalJSON([]byte(`{}`)); err == nil {
		t.Fatal("nil authorization decoder accepted a permit")
	}
}

func TestAuthorizationRejectsInvalidRequests(t *testing.T) {
	t.Parallel()
	compiler := testCompiler(t, testBaseline())
	input := testInput(t)
	invalid := input
	invalid.Directory.Complete = false
	if authorization, err := compiler.CompileAuthorization(t.Context(), invalid, CaptureAge()); err == nil ||
		authorization.data != nil {
		t.Fatal("invalid evidence produced an authorization")
	}
	authorization, err := compiler.CompileAuthorization(t.Context(), input, CaptureAge())
	if err != nil {
		t.Fatal(err)
	}
	var empty Authorization
	if _, err := empty.Remaining(0, input.Now); err == nil {
		t.Fatal("zero value authorized a grant")
	}
	if _, err := empty.Snapshot(t.Context()); err == nil {
		t.Fatal("zero value exposed a candidate")
	}
	for _, index := range []int{-1, 1} {
		if _, err := authorization.Remaining(index, input.Now); err == nil {
			t.Fatal("invalid grant index was accepted")
		}
	}
	if _, err := authorization.Remaining(0, time.Time{}); err == nil {
		t.Fatal("missing utc reading was accepted")
	}
	//nolint:staticcheck // Deliberately missing context tests the rejection boundary.
	if _, err := authorization.Snapshot(nil); err == nil {
		t.Fatal("missing context returned a candidate")
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if _, err := authorization.Snapshot(ctx); !errors.Is(err, context.Canceled) {
		t.Fatalf("snapshot ignored cancellation: %v", err)
	}
	result, err := compiler.CompileAuthorization(ctx, input, CaptureAge())
	if !errors.Is(err, context.Canceled) || result.data != nil {
		t.Fatalf("compilation ignored cancellation: %v", err)
	}
}
