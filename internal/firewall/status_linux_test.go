package firewall

import (
	"context"
	"sync/atomic"
	"testing"
	"time"
)

func TestGuardedServiceStatusRequiresSeparateIdentity(t *testing.T) {
	t.Parallel()
	var calls atomic.Int32
	options := backendOptionsFixture(t)
	options.clock = func() time.Time { calls.Add(1); return time.Now() }
	backend, err := newGuardedBackend(options)
	if err != nil {
		t.Fatal(err)
	}
	service, err := backend.newService(serviceOptionsFixture())
	if err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		name    string
		uid     uint32
		timeout time.Duration
	}{
		{name: "root", uid: 0, timeout: time.Second},
		{name: "directory writer", uid: 65534, timeout: time.Second},
		{name: "no deadline", uid: 65533},
		{name: "unbounded deadline", uid: 65533, timeout: 11 * time.Second},
	} {
		t.Run(test.name, func(t *testing.T) {
			if _, err := service.newStatusServer(test.uid, test.timeout); err == nil {
				t.Fatal("unsafe status identity or timeout accepted")
			}
		})
	}
	if _, err := service.newStatusServer(65533, time.Second); err != nil {
		t.Fatal(err)
	}
	if calls.Load() != 0 || service.hasServed.Load() {
		t.Fatal("constructing a read-only server accessed runtime state or started enforcement")
	}
	for _, service := range []*guardedService{nil, {}, {engine: service.engine},
		{engine: service.engine, backend: &guardedBackend{}}} {
		if _, err := service.newStatusServer(65533, time.Second); err == nil {
			t.Fatal("invalid status dependencies accepted")
		}
		if _, err := service.status(t.Context()); err == nil {
			t.Fatal("invalid status dependencies returned a report")
		}
	}
	var missingContext context.Context
	if _, err := service.status(missingContext); err == nil {
		t.Fatal("missing status context accepted")
	}
}
