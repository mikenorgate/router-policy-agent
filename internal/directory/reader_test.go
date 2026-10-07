package directory

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"
)

func TestNewRejectsUnsafeConfiguration(t *testing.T) {
	tests := []struct {
		name   string
		change func(*Config)
	}{
		{"plaintext", func(c *Config) { c.URL = "ldap://ldap.example.test:389" }},
		{"embedded credentials", func(c *Config) { c.URL = "ldaps://reader:secret@ldap.example.test:636" }},
		{"missing port", func(c *Config) { c.URL = "ldaps://ldap.example.test" }},
		{"zero port", func(c *Config) { c.URL = "ldaps://ldap.example.test:0" }},
		{"path", func(c *Config) { c.URL += "/users" }},
		{"query", func(c *Config) { c.URL += "?" }},
		{"fragment", func(c *Config) { c.URL += "#secret" }},
		{"empty base", func(c *Config) { c.BaseDN = "" }},
		{"invalid base", func(c *Config) { c.BaseDN = "not-a-dn" }},
		{"no timeout", func(c *Config) { c.Timeout = 0 }},
		{"excessive timeout", func(c *Config) { c.Timeout = 11 * time.Second }},
		{"no accounts", func(c *Config) { c.MaximumDevices = 0 }},
		{"too many accounts", func(c *Config) { c.MaximumDevices = 4097 }},
		{"too many groups", func(c *Config) { c.MaximumGroups = 8193 }},
		{"no paging", func(c *Config) { c.PageSize = 0 }},
		{"oversized page", func(c *Config) { c.PageSize = 257 }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			config := fixtureConfig()
			test.change(&config)
			reader, err := New(config, func(context.Context) (Credentials, error) { return Credentials{}, nil })
			if err == nil || reader != nil {
				t.Fatal("unsafe configuration accepted")
			}
			if strings.Contains(err.Error(), "secret") {
				t.Fatal("endpoint diagnostics exposed")
			}
		})
	}
	if reader, err := New(fixtureConfig(), nil); err == nil || reader != nil {
		t.Fatal("nil credential provider accepted")
	}
}

func TestCredentialsAreScopedAndNotSerialized(t *testing.T) {
	valid := Credentials{BindDN: "cn=reader,ou=users," + fixtureBase, Password: "synthetic-test-only"}
	if !validCredentials(valid, fixtureBase) {
		t.Fatal("valid scoped credentials rejected")
	}
	for _, credentials := range []Credentials{
		{BindDN: valid.BindDN}, {BindDN: "cn=reader,ou=foreign," + fixtureBase, Password: valid.Password},
		{BindDN: "cn=reader,ou=nested,ou=users," + fixtureBase, Password: valid.Password},
		{BindDN: valid.BindDN, Password: strings.Repeat("x", 4097)},
	} {
		if validCredentials(credentials, fixtureBase) {
			t.Fatal("unscoped credentials accepted")
		}
	}
	data, err := json.Marshal(valid)
	if err != nil || string(data) != "{}" {
		t.Fatalf("credentials serialized: %q, %v", data, err)
	}
}

func TestCollectRedactsCredentialFailureAndCancellation(t *testing.T) {
	reader, err := New(fixtureConfig(), func(context.Context) (Credentials, error) {
		return Credentials{}, errors.New("synthetic secret and private diagnostic")
	})
	if err != nil {
		t.Fatal(err)
	}
	snapshot, err := reader.Collect(t.Context())
	if !errors.Is(err, ErrRead) || snapshot.Complete || strings.Contains(err.Error(), "secret") {
		t.Fatalf("credential failure leaked: %+v, %v", snapshot, err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	snapshot, err = reader.Collect(ctx)
	if !errors.Is(err, ErrRead) || !errors.Is(err, context.Canceled) || snapshot.Complete {
		t.Fatal("cancellation not preserved")
	}
	var missing *Reader
	if snapshot, err := missing.Collect(t.Context()); !errors.Is(err, ErrRead) || snapshot.Complete {
		t.Fatal("nil reader accepted")
	}
}
