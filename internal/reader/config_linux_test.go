package reader

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"math"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

const syntheticConfig = `{"schema_version":1,"directory_url":"ldaps://directory.example.test:636","base_dn":"dc=example,dc=test","helper_socket":"/run/router-policy-agent/requests.sock","custom_ca":false}`

func TestDecodeConfigRejectsAmbiguousAndUnsafeSettings(t *testing.T) {
	t.Parallel()
	if parsed, err := decodeConfig([]byte(syntheticConfig)); err != nil || parsed.CustomCA {
		t.Fatal("valid private configuration rejected")
	}
	for _, test := range []struct{ name, data string }{
		{name: "unsupported schema", data: strings.Replace(syntheticConfig, `"schema_version":1`, `"schema_version":2`, 1)},
		{name: "duplicate field", data: strings.Replace(syntheticConfig, `"schema_version":1`, `"schema_version":1,"schema_version":1`, 1)},
		{name: "case variant", data: strings.Replace(syntheticConfig, `"schema_version"`, `"Schema_version"`, 1)},
		{name: "missing field", data: strings.Replace(syntheticConfig, `,"custom_ca":false`, "", 1)},
		{name: "null field", data: strings.Replace(syntheticConfig, `"custom_ca":false`, `"custom_ca":null`, 1)},
		{name: "credential injection", data: strings.Replace(syntheticConfig, `"custom_ca":false`, `"custom_ca":false,"password":"synthetic-private"`, 1)},
		{name: "relative socket", data: strings.Replace(syntheticConfig, `/run/router-policy-agent/requests.sock`, `requests.sock`, 1)},
		{name: "unclean socket", data: strings.Replace(syntheticConfig, `/run/router-policy-agent/requests.sock`, `/run/../requests.sock`, 1)},
		{name: "control character socket", data: strings.Replace(syntheticConfig, `/run/router-policy-agent/requests.sock`, `/run/\nrequests.sock`, 1)},
		{name: "oversize socket", data: strings.Replace(syntheticConfig, `/run/router-policy-agent/requests.sock`, `/`+strings.Repeat("a", 107), 1)},
		{name: "oversize document", data: strings.Repeat(" ", maximumConfig) + syntheticConfig},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			if _, err := decodeConfig([]byte(test.data)); !errors.Is(err, errRuntime) {
				t.Fatal("unsafe or ambiguous configuration accepted")
			}
		})
	}
}

func privateFixture(t *testing.T) (*os.Root, string, uint32) {
	t.Helper()
	path := t.TempDir()
	root, err := os.OpenRoot(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := root.Close(); err != nil {
			t.Error("private fixture close failed")
		}
	})
	uid := os.Geteuid()
	if uid < 0 || uint64(uid) > math.MaxUint32 {
		t.Fatal("invalid fixture owner")
		return nil, "", 0
	}
	return root, path, uint32(uid)
}

func writeFixture(t *testing.T, path, name string, data []byte) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(path, name), data, 0o600); err != nil {
		t.Fatal("private fixture write failed")
	}
}

func credentialFixture(t *testing.T, password string) []byte {
	t.Helper()
	data, err := json.Marshal(map[string]string{
		"bind_dn": "cn=reader,ou=users,dc=example,dc=test", "password": password,
	})
	if err != nil {
		t.Fatal("synthetic credential encoding failed")
	}
	return data
}

func TestCredentialsAreReopenedOnAtomicRotation(t *testing.T) {
	t.Parallel()
	root, path, owner := privateFixture(t)
	for _, name := range []string{"first-synthetic-value", "second-synthetic-value"} {
		writeFixture(t, path, "next.json", credentialFixture(t, name))
		if err := os.Rename(filepath.Join(path, "next.json"), filepath.Join(path, "credentials.json")); err != nil {
			t.Fatal("synthetic rotation failed")
		}
		credentials, err := readCredentials(t.Context(), root, owner)
		if err != nil || credentials.Password != name {
			t.Fatal("credential callback cached the old runtime file")
		}
	}
	for _, data := range []string{
		`{"bind_dn":"reader","password":""}`,
		`{"bind_dn":"reader","password":null}`,
		`{"bind_dn":"reader","Password":"synthetic"}`,
		`{"bind_dn":"reader","password":"synthetic","password":"synthetic"}`,
		`{"bind_dn":"reader","password":"synthetic","extra":true}`,
	} {
		writeFixture(t, path, "credentials.json", []byte(data))
		if _, err := readCredentials(t.Context(), root, owner); !errors.Is(err, errRuntime) {
			t.Fatal("ambiguous or invalid credentials accepted")
		}
	}
}

func TestPrivateFilesRejectLinksSpecialFilesAndUnsafeModes(t *testing.T) {
	t.Parallel()
	for _, kind := range []string{"symlink", "hard link", "directory", "fifo", "world readable", "group readable", "executable", "write only", "oversize", "wrong owner"} {
		t.Run(kind, func(t *testing.T) {
			t.Parallel()
			root, path, owner := privateFixture(t)
			name := filepath.Join(path, "reader.json")
			switch kind {
			case "symlink":
				writeFixture(t, path, "target", []byte(syntheticConfig))
				if err := os.Symlink("target", name); err != nil {
					t.Fatal("symlink fixture failed")
				}
			case "hard link":
				writeFixture(t, path, "target", []byte(syntheticConfig))
				if err := os.Link(filepath.Join(path, "target"), name); err != nil {
					t.Fatal("hard link fixture failed")
				}
			case "directory":
				if err := os.Mkdir(name, 0o700); err != nil {
					t.Fatal("directory fixture failed")
				}
			case "fifo":
				if err := syscall.Mkfifo(name, 0o600); err != nil {
					t.Fatal("fifo fixture failed")
				}
			default:
				writeFixture(t, path, "reader.json", []byte(syntheticConfig))
				mode := os.FileMode(0o600)
				switch kind {
				case "world readable":
					mode = 0o604
				case "group readable":
					mode = 0o640
				case "executable":
					mode = 0o700
				case "write only":
					mode = 0o200
				case "oversize":
					writeFixture(t, path, "reader.json", make([]byte, maximumConfig+1))
				case "wrong owner":
					owner = math.MaxUint32
				}
				if err := os.Chmod(name, mode); err != nil {
					t.Fatal("mode fixture failed")
				}
			}
			if _, err := readPrivate(t.Context(), root, owner, "reader.json", maximumConfig); !errors.Is(err, errRuntime) {
				t.Fatal("unsafe local file accepted")
			}
		})
	}
}

func caFixture(t *testing.T, isCA bool) []byte {
	t.Helper()
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal("synthetic CA key generation failed")
	}
	template := &x509.Certificate{SerialNumber: big.NewInt(1), IsCA: isCA, BasicConstraintsValid: true,
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), KeyUsage: x509.KeyUsageCertSign}
	der, err := x509.CreateCertificate(rand.Reader, template, template, public, private)
	if err != nil {
		t.Fatal("synthetic CA creation failed")
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}

func TestCustomCARequiresOnlyBoundedValidCertificateAuthorities(t *testing.T) {
	t.Parallel()
	valid := caFixture(t, true)
	for _, test := range []struct {
		name string
		data []byte
		good bool
	}{
		{name: "valid", data: valid, good: true},
		{name: "empty", data: []byte{}},
		{name: "leading junk", data: append([]byte("junk\n"), valid...)},
		{name: "trailing junk", data: append(append([]byte{}, valid...), []byte("junk")...)},
		{name: "leaf", data: caFixture(t, false)},
		{name: "malformed certificate", data: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: []byte("bad")})},
		{name: "malformed pem", data: []byte("-----BEGIN CERTIFICATE-----\nbad")},
		{name: "too many authorities", data: []byte(strings.Repeat(string(valid), 33))},
		{name: "too much data", data: make([]byte, maximumCA+1)},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			root, path, owner := privateFixture(t)
			writeFixture(t, path, "ca.pem", test.data)
			pool, err := readCA(t.Context(), root, owner)
			if test.good && (err != nil || pool == nil) || !test.good && !errors.Is(err, errRuntime) {
				t.Fatal("unexpected custom CA validation outcome")
			}
		})
	}
}

func TestRunRejectsPrivilegedIdentityAndMissingConfiguration(t *testing.T) {
	t.Parallel()
	if err := Run(t.Context(), "/synthetic/missing", io.Discard); !errors.Is(err, errRuntime) {
		t.Fatal("missing configuration or root identity accepted")
	}
	var missingContext context.Context
	if Run(missingContext, "/synthetic/missing", io.Discard) == nil || Run(t.Context(), "/", io.Discard) == nil ||
		Run(t.Context(), "/synthetic/missing", nil) == nil {
		t.Fatal("invalid runtime dependencies accepted")
	}
	root, path, owner := privateFixture(t)
	writeFixture(t, path, "reader.json", []byte(syntheticConfig))
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if _, err := readPrivate(ctx, root, owner, "reader.json", maximumConfig); !errors.Is(err, errRuntime) {
		t.Fatal("canceled read accepted")
	}
}

func TestLoadReaderValidatesTransportAndTrustBeforeConnecting(t *testing.T) {
	t.Parallel()
	for _, test := range []struct {
		name, data string
		good       bool
		ca         bool
	}{
		{name: "system trust", data: syntheticConfig, good: true},
		{name: "custom trust", data: strings.Replace(syntheticConfig, `"custom_ca":false`, `"custom_ca":true`, 1), good: true, ca: true},
		{name: "missing ca", data: strings.Replace(syntheticConfig, `"custom_ca":false`, `"custom_ca":true`, 1)},
		{name: "bad config", data: `{}`},
		{name: "plaintext", data: strings.Replace(syntheticConfig, "ldaps://", "ldap://", 1)},
		{name: "credentials in url", data: strings.Replace(syntheticConfig, "ldaps://", "ldaps://reader:synthetic@", 1)},
		{name: "missing namespace", data: strings.Replace(syntheticConfig, "dc=example,dc=test", "", 1)},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			root, path, owner := privateFixture(t)
			writeFixture(t, path, "reader.json", []byte(test.data))
			if test.ca {
				writeFixture(t, path, "ca.pem", caFixture(t, true))
			}
			collector, socket, err := loadReader(t.Context(), root, owner)
			if test.good {
				if err != nil || collector == nil || socket != "/run/router-policy-agent/requests.sock" {
					t.Fatal("valid reader configuration did not load")
				}
				// The missing runtime credential is reread at collection time;
				// static configuration cannot cache or fabricate a bind secret.
				if snapshot, err := collector.Collect(t.Context()); err == nil || snapshot.Complete {
					t.Fatal("reader collected without the separately projected credential")
				}
				return
			}
			if !errors.Is(err, errRuntime) || collector != nil || socket != "" {
				t.Fatal("unsafe transport or configuration produced a reader")
			}
		})
	}
	root, _, owner := privateFixture(t)
	if collector, socket, err := loadReader(t.Context(), root, owner); err == nil || collector != nil || socket != "" {
		t.Fatal("missing reader configuration accepted")
	}
}

func FuzzReaderConfig(f *testing.F) {
	f.Add([]byte(syntheticConfig))
	f.Add([]byte(`{"schema_version":1,"schema_version":2}`))
	f.Fuzz(func(t *testing.T, data []byte) {
		parsed, err := decodeConfig(data)
		if err == nil && (parsed.SchemaVersion != 1 || !privatePath(parsed.HelperSocket, 107)) {
			t.Fatal("configuration invariants lost")
		}
	})
}
