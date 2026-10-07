//go:build integration

package cli

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"math/big"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	ber "github.com/go-asn1-ber/asn1-ber"
	"github.com/go-ldap/ldap/v3"
	"github.com/mikenorgate/router-policy-agent/internal/ipc"
	"github.com/mikenorgate/router-policy-agent/internal/policy"
)

func TestConfiguredNonRootReaderUsesLDAPSAndAuthenticatedIPC(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("cross-uid runtime qualification requires an isolated root test runner")
	}
	for _, mode := range []string{"verified", "untrusted tls", "helper rejection"} {
		t.Run(mode, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
			defer cancel()
			root, err := os.MkdirTemp("", "rpa-reader-")
			if err != nil {
				t.Fatal("runtime fixture creation failed")
			}
			// #nosec G302 -- The synthetic reader must traverse the root-owned fixture.
			if err := os.Chmod(root, 0o755); err != nil {
				t.Fatal("runtime fixture traversal failed")
			}
			t.Cleanup(func() {
				if err := os.RemoveAll(root); err != nil {
					t.Error("runtime fixture cleanup failed")
				}
			})
			private := filepath.Join(root, "private")
			if err := os.Mkdir(private, 0o700); err != nil {
				t.Fatal("reader private root creation failed")
			}
			if err := os.Chown(private, 65534, 65534); err != nil {
				t.Fatal("reader private root ownership failed")
			}
			certificate, ca := readerTLSFixture(t)
			var listenConfig net.ListenConfig
			ldapListener, err := listenConfig.Listen(ctx, "tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatal("loopback directory listener failed")
			}
			started := time.Now().UTC()
			ldapDone := make(chan error, 1)
			go func() { ldapDone <- serveReaderLDAP(ctx, ldapListener, certificate, mode) }()
			t.Cleanup(func() {
				if err := ldapListener.Close(); err != nil && !errors.Is(err, net.ErrClosed) {
					t.Error("directory listener cleanup failed")
				}
				if err := <-ldapDone; err != nil {
					t.Error("synthetic directory exchange failed")
				}
			})
			socket := filepath.Join(root, "helper.sock")
			listener, err := net.ListenUnix("unix", &net.UnixAddr{Name: socket, Net: "unix"})
			if err != nil {
				t.Fatal("helper fixture listener failed")
			}
			if err := os.Chown(socket, 0, 65534); err != nil {
				t.Fatal("helper fixture group failed")
			}
			// #nosec G302 -- Only the separately pinned non-root reader group connects.
			if err := os.Chmod(socket, 0o660); err != nil {
				t.Fatal("helper fixture socket mode failed")
			}
			observations := make(chan policy.DirectorySnapshot, 1)
			server, err := ipc.NewServer(ipc.ServerOptions{ReaderUID: 65534, Timeout: time.Second},
				func(_ context.Context, snapshot policy.DirectorySnapshot) (ipc.Receipt, error) {
					observations <- snapshot
					if mode == "helper rejection" {
						return ipc.Receipt{}, errors.New("synthetic-private-helper-diagnostic")
					}
					return ipc.Receipt{SchemaVersion: 1, Status: ipc.StatusShadow,
						BaselineHash: strings.Repeat("a", 64), CompiledAt: time.Now().UTC(), DenialCount: 1}, nil
				})
			if err != nil {
				t.Fatal("helper fixture configuration failed")
			}
			helperContext, stopHelper := context.WithCancel(ctx)
			helperDone := make(chan error, 1)
			go func() { helperDone <- server.Serve(helperContext, listener) }()
			t.Cleanup(func() {
				stopHelper()
				if err := <-helperDone; !errors.Is(err, context.Canceled) && !errors.Is(err, context.DeadlineExceeded) {
					t.Error("helper fixture cleanup failed")
				}
			})
			configuration, err := json.Marshal(map[string]any{
				"schema_version": 1, "directory_url": "ldaps://" + ldapListener.Addr().String(),
				"base_dn": "dc=example,dc=test", "helper_socket": socket, "custom_ca": mode != "untrusted tls",
			})
			if err != nil {
				t.Fatal("reader fixture configuration encoding failed")
			}
			for name, contents := range map[string][]byte{
				"reader.json": configuration, "ca.pem": ca,
				"credentials.json": []byte(`{"bind_dn":"cn=reader,ou=users,dc=example,dc=test","password":"synthetic-runtime-test-only"}`),
			} {
				path := filepath.Join(private, name)
				if err := os.WriteFile(path, contents, 0o600); err != nil {
					t.Fatal("reader fixture file write failed")
				}
				if err := os.Chown(path, 65534, 65534); err != nil {
					t.Fatal("reader fixture file ownership failed")
				}
			}
			executable := copyReaderExecutable(t, root)
			// #nosec G204 -- Execute only the current test binary copied into its new root.
			command := exec.CommandContext(ctx, executable, "-test.run=^TestConfiguredReaderChild$", "-test.v")
			command.Env = append(os.Environ(), "RPA_READER_CHILD=1", "RPA_READER_CONFIG="+private, "RPA_READER_MODE="+mode)
			command.SysProcAttr = &syscall.SysProcAttr{Credential: &syscall.Credential{Uid: 65534, Gid: 65534}}
			output, err := command.CombinedOutput()
			if err != nil {
				t.Fatal("configured non-root reader process failed")
			}
			if bytes.Contains(output, []byte("synthetic-runtime-test-only")) ||
				bytes.Contains(output, []byte("synthetic-private-helper")) || bytes.Contains(output, []byte(private)) {
				t.Fatal("reader process disclosed private data")
			}
			if mode == "untrusted tls" {
				if len(observations) != 0 {
					t.Fatal("unverified directory reached the helper")
				}
				return
			}
			select {
			case snapshot := <-observations:
				if !snapshot.Complete || snapshot.ObservedAt.Before(started) || snapshot.ObservedAt.After(time.Now().UTC()) ||
					len(snapshot.Groups) != 1 || len(snapshot.Devices) != 1 || snapshot.Devices[0].Active ||
					snapshot.Devices[0].MAC != "02:00:00:00:00:01" || snapshot.Groups[0].ID != "placement-id" {
					t.Fatal("actual runtime did not submit original groups and inactive identity")
				}
			case <-ctx.Done():
				t.Fatal("actual runtime never reached the pinned helper")
			}
		})
	}
}

type readerOutcomeWriter struct {
	output bytes.Buffer
	cancel context.CancelFunc
}

func (w *readerOutcomeWriter) Write(data []byte) (int, error) {
	n, err := w.output.Write(data)
	if err == nil {
		w.cancel()
	}
	return n, err
}

func TestConfiguredReaderChild(t *testing.T) {
	if os.Getenv("RPA_READER_CHILD") != "1" {
		t.Skip("cross-uid reader subprocess entry point")
	}
	if os.Geteuid() != 65534 || os.Getuid() != 65534 {
		t.Fatal("reader subprocess retained privilege")
	}
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	diagnostics := &readerOutcomeWriter{cancel: cancel}
	var out bytes.Buffer
	code := RunReader(ctx, []string{"-config-directory", os.Getenv("RPA_READER_CONFIG")},
		CheckIO{Out: &out, Err: diagnostics})
	if code != 0 || out.Len() != 0 {
		t.Fatal("configured reader did not stop cleanly after its first outcome")
	}
	var result struct {
		SchemaVersion int    `json:"schema_version"`
		Outcome       string `json:"outcome"`
		GrantCount    int    `json:"grant_count"`
		DenialCount   int    `json:"denial_count"`
	}
	if err := json.Unmarshal(diagnostics.output.Bytes(), &result); err != nil {
		t.Fatal("reader diagnostics were not one bounded JSON outcome")
	}
	expected := "shadow"
	switch os.Getenv("RPA_READER_MODE") {
	case "untrusted tls":
		expected = "collection_failed"
	case "helper rejection":
		expected = "rejected"
	}
	if result.SchemaVersion != 1 || result.Outcome != expected || result.GrantCount != 0 {
		t.Fatal("reader treated a failed or shadow attempt as authorization")
	}
}

func copyReaderExecutable(t *testing.T, root string) string {
	t.Helper()
	path, err := os.Executable()
	if err != nil {
		t.Fatal("test executable lookup failed")
	}
	// #nosec G304 -- The source is exactly os.Executable, not external input.
	source, err := os.Open(path)
	if err != nil {
		t.Fatal("test executable open failed")
	}
	defer func() {
		if err := source.Close(); err != nil {
			t.Error("test executable close failed")
		}
	}()
	path = filepath.Join(root, "reader.test")
	// #nosec G302 G304 -- Fixed executable basename in a new test-only root; O_EXCL prevents substitution.
	destination, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o755)
	if err != nil {
		t.Fatal("test executable copy creation failed")
	}
	_, copyErr := io.Copy(destination, source)
	if err := errors.Join(copyErr, destination.Close()); err != nil {
		t.Fatal("test executable copy failed")
	}
	return path
}

func readerTLSFixture(t *testing.T) (tls.Certificate, []byte) {
	t.Helper()
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal("synthetic TLS key generation failed")
	}
	now := time.Now()
	ca := &x509.Certificate{SerialNumber: big.NewInt(1), IsCA: true, BasicConstraintsValid: true,
		NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour), KeyUsage: x509.KeyUsageCertSign}
	caDER, err := x509.CreateCertificate(rand.Reader, ca, ca, public, private)
	if err != nil {
		t.Fatal("synthetic TLS authority creation failed")
	}
	leaf := &x509.Certificate{SerialNumber: big.NewInt(2), NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour),
		IPAddresses: []net.IP{net.ParseIP("127.0.0.1")}, KeyUsage: x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	leafDER, err := x509.CreateCertificate(rand.Reader, leaf, ca, public, private)
	if err != nil {
		t.Fatal("synthetic TLS leaf creation failed")
	}
	return tls.Certificate{Certificate: [][]byte{leafDER, caDER}, PrivateKey: private},
		pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER})
}

// serveReaderLDAP handles exactly one bind and two fixed searches. The fixture
// key/credential never comes from a deployment and all I/O has a short deadline.
func serveReaderLDAP(ctx context.Context, listener net.Listener, certificate tls.Certificate, mode string) error {
	raw, err := listener.Accept()
	if err != nil {
		return err
	}
	connection := tls.Server(raw, &tls.Config{MinVersion: tls.VersionTLS12, Certificates: []tls.Certificate{certificate}})
	defer func() {
		// Any close failure is harmless after this test connection's deadline.
		_ = connection.Close()
	}()
	if err := connection.SetDeadline(time.Now().Add(4 * time.Second)); err != nil {
		return err
	}
	if err := connection.HandshakeContext(ctx); err != nil {
		if mode == "untrusted tls" {
			return nil
		}
		return err
	}
	for index, tag := range []ber.Tag{1, 5, 5} {
		request, err := ber.ReadPacket(connection)
		if err != nil || request == nil || len(request.Children) < 2 {
			return errors.New("synthetic directory request missing")
		}
		operation := request.Children[1]
		if index == 0 && operation.Tag != 0 || index > 0 && operation.Tag != 3 {
			return errors.New("synthetic directory request unexpected")
		}
		id, ok := request.Children[0].Value.(int64)
		if !ok {
			return errors.New("synthetic directory request identity invalid")
		}
		if index > 0 {
			if err := sendReaderPacket(connection, readerWireEntry(id, index)); err != nil {
				return err
			}
		}
		result := ber.Encode(ber.ClassApplication, ber.TypeConstructed, tag, nil, "result")
		result.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagEnumerated, 0, "success"))
		result.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, "", "matched"))
		result.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, "", "diagnostic"))
		message := readerWireMessage(id, result)
		if index > 0 {
			controls := ber.Encode(ber.ClassContext, ber.TypeConstructed, 0, nil, "controls")
			controls.AppendChild(ldap.NewControlPaging(256).Encode())
			message.AppendChild(controls)
		}
		if err := sendReaderPacket(connection, message); err != nil {
			return err
		}
	}
	return nil
}

func readerWireMessage(id int64, operation *ber.Packet) *ber.Packet {
	message := ber.NewSequence("message")
	message.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagInteger, id, "id"))
	message.AppendChild(operation)
	return message
}

func readerWireEntry(id int64, index int) *ber.Packet {
	const userDN = "cn=02:00:00:00:00:01,ou=users,dc=example,dc=test"
	const groupDN = "cn=vlan-untrusted,ou=groups,dc=example,dc=test"
	dn := groupDN
	attributes := map[string][]string{
		"uid": {"placement-id"}, "cn": {"vlan-untrusted"}, "objectClass": {"goauthentik.io/ldap/group"},
		"member": {userDN}, policy.Attribute: {`{"schema_version":1,"kind":"placement","vlan_role":"untrusted"}`},
	}
	if index == 2 {
		dn = userDN
		attributes = map[string][]string{
			"uid": {"device-id"}, "cn": {"02:00:00:00:00:01"}, "objectClass": {"goauthentik.io/ldap/user"},
			"ak-active": {"false"}, "memberOf": {groupDN},
		}
	}
	entry := ber.Encode(ber.ClassApplication, ber.TypeConstructed, 4, nil, "entry")
	entry.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, dn, "dn"))
	encoded := ber.NewSequence("attributes")
	for name, values := range attributes {
		attribute := ber.NewSequence("attribute")
		attribute.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, name, "name"))
		set := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSet, nil, "values")
		for _, value := range values {
			set.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, value, "value"))
		}
		attribute.AppendChild(set)
		encoded.AppendChild(attribute)
	}
	entry.AppendChild(encoded)
	return readerWireMessage(id, entry)
}

func sendReaderPacket(connection net.Conn, packet *ber.Packet) error {
	data := packet.Bytes()
	n, err := connection.Write(data)
	if err != nil {
		return err
	}
	if n != len(data) {
		return io.ErrShortWrite
	}
	return nil
}
