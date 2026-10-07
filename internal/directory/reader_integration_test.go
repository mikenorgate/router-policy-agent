//go:build integration

package directory

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"io"
	"math/big"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	ber "github.com/go-asn1-ber/asn1-ber"
	"github.com/go-ldap/ldap/v3"
)

// Certificates and keys are generated in memory. No operational identity or
// credential is used by this disposable loopback LDAP server.
func fixtureTLS(t *testing.T, mode string) (tls.Certificate, *x509.CertPool) {
	t.Helper()
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	ca := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "Synthetic test CA"},
		NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour), IsCA: true, BasicConstraintsValid: true,
		KeyUsage: x509.KeyUsageCertSign}
	caDER, err := x509.CreateCertificate(rand.Reader, ca, ca, public, private)
	if err != nil {
		t.Fatal(err)
	}
	parsedCA, err := x509.ParseCertificate(caDER)
	if err != nil {
		t.Fatal(err)
	}
	leaf := &x509.Certificate{SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: "Synthetic LDAP"},
		NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour), IPAddresses: []net.IP{net.ParseIP("127.0.0.1")},
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	if mode == "wrong hostname" {
		leaf.IPAddresses = nil
		leaf.DNSNames = []string{"ldap.example.test"}
	}
	if mode == "expired" {
		leaf.NotAfter = now.Add(-time.Minute)
	}
	der, err := x509.CreateCertificate(rand.Reader, leaf, parsedCA, public, private)
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	if mode != "untrusted" {
		roots.AddCert(parsedCA)
	}
	return tls.Certificate{Certificate: [][]byte{der, caDER}, PrivateKey: private}, roots
}

type wireFixture struct {
	listener    net.Listener
	mu          sync.Mutex
	connections []net.Conn
	done        chan struct{}
	cancel      context.CancelFunc
}

var errExpectedTLSRejection = errors.New("synthetic client rejected TLS")

func startWireFixture(t *testing.T, certificate tls.Certificate, handler func(context.Context, *tls.Conn) error) *wireFixture {
	t.Helper()
	ctx, cancel := context.WithCancel(t.Context())
	var listenConfig net.ListenConfig
	listener, err := listenConfig.Listen(ctx, "tcp", "127.0.0.1:0")
	if err != nil {
		cancel()
		t.Fatal(err)
	}
	server := &wireFixture{listener: listener, done: make(chan struct{}), cancel: cancel}
	var workers sync.WaitGroup
	go func() {
		defer close(server.done)
		defer workers.Wait()
		for {
			connection, err := listener.Accept()
			if err != nil {
				if ctx.Err() == nil {
					t.Error("synthetic listener failed")
				}
				return
			}
			server.mu.Lock()
			if ctx.Err() != nil {
				server.mu.Unlock()
				if err := connection.Close(); err != nil {
					t.Error("late connection close failed")
				}
				return
			}
			server.connections = append(server.connections, connection)
			server.mu.Unlock()
			workers.Go(func() {
				defer func() {
					if err := connection.Close(); unexpectedClose(err) {
						t.Error("synthetic connection close failed")
					}
				}()
				tlsConnection := tls.Server(connection, &tls.Config{MinVersion: tls.VersionTLS12, Certificates: []tls.Certificate{certificate}})
				if err := handler(ctx, tlsConnection); err != nil && ctx.Err() == nil && !errors.Is(err, errExpectedTLSRejection) {
					t.Errorf("synthetic LDAP handler: %v", err)
				}
			})
		}
	}()
	t.Cleanup(func() {
		server.cancel()
		if err := listener.Close(); unexpectedClose(err) {
			t.Error("synthetic listener close failed")
		}
		server.mu.Lock()
		for _, connection := range server.connections {
			if err := connection.Close(); unexpectedClose(err) {
				t.Error("synthetic shutdown failed")
			}
		}
		server.mu.Unlock()
		select {
		case <-server.done:
		case <-time.After(2 * time.Second):
			t.Error("synthetic LDAP workers did not stop")
		}
	})
	return server
}

func wireReader(t *testing.T, server *wireFixture, roots *x509.CertPool, credentials func(context.Context) (Credentials, error)) *Reader {
	t.Helper()
	config := fixtureConfig()
	config.URL = "ldaps://" + server.listener.Addr().String()
	config.RootCAs = roots
	reader, err := New(config, credentials)
	if err != nil {
		t.Fatal(err)
	}
	return reader
}

func wireMessage(id int64, operation *ber.Packet, controls ...ldap.Control) *ber.Packet {
	message := ber.NewSequence("LDAP message")
	message.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagInteger, id, "message ID"))
	message.AppendChild(operation)
	if len(controls) != 0 {
		encoded := ber.Encode(ber.ClassContext, ber.TypeConstructed, 0, nil, "controls")
		for _, control := range controls {
			encoded.AppendChild(control.Encode())
		}
		message.AppendChild(encoded)
	}
	return message
}

func wireResult(id int64, tag ber.Tag, code uint64, controls ...ldap.Control) *ber.Packet {
	operation := ber.Encode(ber.ClassApplication, ber.TypeConstructed, tag, nil, "result")
	operation.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagEnumerated, code, "result code"))
	operation.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, "", "matched DN"))
	operation.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, "synthetic private diagnostic", "diagnostic"))
	return wireMessage(id, operation, controls...)
}

func wireEntry(id int64, entry *ldap.Entry) *ber.Packet {
	operation := ber.Encode(ber.ClassApplication, ber.TypeConstructed, 4, nil, "entry")
	operation.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, entry.DN, "DN"))
	attributes := ber.NewSequence("attributes")
	for _, attribute := range entry.Attributes {
		encoded := ber.NewSequence("attribute")
		encoded.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, attribute.Name, "name"))
		values := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSet, nil, "values")
		for _, value := range attribute.Values {
			values.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, value, "value"))
		}
		encoded.AppendChild(values)
		attributes.AppendChild(encoded)
	}
	operation.AppendChild(attributes)
	return wireMessage(id, operation)
}

func sendWire(connection net.Conn, packet *ber.Packet) error {
	data := packet.Bytes()
	for len(data) != 0 {
		n, err := connection.Write(data)
		if err != nil {
			return err
		}
		if n == 0 {
			return io.ErrShortWrite
		}
		data = data[n:]
	}
	return nil
}

func readWire(connection net.Conn) (int64, *ber.Packet, *ber.Packet, error) {
	packet, err := ber.ReadPacket(connection)
	if err != nil {
		return 0, nil, nil, err
	}
	if packet == nil || len(packet.Children) < 2 {
		return 0, nil, nil, errors.New("invalid synthetic request")
	}
	id, ok := packet.Children[0].Value.(int64)
	if !ok {
		return 0, nil, nil, errors.New("invalid synthetic ID")
	}
	return id, packet.Children[1], packet, nil
}

func TestLDAPSCollectsVerifiedPagedDataAndRotatesCredentials(t *testing.T) {
	certificate, roots := fixtureTLS(t, "valid")
	passwords := make(chan string, 2)
	server := startWireFixture(t, certificate, func(_ context.Context, connection *tls.Conn) error {
		id, operation, _, err := readWire(connection)
		if err != nil {
			return err
		}
		if operation.Tag != 0 || len(operation.Children) != 3 {
			return errors.New("not a simple bind")
		}
		passwords <- operation.Children[2].Data.String()
		if err := sendWire(connection, wireResult(id, 1, ldap.LDAPResultSuccess)); err != nil {
			return err
		}
		groups, users := fixtureEntries()
		for index := range 3 {
			id, search, packet, err := readWire(connection)
			if err != nil {
				return err
			}
			if search.Tag != 3 || len(search.Children) != 8 || len(packet.Children) != 3 ||
				len(packet.Children[2].Children) != 1 {
				return errors.New("not a bounded LDAP search")
			}
			control := packet.Children[2].Children[0]
			if len(control.Children) != 3 {
				return errors.New("missing critical paging")
			}
			critical, ok := control.Children[1].Value.(bool)
			if !ok || !critical {
				return errors.New("paging not critical on wire")
			}
			base := search.Children[0].Data.String()
			if index < 2 && base != "ou=groups,"+fixtureBase || index == 2 && base != "ou=users,"+fixtureBase {
				return errors.New("wrong search namespace")
			}
			paging := ldap.NewControlPaging(2)
			switch index {
			case 0:
				if err := sendWire(connection, wireEntry(id, groups[0])); err != nil {
					return err
				}
				paging.SetCookie([]byte("synthetic-next"))
			case 2:
				if err := sendWire(connection, wireEntry(id, users[0])); err != nil {
					return err
				}
			}
			if err := sendWire(connection, wireResult(id, 5, ldap.LDAPResultSuccess, paging)); err != nil {
				return err
			}
		}
		var one [1]byte
		if _, err := connection.Read(one[:]); !errors.Is(err, io.EOF) {
			return errors.New("client did not close after collection")
		}
		return nil
	})
	calls := 0
	reader := wireReader(t, server, roots, func(context.Context) (Credentials, error) {
		calls++
		password := "synthetic-first"
		if calls == 2 {
			password = "synthetic-second"
		}
		return Credentials{BindDN: "cn=reader,ou=users," + fixtureBase, Password: password}, nil
	})
	reader.now = func() time.Time { return fixtureTime }
	for _, expected := range []string{"synthetic-first", "synthetic-second"} {
		snapshot, err := reader.Collect(t.Context())
		if err != nil || !snapshot.Complete || len(snapshot.Devices) != 1 || !snapshot.ObservedAt.Equal(fixtureTime) {
			t.Fatalf("wire collection: %+v, %v", snapshot, err)
		}
		if password := <-passwords; password != expected {
			t.Fatal("credential rotation ignored")
		}
	}
}

func TestLDAPSRejectsUnverifiedServerBeforeSendingCredentials(t *testing.T) {
	for _, mode := range []string{"untrusted", "wrong hostname", "expired"} {
		t.Run(mode, func(t *testing.T) {
			certificate, roots := fixtureTLS(t, mode)
			var applicationBytes atomic.Int64
			server := startWireFixture(t, certificate, func(ctx context.Context, connection *tls.Conn) error {
				if err := connection.HandshakeContext(ctx); err != nil {
					return errExpectedTLSRejection
				}
				var data [256]byte
				n, _ := connection.Read(data[:])
				applicationBytes.Add(int64(n))
				return nil
			})
			reader := wireReader(t, server, roots, func(context.Context) (Credentials, error) {
				return Credentials{BindDN: "cn=reader,ou=users," + fixtureBase, Password: "synthetic-never-send"}, nil
			})
			snapshot, err := reader.Collect(t.Context())
			if !errors.Is(err, ErrRead) || snapshot.Complete || applicationBytes.Load() != 0 || strings.Contains(err.Error(), "127.0.0.1") {
				t.Fatalf("unverified TLS accepted or disclosed: %+v, %v", snapshot, err)
			}
		})
	}
}

func TestLDAPSCancellationClosesBlockedBind(t *testing.T) {
	certificate, roots := fixtureTLS(t, "valid")
	bound := make(chan struct{})
	closed := make(chan struct{})
	server := startWireFixture(t, certificate, func(_ context.Context, connection *tls.Conn) error {
		if _, _, _, err := readWire(connection); err != nil {
			return err
		}
		close(bound)
		defer close(closed)
		var one [1]byte
		if _, err := connection.Read(one[:]); !errors.Is(err, io.EOF) {
			return errors.New("cancelled client remained open")
		}
		return nil
	})
	reader := wireReader(t, server, roots, func(context.Context) (Credentials, error) {
		return Credentials{BindDN: "cn=reader,ou=users," + fixtureBase, Password: "synthetic-cancel"}, nil
	})
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	done := make(chan error, 1)
	go func() {
		snapshot, err := reader.Collect(ctx)
		if snapshot.Complete {
			done <- errors.New("cancelled snapshot accepted")
			return
		}
		done <- err
	}()
	select {
	case <-bound:
	case <-time.After(time.Second):
		t.Fatal("bind not reached")
	}
	cancel()
	select {
	case err := <-done:
		if !errors.Is(err, ErrRead) || !errors.Is(err, context.Canceled) {
			t.Fatalf("cancellation lost: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("cancellation did not join client")
	}
	select {
	case <-closed:
	case <-time.After(time.Second):
		t.Fatal("socket survived cancellation")
	}
}

func TestLDAPSDiscardsPartialLDAPResultAndRedactsDiagnostic(t *testing.T) {
	certificate, roots := fixtureTLS(t, "valid")
	server := startWireFixture(t, certificate, func(_ context.Context, connection *tls.Conn) error {
		id, _, _, err := readWire(connection)
		if err != nil {
			return err
		}
		if err := sendWire(connection, wireResult(id, 1, ldap.LDAPResultSuccess)); err != nil {
			return err
		}
		id, _, _, err = readWire(connection)
		if err != nil {
			return err
		}
		groups, _ := fixtureEntries()
		if err := sendWire(connection, wireEntry(id, groups[0])); err != nil {
			return err
		}
		if err := sendWire(connection, wireResult(id, 5, ldap.LDAPResultSizeLimitExceeded, ldap.NewControlPaging(2))); err != nil {
			return err
		}
		var one [1]byte
		if _, err := connection.Read(one[:]); !errors.Is(err, io.EOF) {
			return errors.New("failed search connection survived")
		}
		return nil
	})
	reader := wireReader(t, server, roots, func(context.Context) (Credentials, error) {
		return Credentials{BindDN: "cn=reader,ou=users," + fixtureBase, Password: "synthetic-partial"}, nil
	})
	snapshot, err := reader.Collect(t.Context())
	if !errors.Is(err, ErrRead) || snapshot.Complete || snapshot.Groups != nil || strings.Contains(err.Error(), "private diagnostic") {
		t.Fatalf("partial result escaped: %+v, %v", snapshot, err)
	}
}

func TestLDAPSRejectsMalformedResponsesWithoutParserPanic(t *testing.T) {
	for _, mode := range []string{"empty entry", "deep paging value"} {
		t.Run(mode, func(t *testing.T) {
			certificate, roots := fixtureTLS(t, "valid")
			server := startWireFixture(t, certificate, func(_ context.Context, connection *tls.Conn) error {
				id, _, _, err := readWire(connection)
				if err != nil {
					return err
				}
				if err := sendWire(connection, wireResult(id, 1, ldap.LDAPResultSuccess)); err != nil {
					return err
				}
				id, _, _, err = readWire(connection)
				if err != nil {
					return err
				}
				var response *ber.Packet
				if mode == "empty entry" {
					// This is well-framed BER but violates SearchResultEntry shape.
					response = wireMessage(id, ber.Encode(ber.ClassApplication, ber.TypeConstructed, 4, nil, "malformed entry"))
				} else {
					embedded := ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagInteger, 1, "leaf")
					for range maximumFrameDepth {
						parent := ber.NewSequence("nested")
						parent.AppendChild(embedded)
						embedded = parent
					}
					control := ldap.NewControlString(ldap.ControlTypePaging, false, string(embedded.Bytes()))
					response = wireResult(id, 5, ldap.LDAPResultSuccess, control)
				}
				if err := sendWire(connection, response); err != nil {
					return err
				}
				var one [1]byte
				if _, err := connection.Read(one[:]); !errors.Is(err, io.EOF) {
					return errors.New("malformed response connection survived")
				}
				return nil
			})
			reader := wireReader(t, server, roots, func(context.Context) (Credentials, error) {
				return Credentials{BindDN: "cn=reader,ou=users," + fixtureBase, Password: "synthetic-malformed"}, nil
			})
			snapshot, err := reader.Collect(t.Context())
			if !errors.Is(err, ErrRead) || snapshot.Complete || snapshot.Devices != nil || snapshot.Groups != nil {
				t.Fatalf("malformed response accepted: %+v, %v", snapshot, err)
			}
		})
	}
}
