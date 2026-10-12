//go:build integration

package directory

import (
	"context"
	"crypto/tls"
	"errors"
	"net"
	"testing"

	"github.com/go-ldap/ldap/v3"
)

func prepareStartTLS(connection net.Conn) error {
	id, operation, _, err := readWire(connection)
	if err != nil {
		return err
	}
	if id != 1 || operation.Tag != 23 || len(operation.Children) != 1 || operation.Children[0].Data.String() != startTLSOID {
		return errors.New("unexpected anonymous upgrade request")
	}
	return sendWire(connection, wireResult(id, 24, ldap.LDAPResultSuccess))
}

func TestStartTLSCollectsOnlyAfterVerifiedUpgrade(t *testing.T) {
	certificate, roots := fixtureTLS(t, "valid")
	server := startWireFixtureWithUpgrade(t, certificate, prepareStartTLS, func(_ context.Context, connection *tls.Conn) error {
		id, operation, _, err := readWire(connection)
		if err != nil {
			return err
		}
		if operation.Tag != 0 || !connection.ConnectionState().HandshakeComplete {
			return errors.New("bind preceded verified upgrade")
		}
		if err := sendWire(connection, wireResult(id, 1, ldap.LDAPResultSuccess)); err != nil {
			return err
		}
		for range 2 {
			id, operation, _, err := readWire(connection)
			if err != nil || operation.Tag != 3 {
				return errors.New("missing post-upgrade search")
			}
			if err := sendWire(connection, wireResult(id, 5, ldap.LDAPResultSuccess, ldap.NewControlPaging(2))); err != nil {
				return err
			}
		}
		return nil
	})
	configuration := fixtureConfig()
	configuration.URL, configuration.RootCAs = "ldap+starttls://"+server.listener.Addr().String(), roots
	reader, err := New(configuration, startTLSCredentials)
	if err != nil {
		t.Fatal(err)
	}
	snapshot, err := reader.Collect(t.Context())
	if err != nil || !snapshot.Complete {
		t.Fatal("verified StartTLS collection failed")
	}
}

func TestStartTLSRejectsUnverifiedServerBeforeBind(t *testing.T) {
	for _, mode := range []string{"untrusted", "wrong hostname", "expired"} {
		t.Run(mode, func(t *testing.T) {
			t.Parallel()
			certificate, roots := fixtureTLS(t, mode)
			server := startWireFixtureWithUpgrade(t, certificate, prepareStartTLS, func(ctx context.Context, connection *tls.Conn) error {
				if err := connection.HandshakeContext(ctx); err == nil {
					return errors.New("client accepted an unverified directory")
				}
				return errExpectedTLSRejection
			})
			configuration := fixtureConfig()
			configuration.URL, configuration.RootCAs = "ldap+starttls://"+server.listener.Addr().String(), roots
			reader, err := New(configuration, startTLSCredentials)
			if err != nil {
				t.Fatal(err)
			}
			if snapshot, err := reader.Collect(t.Context()); err == nil || snapshot.Complete {
				t.Fatal("unverified directory supplied an accepted snapshot")
			}
		})
	}
}
