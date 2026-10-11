//go:build integration

package directory

import (
	"context"
	"crypto/tls"
	"errors"
	"io"
	"testing"

	"github.com/go-ldap/ldap/v3"
)

func TestLDAPSBoundedUnpagedWireCollection(t *testing.T) {
	for _, partial := range []bool{false, true} {
		t.Run(map[bool]string{false: "complete", true: "size_limit"}[partial], func(t *testing.T) {
			certificate, roots := fixtureTLS(t, "valid")
			server := startWireFixture(t, certificate, func(_ context.Context, connection *tls.Conn) error {
				id, _, _, err := readWire(connection)
				if err != nil {
					return err
				}
				if err := sendWire(connection, wireResult(id, 1, ldap.LDAPResultSuccess)); err != nil {
					return err
				}
				groups, users := fixtureEntries()
				attribute(users[0], "ak-active").Values = []string{"TRUE"}
				for index := range 2 {
					id, search, packet, err := readWire(connection)
					if err != nil {
						return err
					}
					if search.Tag != 3 || len(search.Children) != 8 || len(packet.Children) != 2 {
						return errors.New("unpaged request contains controls or wrong shape")
					}
					limit, ok := search.Children[3].Value.(int64)
					if !ok || limit != 17 {
						return errors.New("unpaged request lacks size bound")
					}
					entry := groups[0]
					if index == 1 {
						entry = users[0]
					}
					if err := sendWire(connection, wireEntry(id, entry)); err != nil {
						return err
					}
					code := ldap.LDAPResultSuccess
					if partial {
						code = ldap.LDAPResultSizeLimitExceeded
					}
					if err := sendWire(connection, wireResult(id, 5, uint64(code))); err != nil {
						return err
					}
					if partial {
						break
					}
				}
				var one [1]byte
				if _, err := connection.Read(one[:]); !errors.Is(err, io.EOF) {
					return errors.New("client did not close")
				}
				return nil
			})
			reader := wireReader(t, server, roots, func(context.Context) (Credentials, error) {
				return Credentials{BindDN: "cn=reader,ou=users," + fixtureBase, Password: "synthetic-only"}, nil
			})
			reader.config.Unpaged = true
			snapshot, err := reader.Collect(t.Context())
			if partial {
				if !errors.Is(err, ErrRead) || snapshot.Complete {
					t.Fatal("partial wire result accepted")
				}
			} else if err != nil || !snapshot.Complete || len(snapshot.Devices) != 1 || !snapshot.Devices[0].Active {
				t.Fatal("complete unpaged wire result rejected")
			}
		})
	}
}
