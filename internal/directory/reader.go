// Package directory collects original Authentik entries over verified LDAPS.
// It neither supplies network bindings nor authenticates a NAS session.
package directory

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"net"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/go-ldap/ldap/v3"
	"github.com/mikenorgate/router-policy-agent/internal/policy"
)

// ErrRead deliberately excludes directory diagnostics, credentials and entries.
var ErrRead = errors.New("directory: collection failed")

// Config is private deployment configuration, never a group attribute.
// URL must be an explicit ldaps:// host and port. RootCAs nil uses system roots.
// Deployment must separately qualify direct search and reserved-field controls.
type Config struct {
	URL            string
	BaseDN         string
	RootCAs        *x509.CertPool
	Timeout        time.Duration
	PageSize       uint32
	MaximumDevices int
	MaximumGroups  int
}

// Credentials are obtained again for every collection to support rotation.
// No serializer should expose the secret or the private lookup identity.
type Credentials struct {
	BindDN   string `json:"-"`
	Password string `json:"-"`
}

// Reader owns immutable connection configuration, but caches no directory data.
// Concurrent collections use separate bounded connections and snapshots.
type Reader struct {
	config      Config
	address     string
	hostname    string
	credentials func(context.Context) (Credentials, error)
	now         func() time.Time
}

// New checks transport, namespace and quotas without connecting to a server.
// credentials must provide the separately authorized scoped read identity and
// honor cancellation. It must be safe for concurrent use if the Reader is shared.
func New(config Config, credentials func(context.Context) (Credentials, error)) (*Reader, error) {
	endpoint, err := url.Parse(config.URL)
	if err != nil || endpoint == nil {
		return nil, errors.New("directory: invalid endpoint")
	}
	isUnsafeEndpoint := endpoint.Scheme != "ldaps" || endpoint.User != nil ||
		endpoint.Path != "" || endpoint.RawQuery != "" || endpoint.Fragment != "" ||
		endpoint.Opaque != "" || endpoint.ForceQuery
	host, port, splitErr := net.SplitHostPort(endpoint.Host)
	portNumber, portErr := strconv.ParseUint(port, 10, 16)
	if isUnsafeEndpoint || splitErr != nil || portErr != nil || portNumber == 0 || host == "" {
		return nil, errors.New("directory: verified ldaps endpoint required")
	}
	base, parseErr := ldap.ParseDN(config.BaseDN)
	isBadNamespace := parseErr != nil || base == nil || len(base.RDNs) == 0 || len(config.BaseDN) > 1024
	isBadTimeout := config.Timeout <= 0 || config.Timeout > 10*time.Second
	isBadCapacity := config.MaximumDevices <= 0 || config.MaximumDevices > 4096 ||
		config.MaximumGroups <= 0 || config.MaximumGroups > 8192
	isBadPaging := config.PageSize == 0 || config.PageSize > 256
	if credentials == nil || isBadNamespace || isBadTimeout || isBadCapacity || isBadPaging {
		return nil, errors.New("directory: invalid namespace, timing or collection limits")
	}
	if config.RootCAs != nil {
		config.RootCAs = config.RootCAs.Clone()
	}
	return &Reader{
		config: config, address: endpoint.Host, hostname: host,
		credentials: credentials, now: time.Now,
	}, nil
}

type searcher interface {
	Search(*ldap.SearchRequest) (*ldap.SearchResult, error)
}

// Collect returns a complete bounded snapshot or no snapshot at all.
// Its authorization age starts before dialing and includes every read.
// Certificate/hostname failure never falls back to plaintext or another host.
func (r *Reader) Collect(ctx context.Context) (result policy.DirectorySnapshot, resultErr error) {
	if r == nil || r.credentials == nil || r.now == nil || ctx == nil {
		return policy.DirectorySnapshot{}, ErrRead
	}
	ctx, cancel := context.WithTimeout(ctx, r.config.Timeout)
	defer cancel()
	observed := r.now().UTC()
	credentials, err := r.credentials(ctx)
	if err != nil || ctx.Err() != nil || !validCredentials(credentials, r.config.BaseDN) {
		return policy.DirectorySnapshot{}, readError(ctx)
	}
	dialer := tls.Dialer{
		NetDialer: &net.Dialer{Timeout: r.config.Timeout},
		Config: &tls.Config{
			MinVersion: tls.VersionTLS12,
			ServerName: r.hostname,
			RootCAs:    r.config.RootCAs,
		},
	}
	connection, err := dialer.DialContext(ctx, "tcp", r.address)
	if err != nil {
		return policy.DirectorySnapshot{}, readError(ctx)
	}
	deadline, ok := ctx.Deadline()
	if !ok {
		if closeErr := connection.Close(); closeErr != nil {
			return policy.DirectorySnapshot{}, ErrRead
		}
		return policy.DirectorySnapshot{}, ErrRead
	}
	if err := connection.SetDeadline(deadline); err != nil {
		if closeErr := connection.Close(); closeErr != nil {
			return policy.DirectorySnapshot{}, ErrRead
		}
		return policy.DirectorySnapshot{}, ErrRead
	}
	bounded := &boundedConn{
		Conn: connection, reader: newFrameReader(connection),
	}
	client := ldap.NewConn(bounded, true)
	client.SetTimeout(r.config.Timeout)
	client.Start()
	closed := make(chan struct{})
	stop := context.AfterFunc(ctx, func() {
		// Close records the redacted failure for the joined cleanup below.
		_ = bounded.Close()
		close(closed)
	})
	defer func() {
		if !stop() {
			<-closed
		}
		// Close the socket first so blocked library I/O cannot delay joining.
		socketErr := bounded.Close()
		libraryErr := client.Close()
		if unexpectedClose(socketErr) || unexpectedClose(libraryErr) {
			result, resultErr = policy.DirectorySnapshot{}, readError(ctx)
		}
	}()
	if err := safeBind(client, credentials); err != nil {
		return policy.DirectorySnapshot{}, readError(ctx)
	}
	snapshot, err := r.collect(ctx, client, observed)
	if err != nil || ctx.Err() != nil {
		return policy.DirectorySnapshot{}, readError(ctx)
	}
	return snapshot, nil
}

// safeBind confines the dependency's response-shape assumptions to the
// untrusted LDAP boundary. A malformed server packet cannot crash the reader.
func safeBind(client *ldap.Conn, credentials Credentials) (resultErr error) {
	defer func() {
		if recover() != nil {
			resultErr = ErrRead
		}
	}()
	return client.Bind(credentials.BindDN, credentials.Password)
}

func safeSearch(client searcher, request *ldap.SearchRequest) (result *ldap.SearchResult, resultErr error) {
	defer func() {
		if recover() != nil {
			result, resultErr = nil, ErrRead
		}
	}()
	return client.Search(request)
}

func validCredentials(credentials Credentials, baseDN string) bool {
	if credentials.Password == "" || len(credentials.Password) > 4096 {
		return false
	}
	dn, err := ldap.ParseDN(credentials.BindDN)
	base, baseErr := ldap.ParseDN("ou=users," + baseDN)
	return err == nil && baseErr == nil && dn != nil && base != nil &&
		len(dn.RDNs) == len(base.RDNs)+1 && base.AncestorOfFold(dn)
}

func readError(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return errors.Join(ErrRead, err)
	}
	return ErrRead
}

// boundedConn closes the transport once even when cancellation and LDAP cleanup
// race. Its reader checks framing budgets before the library allocates a tree.
type boundedConn struct {
	net.Conn
	reader   *frameReader
	closeOne sync.Once
	closeErr error
}

func (c *boundedConn) Read(data []byte) (int, error) { return c.reader.Read(data) }

func (c *boundedConn) Close() error {
	c.closeOne.Do(func() { c.closeErr = c.Conn.Close() })
	return c.closeErr
}

func unexpectedClose(err error) bool { return err != nil && !errors.Is(err, net.ErrClosed) }

func canonicalDN(raw string) (string, error) {
	if raw == "" || len(raw) > 2048 || strings.ContainsRune(raw, '\x00') {
		return "", ErrRead
	}
	dn, err := ldap.ParseDN(raw)
	if err != nil || dn == nil || len(dn.RDNs) == 0 {
		return "", ErrRead
	}
	return strings.ToLower(dn.String()), nil
}
