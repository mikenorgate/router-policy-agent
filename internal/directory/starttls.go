package directory

import (
	"bytes"
	"context"
	"crypto/tls"
	"net"
	"net/url"
)

// The only cleartext operation is this fixed anonymous StartTLS request. It
// carries no identity, credential, search or directory-controlled field.
const startTLSRequest = "\x30\x1d\x02\x01\x01\x77\x18\x80\x161.3.6.1.4.1.1466.20037"
const startTLSOID = "1.3.6.1.4.1.1466.20037"

func (r *Reader) dialVerified(ctx context.Context) (net.Conn, error) {
	configuration := &tls.Config{
		MinVersion: tls.VersionTLS12, ServerName: r.hostname, RootCAs: r.config.RootCAs,
	}
	dialer := &net.Dialer{Timeout: r.config.Timeout}
	endpoint, err := url.Parse(r.config.URL)
	if err != nil {
		return nil, ErrRead
	}
	if endpoint.Scheme == "ldaps" {
		tlsDialer := tls.Dialer{NetDialer: dialer, Config: configuration}
		return tlsDialer.DialContext(ctx, "tcp", r.address)
	}
	if endpoint.Scheme != "ldap+starttls" {
		return nil, ErrRead
	}
	connection, err := dialer.DialContext(ctx, "tcp", r.address)
	if err != nil {
		return nil, ErrRead
	}
	closed := make(chan struct{})
	stop := context.AfterFunc(ctx, func() {
		// The failed/cancelled operation always returns ErrRead. Closing the
		// socket here interrupts the bounded anonymous negotiation immediately.
		_ = connection.Close()
		close(closed)
	})
	defer func() {
		if !stop() {
			<-closed
		}
	}()
	deadline, ok := ctx.Deadline()
	if !ok || connection.SetDeadline(deadline) != nil {
		return nil, closeFailedTLS(connection)
	}
	if err := negotiateStartTLS(connection); err != nil || ctx.Err() != nil {
		return nil, closeFailedTLS(connection)
	}
	secured := tls.Client(connection, configuration)
	if err := secured.HandshakeContext(ctx); err != nil {
		return nil, closeFailedTLS(secured)
	}
	return secured, nil
}

func closeFailedTLS(connection net.Conn) error {
	if err := connection.Close(); unexpectedClose(err) {
		return ErrRead
	}
	return ErrRead
}

// Negotiate before starting the LDAP library, so its BER-limited reader never
// sees TLS handshake bytes. A bounded single response must match request ID 1
// and report success; referrals, controls and unexpected payloads are rejected.
func negotiateStartTLS(connection net.Conn) error {
	if connection == nil {
		return ErrRead
	}
	n, err := connection.Write([]byte(startTLSRequest))
	if err != nil || n != len(startTLSRequest) {
		return ErrRead
	}
	response, err := newFrameReader(connection).frame()
	if err != nil || !validStartTLSResponse(response) {
		return ErrRead
	}
	return nil
}

func validStartTLSResponse(response []byte) bool {
	message, ok := frameChildren(response, 2)
	if !ok || len(message) != 2 || message[1][0] != 0x78 {
		return false
	}
	id, ok := frameValue(message[0], 0x02)
	if !ok || !bytes.Equal(id, []byte{1}) {
		return false
	}
	fields, ok := frameChildren(message[1], 4)
	if !ok || len(fields) < 3 {
		return false
	}
	result, validResult := frameValue(fields[0], 0x0a)
	matched, validMatched := frameValue(fields[1], 0x04)
	diagnostic, validDiagnostic := frameValue(fields[2], 0x04)
	isSuccess := validResult && bytes.Equal(result, []byte{0})
	isEmptyDN := validMatched && len(matched) == 0
	isDiagnostic := validDiagnostic && len(diagnostic) <= 1024
	if !isSuccess || !isEmptyDN || !isDiagnostic {
		return false
	}
	if len(fields) == 4 {
		name, ok := frameValue(fields[3], 0x8a)
		return ok && string(name) == startTLSOID
	}
	return true
}
