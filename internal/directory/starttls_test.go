package directory

import (
	"context"
	"testing"
)

func startTLSCredentials(context.Context) (Credentials, error) {
	return Credentials{BindDN: "cn=reader,ou=users," + fixtureBase, Password: "synthetic-starttls-only"}, nil
}

func TestStartTLSRequiresMatchingSuccessfulBoundedResponse(t *testing.T) {
	t.Parallel()
	valid := []byte("\x30\x0c\x02\x01\x01\x78\x07\x0a\x01\x00\x04\x00\x04\x00")
	for _, test := range []struct {
		name string
		data []byte
		want bool
	}{
		{name: "success", data: valid, want: true},
		{name: "wrong message id", data: []byte("\x30\x0c\x02\x01\x02\x78\x07\x0a\x01\x00\x04\x00\x04\x00")},
		{name: "server refusal", data: []byte("\x30\x0c\x02\x01\x01\x78\x07\x0a\x01\x02\x04\x00\x04\x00")},
		{name: "bind response instead", data: []byte("\x30\x0c\x02\x01\x01\x61\x07\x0a\x01\x00\x04\x00\x04\x00")},
		{name: "extra response field", data: []byte("\x30\x0e\x02\x01\x01\x78\x09\x0a\x01\x00\x04\x00\x04\x00\x8b\x00")},
		{name: "truncated response", data: valid[:8]},
		{name: "missing response", data: []byte{}},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			if got := validStartTLSResponse(test.data); got != test.want {
				t.Fatalf("response admitted=%v, want %v", got, test.want)
			}
		})
	}
}

func TestDirectoryStartTLSIsExplicitAndPlainLDAPRemainsRejected(t *testing.T) {
	t.Parallel()
	for _, test := range []struct {
		name string
		url  string
		want bool
	}{
		{name: "verified starttls", url: "ldap+starttls://directory.example.test:389", want: true},
		{name: "verified ldaps", url: "ldaps://directory.example.test:636", want: true},
		{name: "plaintext ldap", url: "ldap://directory.example.test:389"},
		{name: "ambiguous starttls query", url: "ldap://directory.example.test:389?starttls=true"},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			configuration := fixtureConfig()
			configuration.URL = test.url
			if _, err := New(configuration, startTLSCredentials); (err == nil) != test.want {
				t.Fatal("unexpected directory transport admission")
			}
		})
	}
}
