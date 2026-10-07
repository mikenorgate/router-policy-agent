package reader

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"unicode"

	"github.com/mikenorgate/router-policy-agent/internal/directory"
	"github.com/mikenorgate/router-policy-agent/internal/hostfs"
	"github.com/mikenorgate/router-policy-agent/internal/strictjson"
)

const maximumConfig = 16 << 10
const maximumCredentials = 8 << 10
const maximumCA = 64 << 10

type config struct {
	SchemaVersion int    `json:"schema_version"`
	DirectoryURL  string `json:"directory_url"`
	BaseDN        string `json:"base_dn"`
	HelperSocket  string `json:"helper_socket"`
	CustomCA      bool   `json:"custom_ca"`
}

func decodeConfig(data []byte) (config, error) {
	keys := []string{"schema_version", "directory_url", "base_dn", "helper_socket", "custom_ca"}
	if err := strictjson.Object(data, keys, nil, maximumConfig); err != nil {
		return config{}, errRuntime
	}
	var parsed config
	if err := strictjson.Decode(data, &parsed, maximumConfig); err != nil {
		return config{}, errRuntime
	}
	if parsed.SchemaVersion != 1 || !privatePath(parsed.HelperSocket, 107) {
		return config{}, errRuntime
	}
	return parsed, nil
}

func privatePath(path string, maximum int) bool {
	isClean := path != "/" && filepath.IsAbs(path) && filepath.Clean(path) == path
	return isClean && len(path) <= maximum && strings.IndexFunc(path, unicode.IsControl) < 0
}

// readPrivate checks descriptor metadata before and after bounded reading.
// Fixed basenames prohibit attribute-selected paths and rotation through links.
func readPrivate(ctx context.Context, root *os.Root, owner uint32, name string, maximum int64) ([]byte, error) {
	file, err := hostfs.OpenRegular(ctx, root, hostfs.FileOptions{
		Name: name, OwnerUID: owner, MaximumSize: maximum,
	})
	if err != nil {
		return nil, errRuntime
	}
	check := func() error {
		if err := hostfs.CheckPrivateFile(file, owner, maximum); err != nil {
			return errRuntime
		}
		info, err := file.Stat()
		if err != nil {
			return errRuntime
		}
		if mode := info.Mode().Perm(); mode != 0o400 && mode != 0o600 {
			return errRuntime
		}
		return nil
	}
	if err := check(); err != nil {
		if closeErr := file.Close(); closeErr != nil {
			return nil, errRuntime
		}
		return nil, errRuntime
	}
	data, readErr := io.ReadAll(io.LimitReader(file, maximum+1))
	if err := errors.Join(readErr, check(), file.Close(), ctx.Err()); err != nil || int64(len(data)) > maximum {
		clear(data)
		return nil, errRuntime
	}
	return data, nil
}

func readCredentials(ctx context.Context, root *os.Root, owner uint32) (directory.Credentials, error) {
	data, err := readPrivate(ctx, root, owner, "credentials.json", maximumCredentials)
	if err != nil {
		return directory.Credentials{}, errRuntime
	}
	defer clear(data)
	if err := strictjson.Object(data, []string{"bind_dn", "password"}, nil, maximumCredentials); err != nil {
		return directory.Credentials{}, errRuntime
	}
	var parsed struct {
		BindDN   string `json:"bind_dn"`
		Password string `json:"password"`
	}
	if err := strictjson.Decode(data, &parsed, maximumCredentials); err != nil {
		return directory.Credentials{}, errRuntime
	}
	validName := parsed.BindDN != "" && len(parsed.BindDN) <= 2048
	validPassword := parsed.Password != "" && len(parsed.Password) <= 4096
	if !validName || !validPassword {
		return directory.Credentials{}, errRuntime
	}
	return directory.Credentials{BindDN: parsed.BindDN, Password: parsed.Password}, nil
}

func readCA(ctx context.Context, root *os.Root, owner uint32) (*x509.CertPool, error) {
	data, err := readPrivate(ctx, root, owner, "ca.pem", maximumCA)
	if err != nil {
		return nil, errRuntime
	}
	roots := x509.NewCertPool()
	var count int
	for len(bytes.TrimSpace(data)) != 0 {
		trimmed := bytes.TrimSpace(data)
		if !bytes.HasPrefix(trimmed, []byte("-----BEGIN CERTIFICATE-----")) {
			return nil, errRuntime
		}
		block, rest := pem.Decode(trimmed)
		if block == nil || block.Type != "CERTIFICATE" || len(block.Headers) != 0 {
			return nil, errRuntime
		}
		certificate, err := x509.ParseCertificate(block.Bytes)
		if err != nil || !certificate.IsCA || !certificate.BasicConstraintsValid {
			return nil, errRuntime
		}
		count++
		if count > 32 {
			return nil, errRuntime
		}
		roots.AddCert(certificate)
		data = rest
	}
	if count == 0 {
		return nil, errRuntime
	}
	return roots, nil
}
