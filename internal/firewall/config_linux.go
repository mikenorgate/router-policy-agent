package firewall

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"unicode"

	"github.com/mikenorgate/router-policy-agent/internal/agent"
	"github.com/mikenorgate/router-policy-agent/internal/hostfs"
	"github.com/mikenorgate/router-policy-agent/internal/strictjson"
)

const helperConfigFile = "helper.json"
const maximumHelperConfig = 16 << 10

// helperConfig belongs to the privileged integration, never reader IPC. The
// profile pin and expected vector must come from its independently verified
// release/configuration, not be learned from live files or firewall listings.
// It cannot initialize state, override clocks, supply bindings or select hooks.
type helperConfig struct {
	SchemaVersion      int              `json:"schema_version"`
	Mode               agent.Mode       `json:"mode"`
	Profile            helperProfile    `json:"profile"`
	GenerationDir      string           `json:"generation_directory"`
	StateDir           string           `json:"state_directory"`
	NFTExecutable      string           `json:"nft_executable"`
	ReaderUID          uint32           `json:"reader_uid"`
	OperatorUID        uint32           `json:"operator_uid"`
	RequestTimeoutMS   uint32           `json:"request_timeout_ms"`
	RequestSocket      string           `json:"request_socket"`
	StatusSocket       string           `json:"status_socket"`
	ExpectedGeneration writerGeneration `json:"expected_generation"`
}

type helperProfile struct {
	Directory string `json:"directory"`
	SHA256    string `json:"sha256"`
}

func decodeHelperConfig(ctx context.Context, data []byte) (helperConfig, error) {
	if ctx == nil {
		return helperConfig{}, errors.New("firewall: missing helper configuration context")
	}
	if err := ctx.Err(); err != nil {
		return helperConfig{}, err
	}
	keys := []string{
		"schema_version", "mode", "profile", "generation_directory", "state_directory", "nft_executable",
		"reader_uid", "operator_uid", "request_timeout_ms", "request_socket", "status_socket", "expected_generation",
	}
	if err := strictjson.Object(data, keys, nil, maximumHelperConfig); err != nil {
		return helperConfig{}, profileFailure("helper configuration structure invalid", err)
	}
	object := map[string]json.RawMessage{}
	if err := strictjson.Decode(data, &object, maximumHelperConfig); err != nil {
		return helperConfig{}, profileFailure("helper configuration schema invalid", err)
	}
	if err := strictjson.Object(object["profile"], []string{"directory", "sha256"}, nil, maximumHelperConfig); err != nil {
		return helperConfig{}, profileFailure("helper profile structure invalid", err)
	}
	if _, err := decodeWriterGeneration(object["expected_generation"]); err != nil {
		return helperConfig{}, profileFailure("helper generation invalid", err)
	}
	var config helperConfig
	if err := strictjson.Decode(data, &config, maximumHelperConfig); err != nil {
		return helperConfig{}, profileFailure("helper configuration schema invalid", err)
	}
	if err := config.validate(); err != nil {
		return helperConfig{}, err
	}
	if err := ctx.Err(); err != nil {
		return helperConfig{}, err
	}
	return config, nil
}

func (c helperConfig) validate() error {
	if c.Mode != agent.Shadow && c.Mode != agent.Enforce {
		return errors.New("firewall: helper requires an explicit valid mode")
	}
	validIDs := c.ReaderUID != 0 && c.OperatorUID != 0 && c.ReaderUID != c.OperatorUID
	validTimeout := c.RequestTimeoutMS > 0 && c.RequestTimeoutMS <= 10_000
	if c.SchemaVersion != 1 || !validIDs || !validTimeout || !generationHash(c.Profile.SHA256) {
		return errors.New("firewall: invalid helper configuration bounds")
	}
	if err := c.ExpectedGeneration.validate(); err != nil {
		return err
	}
	if !c.ExpectedGeneration.Ready {
		return errors.New("firewall: helper expected generation must be ready")
	}
	for _, path := range []string{c.Profile.Directory, c.GenerationDir, c.StateDir, c.NFTExecutable} {
		if !helperPath(path, 4096) {
			return errors.New("firewall: helper requires clean absolute private resource paths")
		}
	}
	validSockets := helperPath(c.RequestSocket, 107) && helperPath(c.StatusSocket, 107)
	if !validSockets || c.RequestSocket == c.StatusSocket {
		return errors.New("firewall: helper requires distinct absolute socket paths")
	}
	// State owns an exclusive .lock; resources must not share/overlap private
	// roots. Socket access must not require exposing state/profile directories.
	directories := []string{c.Profile.Directory, c.GenerationDir, c.StateDir}
	for i, directory := range directories {
		for _, other := range directories[i+1:] {
			if helperContains(directory, other) || helperContains(other, directory) {
				return errors.New("firewall: helper private resource directories overlap")
			}
		}
		if helperContains(directory, c.RequestSocket) || helperContains(directory, c.StatusSocket) {
			return errors.New("firewall: helper socket overlaps a private resource directory")
		}
	}
	return nil
}

func helperPath(path string, maximum int) bool {
	validShape := path != "/" && filepath.IsAbs(path) && filepath.Clean(path) == path
	return validShape && len(path) <= maximum && strings.IndexFunc(path, unicode.IsControl) < 0
}

func helperContains(directory, path string) bool {
	return path == directory || strings.HasPrefix(path, directory+string(filepath.Separator))
}

// loadHelperConfig opens one fixed, bounded, private root-owned file. It neither
// reads neighboring deployment files nor performs activation. File ownership
// is not release authentication or proof that /var is encrypted and persistent.
func loadHelperConfig(ctx context.Context, directory string) (helperConfig, error) {
	if ctx == nil {
		return helperConfig{}, errors.New("firewall: missing helper configuration context")
	}
	if err := ctx.Err(); err != nil {
		return helperConfig{}, err
	}
	if os.Geteuid() != 0 {
		return helperConfig{}, errors.New("firewall: helper configuration loading requires root")
	}
	root, err := hostfs.OpenDirectory(ctx, hostfs.DirectoryOptions{Path: directory, OwnerUID: 0, Private: true})
	if err != nil {
		return helperConfig{}, profileFailure("helper configuration directory unavailable", err)
	}
	file, err := hostfs.OpenRegular(ctx, root, hostfs.FileOptions{
		Name: helperConfigFile, OwnerUID: 0, MaximumSize: maximumHelperConfig,
	})
	if err != nil {
		return helperConfig{}, profileFailure("helper configuration file unavailable", errors.Join(err, root.Close()))
	}
	check := func() error {
		if err := hostfs.CheckPrivateFile(file, 0, maximumHelperConfig); err != nil {
			return err
		}
		info, err := file.Stat()
		if err != nil {
			return err
		}
		if mode := info.Mode().Perm(); mode != 0o400 && mode != 0o600 {
			return errors.New("firewall: helper configuration must be owner-readable and private")
		}
		return nil
	}
	if err := check(); err != nil {
		return helperConfig{}, profileFailure("helper configuration metadata invalid", errors.Join(err, file.Close(), root.Close()))
	}
	data, readErr := io.ReadAll(io.LimitReader(file, maximumHelperConfig+1))
	if err := errors.Join(readErr, check(), file.Close(), root.Close(), ctx.Err()); err != nil {
		return helperConfig{}, profileFailure("helper configuration read failed", err)
	}
	return decodeHelperConfig(ctx, data)
}
