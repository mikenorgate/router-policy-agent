package radius

import (
	"context"
	"errors"
	"io"
	"net/netip"
	"os"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"time"
	"unicode"

	"github.com/mikenorgate/router-policy-agent/internal/hostfs"
	"github.com/mikenorgate/router-policy-agent/internal/kea"
	"github.com/mikenorgate/router-policy-agent/internal/strictjson"
)

const maximumRuntimeConfig = 16 << 10

var errRuntime = errors.New("radius: shadow runtime unavailable")

type runtimeConfig struct {
	SchemaVersion   int      `json:"schema_version"`
	Mode            string   `json:"mode"`
	RadiusUser      string   `json:"radius_user"`
	NASPrefixes     []string `json:"nas_prefixes"`
	KeaUser         string   `json:"kea_user"`
	KeaSocket       string   `json:"kea_socket"`
	SubnetID        uint32   `json:"subnet_id"`
	IPv4Prefix      string   `json:"ipv4_prefix"`
	VLAN            uint16   `json:"vlan"`
	MaximumDevices  int      `json:"maximum_devices"`
	OutputDirectory string   `json:"output_directory"`
}

// RunShadow performs one root-only, bounded collection from collector.json in
// an existing private root-owned directory. It resolves service accounts from
// the host, never the directory, and publishes only the distinct shadow schema.
// There is no enforcement mode, helper connection, environment configuration,
// credential access, network listener or caller-selected command.
func RunShadow(ctx context.Context, configDirectory string) (Collection, error) {
	return runShadow(ctx, configDirectory, PublishIPv4)
}

func runShadow(
	ctx context.Context,
	configDirectory string,
	publish func(context.Context, CollectorOptions, string) (Collection, error),
) (collected Collection, result error) {
	if ctx == nil || os.Getuid() != 0 || os.Geteuid() != 0 || publish == nil {
		return Collection{}, errRuntime
	}
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	root, err := hostfs.OpenDirectory(ctx, hostfs.DirectoryOptions{
		Path: configDirectory, OwnerUID: 0, Private: true,
	})
	if err != nil {
		return Collection{}, errors.Join(errRuntime, ctx.Err())
	}
	defer func() {
		if err := root.Close(); err != nil {
			collected, result = Collection{}, errRuntime
		}
	}()
	file, err := hostfs.OpenRegular(ctx, root, hostfs.FileOptions{
		Name: "collector.json", OwnerUID: 0, MaximumSize: maximumRuntimeConfig,
	})
	if err != nil {
		return Collection{}, errRuntime
	}
	data, readErr := io.ReadAll(io.LimitReader(file, maximumRuntimeConfig+1))
	checkErr := hostfs.CheckPrivateFile(file, 0, maximumRuntimeConfig)
	if err := errors.Join(readErr, checkErr, file.Close(), ctx.Err()); err != nil {
		return Collection{}, errors.Join(errRuntime, ctx.Err())
	}
	configuration, err := decodeRuntimeConfig(data)
	if err != nil {
		return Collection{}, errRuntime
	}
	options, err := configuration.options()
	if err != nil {
		return Collection{}, errRuntime
	}
	collected, err = publish(ctx, options, configuration.OutputDirectory)
	if err != nil || ctx.Err() != nil {
		return Collection{}, errors.Join(errRuntime, ctx.Err())
	}
	return collected, nil
}

func decodeRuntimeConfig(data []byte) (runtimeConfig, error) {
	keys := []string{"schema_version", "mode", "radius_user", "nas_prefixes", "kea_user", "kea_socket",
		"subnet_id", "ipv4_prefix", "vlan", "maximum_devices", "output_directory"}
	if err := strictjson.Object(data, keys, nil, maximumRuntimeConfig); err != nil {
		return runtimeConfig{}, errRuntime
	}
	var configuration runtimeConfig
	if err := strictjson.Decode(data, &configuration, maximumRuntimeConfig); err != nil {
		return runtimeConfig{}, errRuntime
	}
	isSchema := configuration.SchemaVersion == 1 && configuration.Mode == "shadow"
	isUsers := localUser(configuration.RadiusUser) && localUser(configuration.KeaUser)
	isOutput := runtimePath(configuration.OutputDirectory, 4096)
	if !isSchema || !isUsers || !isOutput {
		return runtimeConfig{}, errRuntime
	}
	if _, err := configuration.collectorOptions(); err != nil {
		return runtimeConfig{}, errRuntime
	}
	return configuration, nil
}

func (c runtimeConfig) collectorOptions() (CollectorOptions, error) {
	options := CollectorOptions{
		Journal: JournalOptions{NASPrefixes: []netip.Prefix{}, Timeout: 5 * time.Second},
		Kea:     kea.Options{Socket: c.KeaSocket, SubnetID: c.SubnetID, Timeout: 5 * time.Second},
		VLAN:    c.VLAN, MaximumDevices: c.MaximumDevices, Timeout: 25 * time.Second,
	}
	if len(c.NASPrefixes) == 0 || len(c.NASPrefixes) > 64 || !runtimePath(c.KeaSocket, 107) {
		return CollectorOptions{}, errRuntime
	}
	seen := make(map[netip.Prefix]bool)
	for _, value := range c.NASPrefixes {
		prefix, err := netip.ParsePrefix(value)
		if err != nil || prefix != prefix.Masked() || prefix.String() != value || seen[prefix] {
			return CollectorOptions{}, errRuntime
		}
		seen[prefix] = true
		options.Journal.NASPrefixes = append(options.Journal.NASPrefixes, prefix)
	}
	prefix, err := netip.ParsePrefix(c.IPv4Prefix)
	if err != nil || prefix.String() != c.IPv4Prefix {
		return CollectorOptions{}, errRuntime
	}
	options.Kea.Prefix = prefix
	if !validCollectorOptions(options) {
		return CollectorOptions{}, errRuntime
	}
	return options, nil
}

func (c runtimeConfig) options() (CollectorOptions, error) {
	options, err := c.collectorOptions()
	if err != nil {
		return CollectorOptions{}, err
	}
	options.Journal.ServiceUID, err = serviceUID(c.RadiusUser)
	if err != nil {
		return CollectorOptions{}, err
	}
	options.Kea.ServerUID, err = serviceUID(c.KeaUser)
	if err != nil {
		return CollectorOptions{}, err
	}
	return options, nil
}

func serviceUID(name string) (uint32, error) {
	account, err := user.Lookup(name)
	if err != nil || account == nil {
		return 0, errRuntime
	}
	uid, err := strconv.ParseUint(account.Uid, 10, 32)
	if err != nil || uid == 0 {
		return 0, errRuntime
	}
	return uint32(uid), nil // ParseUint is bounded to 32 bits above.
}

func localUser(name string) bool {
	if name == "" || len(name) > 32 || name == "root" {
		return false
	}
	for index, ch := range name {
		isLetter := ch >= 'a' && ch <= 'z'
		isSuffix := index > 0 && (ch >= '0' && ch <= '9' || ch == '-')
		if !isLetter && ch != '_' && !isSuffix {
			return false
		}
	}
	return true
}

func runtimePath(path string, maximum int) bool {
	isClean := path != "/" && filepath.IsAbs(path) && filepath.Clean(path) == path
	return isClean && len(path) <= maximum && strings.IndexFunc(path, unicode.IsControl) < 0
}
