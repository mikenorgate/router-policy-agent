package firewall

import (
	"context"
	"errors"
	"io"
	"os"

	"github.com/mikenorgate/router-policy-agent/internal/hostfs"
)

const routerProfileFile = "profile.json"

// The directory and pin are privileged, image-owned configuration. Neither
// may come from a directory snapshot, reader request or generation record.
type profileOptions struct {
	Directory string
	SHA256    string
}

// loadRouterProfile performs read-only loading of one fixed, root-owned,
// private regular file. It closes every descriptor before returning an
// immutable in-memory profile. There is no automatic initialization, pin
// learning, symlink following or production-profile content in this project.
func loadRouterProfile(ctx context.Context, options profileOptions) (*routerProfile, error) {
	if ctx == nil {
		return nil, errors.New("firewall: missing router profile context")
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if os.Geteuid() != 0 {
		return nil, errors.New("firewall: router profile loading requires root")
	}
	if !generationHash(options.SHA256) {
		return nil, errors.New("firewall: invalid router profile digest pin")
	}
	root, err := hostfs.OpenDirectory(ctx, hostfs.DirectoryOptions{
		Path: options.Directory, OwnerUID: 0, Private: true,
	})
	if err != nil {
		return nil, profileFailure("directory unavailable", err)
	}
	data, readErr := readRouterProfile(ctx, root)
	closeErr := root.Close()
	if err := errors.Join(readErr, closeErr, ctx.Err()); err != nil {
		return nil, profileFailure("read failed", err)
	}
	return decodePinnedProfile(ctx, data, options.SHA256)
}

func readRouterProfile(ctx context.Context, root *os.Root) ([]byte, error) {
	file, err := hostfs.OpenRegular(ctx, root, hostfs.FileOptions{
		Name: routerProfileFile, OwnerUID: 0, MaximumSize: maximumRouterProfile,
	})
	if err != nil {
		return nil, err
	}
	if err := checkRouterProfileFile(file); err != nil {
		return nil, errors.Join(err, file.Close())
	}
	data, readErr := io.ReadAll(io.LimitReader(file, maximumRouterProfile+1))
	metadataErr := checkRouterProfileFile(file)
	closeErr := file.Close()
	if err := errors.Join(readErr, metadataErr, closeErr, ctx.Err()); err != nil {
		return nil, err
	}
	return data, nil
}

func checkRouterProfileFile(file *os.File) error {
	if err := hostfs.CheckPrivateFile(file, 0, maximumRouterProfile); err != nil {
		return err
	}
	info, err := file.Stat()
	if err != nil {
		return err
	}
	mode := info.Mode().Perm()
	if mode != 0o600 && mode != 0o400 {
		return errors.New("firewall: router profile must be owner-readable and private")
	}
	return nil
}

// inspect uses only this profile's paired contract and fixed guard layout.
// It issues one fixed read-only operation, not a mutation or permission. The
// real helper must still hold the shared writer fence and independently prove
// protected paths, mapping state, boot ordering and release/pin provenance.
func (p *routerProfile) inspect(ctx context.Context, executor *process) (*rulesetObservation, error) {
	if p == nil || executor == nil {
		return nil, errors.New("firewall: missing router profile inspection dependencies")
	}
	validRenderer := p.renderer != nil && p.renderer.compiler != nil
	validContract := p.ruleset != nil && len(p.ruleset.program) != 0
	validLayout := p.layout != nil && len(p.layout.managedInterfaces) != 0
	if !generationHash(p.digest) || !validRenderer || !validContract || !validLayout {
		return nil, errors.New("firewall: incomplete router profile")
	}
	return executor.inspectRuleset(ctx, p.ruleset, p.layout)
}
