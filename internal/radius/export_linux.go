package radius

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"math"
	"os"
	"path/filepath"
	"strconv"
	"syscall"
	"time"

	"github.com/mikenorgate/router-policy-agent/internal/hostfs"
)

const shadowFilename = "radius-shadow.json"
const maximumShadow = 4 << 20

type shadowReport struct {
	Kind             string     `json:"kind"`
	Mode             string     `json:"mode"`
	EnforcementReady bool       `json:"enforcement_ready"`
	Complete         bool       `json:"complete"`
	SampledAt        time.Time  `json:"sampled_at"`
	Collection       Collection `json:"collection"`
}

// PublishIPv4 serializes one collector in an existing root-private directory.
// It atomically publishes an incomplete shadow report before reading sources,
// so a collection failure cannot leave the previous report marked complete.
// Successful reports are still enforcement_ready=false and are never named
// bindings.json. The helper rejects this distinct schema even if renamed.
// Directory must be dedicated to the collector on encrypted local storage.
func PublishIPv4(ctx context.Context, options CollectorOptions, directory string) (collected Collection, result error) {
	if ctx == nil || os.Geteuid() != 0 || !validCollectorOptions(options) {
		return Collection{}, errors.New("radius: invalid privileged publisher options")
	}
	root, err := hostfs.OpenDirectory(ctx, hostfs.DirectoryOptions{Path: directory, OwnerUID: 0, Private: true})
	if err != nil {
		return Collection{}, errors.New("radius: shadow directory unavailable")
	}
	defer func() {
		if err := root.Close(); err != nil {
			result = errors.Join(result, errors.New("radius: shadow directory close failed"))
		}
		if result != nil {
			collected = Collection{}
		}
	}()
	lock, err := hostfs.OpenLock(ctx, root, 0)
	if err != nil {
		return Collection{}, errors.New("radius: shadow lock unavailable")
	}
	defer func() {
		if err := lock.Close(); err != nil {
			result = errors.Join(result, errors.New("radius: shadow lock close failed"))
		}
	}()
	fd, err := fileDescriptor(lock)
	if err != nil || syscall.Flock(fd, syscall.LOCK_EX|syscall.LOCK_NB) != nil {
		return Collection{}, errors.New("radius: shadow publisher already active")
	}
	defer func() {
		if err := syscall.Flock(fd, syscall.LOCK_UN); err != nil {
			result = errors.Join(result, errors.New("radius: shadow lock release failed"))
		}
	}()
	return publishIPv4(ctx, root, func(ctx context.Context) (Collection, error) { return CollectIPv4(ctx, options) })
}

func publishIPv4(ctx context.Context, root *os.Root, collect func(context.Context) (Collection, error)) (Collection, error) {
	if ctx == nil || root == nil || collect == nil {
		return Collection{}, errors.New("radius: missing shadow publisher dependency")
	}
	report := shadowReport{Kind: "radius_ipv4_shadow_v1", Mode: "shadow", SampledAt: time.Now().UTC(),
		Collection: Collection{Candidates: []IPv4Candidate{}}}
	if err := writeShadow(ctx, root, report); err != nil {
		return Collection{}, err
	}
	collected, err := collect(ctx)
	if err != nil {
		return Collection{}, err
	}
	report.Complete, report.Collection = true, collected
	report.SampledAt = time.Now().UTC()
	if err := writeShadow(ctx, root, report); err != nil {
		return Collection{}, err
	}
	return collected, nil
}

func writeShadow(ctx context.Context, root *os.Root, report shadowReport) (result error) {
	if err := ctx.Err(); err != nil {
		return err
	}
	data, err := json.Marshal(report)
	if err != nil || len(data) > maximumShadow {
		return errors.New("radius: invalid shadow serialization")
	}
	// Refuse to replace links, special files or unsafe exports. Missing output is
	// expected on first publication; no binding/state file is read or modified.
	existing, err := hostfs.OpenRegular(ctx, root, hostfs.FileOptions{Name: shadowFilename, OwnerUID: 0, MaximumSize: maximumShadow})
	if err == nil {
		if err := existing.Close(); err != nil {
			return errors.New("radius: previous shadow close failed")
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return errors.New("radius: unsafe previous shadow export")
	}
	directory, err := root.OpenFile(".", os.O_RDONLY|syscall.O_DIRECTORY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return errors.New("radius: shadow sync directory unavailable")
	}
	defer func() { result = errors.Join(result, directory.Close()) }()
	fd, err := fileDescriptor(directory)
	if err != nil {
		return err
	}
	temporary, err := os.CreateTemp("/proc/self/fd/"+strconv.Itoa(fd), ".radius-shadow-*")
	if err != nil {
		return errors.New("radius: temporary shadow unavailable")
	}
	name := filepath.Base(temporary.Name())
	isClosed := false
	defer func() {
		if !isClosed {
			result = errors.Join(result, temporary.Close())
		}
		if err := root.Remove(name); err != nil && !errors.Is(err, os.ErrNotExist) {
			result = errors.Join(result, errors.New("radius: temporary shadow cleanup failed"))
		}
	}()
	if err := hostfs.CheckPrivateFile(temporary, 0, 0); err != nil {
		return errors.New("radius: unsafe temporary shadow")
	}
	n, err := temporary.Write(data)
	if err != nil || n != len(data) {
		return errors.Join(errors.New("radius: shadow write failed"), io.ErrShortWrite)
	}
	if err := temporary.Sync(); err != nil {
		return errors.New("radius: shadow sync failed")
	}
	err = temporary.Close()
	isClosed = true
	if err != nil {
		return errors.New("radius: shadow close failed")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := root.Rename(name, shadowFilename); err != nil {
		return errors.New("radius: shadow replacement failed")
	}
	if err := directory.Sync(); err != nil {
		return errors.New("radius: shadow directory sync failed")
	}
	return nil
}

func fileDescriptor(file *os.File) (int, error) {
	if file == nil || file.Fd() > math.MaxInt {
		return 0, errors.New("radius: invalid file descriptor")
	}
	return int(file.Fd()), nil
}
