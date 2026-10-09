package binding

import (
	"context"
	"errors"
	"io"
	"os"

	"github.com/mikenorgate/router-policy-agent/internal/hostfs"
	"github.com/mikenorgate/router-policy-agent/internal/strictjson"
)

const maximumSnapshotBytes = 8 << 20

// Load reads one atomic, root-owned bindings.json export on each invocation.
// It does not qualify its producer or refresh any evidence timestamps. The
// engine independently checks freshness, ownership, completeness and quotas.
func Load(ctx context.Context, directory string) (Snapshot, error) {
	if ctx == nil || os.Geteuid() != 0 {
		return Snapshot{}, errors.New("binding: root-owned export required")
	}
	root, err := hostfs.OpenDirectory(ctx, hostfs.DirectoryOptions{
		Path: directory, OwnerUID: 0, Private: true,
	})
	if err != nil {
		return Snapshot{}, errors.New("binding: export directory unavailable")
	}
	file, err := hostfs.OpenRegular(ctx, root, hostfs.FileOptions{
		Name: "bindings.json", OwnerUID: 0, MaximumSize: maximumSnapshotBytes,
	})
	if err != nil {
		return Snapshot{}, errors.Join(errors.New("binding: export unavailable"), root.Close())
	}
	before, statErr := file.Stat()
	data, readErr := io.ReadAll(io.LimitReader(file, maximumSnapshotBytes+1))
	after, afterErr := file.Stat()
	metadataErr := hostfs.CheckPrivateFile(file, 0, maximumSnapshotBytes)
	closeErr := errors.Join(file.Close(), root.Close())
	if err := errors.Join(statErr, readErr, afterErr, metadataErr, closeErr, ctx.Err()); err != nil {
		return Snapshot{}, errors.New("binding: export read failed")
	}
	if before.Size() != after.Size() || !before.ModTime().Equal(after.ModTime()) {
		return Snapshot{}, errors.New("binding: export changed during read")
	}
	return decodeSnapshot(data)
}

func decodeSnapshot(data []byte) (Snapshot, error) {
	keys := []string{"schema_version", "generation", "observed_at", "complete", "records"}
	if err := strictjson.Object(data, keys, nil, maximumSnapshotBytes); err != nil {
		return Snapshot{}, errors.New("binding: invalid export")
	}
	var snapshot Snapshot
	if err := strictjson.Decode(data, &snapshot, maximumSnapshotBytes); err != nil {
		return Snapshot{}, errors.New("binding: invalid export")
	}
	if snapshot.SchemaVersion != 1 || snapshot.Generation == "" || len(snapshot.Generation) > 128 ||
		!snapshot.Complete || snapshot.ObservedAt.IsZero() || len(snapshot.Records) > 4096 {
		return Snapshot{}, errors.New("binding: incomplete or oversized export")
	}
	for _, record := range snapshot.Records {
		if len(record.Addresses) > 16 {
			return Snapshot{}, errors.New("binding: oversized address export")
		}
	}
	return snapshot, nil
}
