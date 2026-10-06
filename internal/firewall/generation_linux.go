package firewall

import (
	"context"
	"errors"
	"io"
	"os"

	"github.com/mikenorgate/router-policy-agent/internal/hostfs"
)

const writerGenerationFile = "generation.json"

// generationGate is only a cooperative exclusion/generation prerequisite. It
// does not authenticate actual kernel floor or translator state. No production
// guarded mutation can use it alone; the independent auditor and all owning
// writer protocols must be wired and qualified before activation.
type generationGate struct {
	fence *hostfs.Fence
}

func openGenerationGate(ctx context.Context, directory string) (*generationGate, error) {
	if os.Geteuid() != 0 {
		return nil, errors.New("firewall: writer generation gate requires root")
	}
	fence, err := hostfs.OpenFence(ctx, hostfs.DirectoryOptions{Path: directory, OwnerUID: 0, Private: true})
	if err != nil {
		return nil, err
	}
	return &generationGate{fence: fence}, nil
}

// with runs only a trusted, deadline-aware callback when the fixed private
// generation record exactly matches the helper's expected vector. Queueing
// consumes existing authorization age; this gate never refreshes a renderer.
// Its post-check reports drift but cannot roll back a callback that already
// ran. The caller must revoke on failure, and participating map/floor writers
// must withdraw old grants before their own update while holding this fence.
func (g *generationGate) with(
	ctx context.Context,
	expected writerGeneration,
	operation func(context.Context) error,
) error {
	missingGate := g == nil || g.fence == nil
	missingOperation := ctx == nil || operation == nil
	if missingGate || missingOperation {
		return errors.New("firewall: missing writer generation dependencies")
	}
	if err := expected.validate(); err != nil {
		return err
	}
	if !expected.Ready {
		return errors.New("firewall: expected writer generation is closed")
	}
	return g.fence.With(ctx, func(bounded context.Context, root *os.Root) error {
		if err := checkWriterGeneration(bounded, root, expected); err != nil {
			return err
		}
		operationErr := operation(bounded)
		checkErr := checkWriterGeneration(bounded, root, expected)
		return errors.Join(operationErr, checkErr, bounded.Err())
	})
}

func checkWriterGeneration(ctx context.Context, root *os.Root, expected writerGeneration) error {
	actual, err := readWriterGeneration(ctx, root)
	if err != nil {
		return err
	}
	return actual.check(expected)
}

func readWriterGeneration(ctx context.Context, root *os.Root) (writerGeneration, error) {
	file, err := hostfs.OpenRegular(ctx, root, hostfs.FileOptions{
		Name: writerGenerationFile, OwnerUID: 0, MaximumSize: maximumGenerationSize,
	})
	if err != nil {
		return writerGeneration{}, err
	}
	data, readErr := io.ReadAll(io.LimitReader(file, maximumGenerationSize+1))
	closeErr := file.Close()
	if err := errors.Join(readErr, closeErr, ctx.Err()); err != nil {
		return writerGeneration{}, err
	}
	return decodeWriterGeneration(data)
}

func (g *generationGate) close(ctx context.Context) error {
	if g == nil || g.fence == nil {
		return errors.New("firewall: missing writer generation gate")
	}
	return g.fence.Close(ctx)
}
