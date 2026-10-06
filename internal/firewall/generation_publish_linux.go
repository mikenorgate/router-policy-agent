package firewall

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"os"
	"path/filepath"
	"strconv"
	"syscall"

	"github.com/mikenorgate/router-policy-agent/internal/hostfs"
)

// writeWriterGeneration atomically replaces only the fixed coordination record.
// The caller must hold the shared writer fence and have checked existing state.
// A failure after rename is an indeterminate publication, not proof of rollback.
func writeWriterGeneration(ctx context.Context, root *os.Root, value writerGeneration) (result error) {
	if ctx == nil || root == nil {
		return errors.New("firewall: missing generation publication dependencies")
	}
	if err := value.validate(); err != nil {
		return err
	}
	data, err := json.Marshal(value)
	if err != nil || len(data) > maximumGenerationSize {
		return errors.New("firewall: invalid serialized writer generation")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	directory, err := root.OpenFile(".", os.O_RDONLY|syscall.O_DIRECTORY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return fmt.Errorf("firewall: open generation sync directory: %w", err)
	}
	defer func() { result = errors.Join(result, directory.Close()) }()
	rawFD := directory.Fd()
	if rawFD > math.MaxInt {
		return errors.New("firewall: invalid generation directory descriptor")
	}
	// The proc path names the pinned directory descriptor, not a mutable
	// configured pathname. CreateTemp is unpredictable and owner-only.
	temporary, err := os.CreateTemp("/proc/self/fd/"+strconv.Itoa(int(rawFD)), ".generation-*")
	if err != nil {
		return fmt.Errorf("firewall: create temporary generation: %w", err)
	}
	name := filepath.Base(temporary.Name())
	isClosed := false
	defer func() {
		if !isClosed {
			result = errors.Join(result, temporary.Close())
		}
		if err := root.Remove(name); err != nil && !errors.Is(err, os.ErrNotExist) {
			result = errors.Join(result, fmt.Errorf("firewall: remove temporary generation: %w", err))
		}
	}()
	if err := hostfs.CheckPrivateFile(temporary, 0, 0); err != nil {
		return err
	}
	n, err := temporary.Write(data)
	if err != nil {
		return fmt.Errorf("firewall: write temporary generation: %w", err)
	}
	if n != len(data) {
		return io.ErrShortWrite
	}
	if err := temporary.Sync(); err != nil {
		return fmt.Errorf("firewall: sync generation: %w", err)
	}
	err = temporary.Close()
	isClosed = true
	if err != nil {
		return fmt.Errorf("firewall: close temporary generation: %w", err)
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := root.Rename(name, writerGenerationFile); err != nil {
		return fmt.Errorf("firewall: replace generation: %w", err)
	}
	if err := directory.Sync(); err != nil {
		return fmt.Errorf("firewall: sync generation directory: %w", err)
	}
	return nil
}
