package hostfs

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"syscall"
)

// OpenExecutable pins a regular, single-link ELF executable in a checked root.
// The expected owner must control it; group/world writes, privilege bits,
// symlinks, scripts and special files reject. Callers must execute this pinned
// descriptor, not reopen its pathname. This does not authenticate its release.
func OpenExecutable(ctx context.Context, root *os.Root, name string, owner uint32) (*os.File, error) {
	if ctx == nil || root == nil || !validName(name) {
		return nil, errors.New("hostfs: invalid executable options")
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	// A special-file path must reject without blocking while opening a FIFO.
	file, err := openNoFollow(root, name, os.O_RDONLY|syscall.O_NONBLOCK, 0)
	if err != nil {
		return nil, fmt.Errorf("hostfs: open executable: %w", err)
	}
	if err := checkExecutable(file, owner); err != nil {
		return nil, errors.Join(err, file.Close())
	}
	return file, nil
}

func checkExecutable(file *os.File, owner uint32) error {
	info, err := file.Stat()
	if err != nil {
		return fmt.Errorf("hostfs: inspect executable: %w", err)
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	isUnsafeIdentity := !ok || !info.Mode().IsRegular()
	if isUnsafeIdentity || stat.Uid != owner || stat.Nlink != 1 {
		return errors.New("hostfs: untrusted executable identity")
	}
	isUnsafeMode := info.Mode().Perm()&0o022 != 0 || info.Mode().Perm()&0o100 == 0
	hasPrivilegeBits := info.Mode()&(os.ModeSetuid|os.ModeSetgid|os.ModeSticky) != 0
	if isUnsafeMode || hasPrivilegeBits || info.Size() < 4 || info.Size() > 64<<20 {
		return errors.New("hostfs: unsafe executable permissions or size")
	}
	var magic [4]byte
	if _, err := file.ReadAt(magic[:], 0); err != nil {
		return fmt.Errorf("hostfs: read executable header: %w", err)
	}
	if magic != [4]byte{0x7f, 'E', 'L', 'F'} {
		return errors.New("hostfs: ELF executable required")
	}
	if _, err := file.Seek(0, io.SeekStart); err != nil {
		return fmt.Errorf("hostfs: rewind executable: %w", err)
	}
	return nil
}
