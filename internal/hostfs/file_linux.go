package hostfs

import (
	"context"
	"errors"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"syscall"
)

// FileOptions specifies one private regular file in a previously checked root.
type FileOptions struct {
	Name        string
	OwnerUID    uint32
	MaximumSize int64
}

// OpenRegular rejects symlinks, special files, hard links, unsafe permissions
// and oversized files before a caller reads their contents. O_NONBLOCK prevents
// a substituted FIFO from hanging before its descriptor can be inspected.
func OpenRegular(ctx context.Context, root *os.Root, options FileOptions) (*os.File, error) {
	if ctx == nil || root == nil || !validName(options.Name) || options.MaximumSize <= 0 {
		return nil, errors.New("hostfs: invalid regular-file options")
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	file, err := openNoFollow(root, options.Name, os.O_RDONLY, 0)
	if err != nil {
		return nil, fmt.Errorf("hostfs: open private file: %w", err)
	}
	if err := CheckPrivateFile(file, options.OwnerUID, options.MaximumSize); err != nil {
		return nil, errors.Join(err, file.Close())
	}
	return file, nil
}

// OpenLock opens the fixed empty process-lock file without following links.
// Its lifetime and exclusive locking remain the caller's responsibility.
func OpenLock(ctx context.Context, root *os.Root, owner uint32) (*os.File, error) {
	if ctx == nil || root == nil {
		return nil, errors.New("hostfs: invalid lock options")
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	file, err := openNoFollow(root, ".lock", os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, err
	}
	if err := CheckPrivateFile(file, owner, 0); err != nil {
		return nil, errors.Join(err, file.Close())
	}
	return file, nil
}

// os.Root resolves in-root symlinks before its open operation, so supplying
// O_NOFOLLOW to Root.OpenFile is insufficient. A fixed basename opened with
// openat on the pinned directory descriptor has the required kernel semantics.
func openNoFollow(root *os.Root, name string, flags int, mode uint32) (*os.File, error) {
	directory, err := root.OpenFile(".", os.O_RDONLY|syscall.O_DIRECTORY, 0)
	if err != nil {
		return nil, fmt.Errorf("hostfs: open containing directory: %w", err)
	}
	rawFD := directory.Fd()
	if rawFD > math.MaxInt {
		return nil, errors.Join(errors.New("hostfs: invalid directory descriptor"), directory.Close())
	}
	fd, openErr := syscall.Openat(int(rawFD), name, flags|syscall.O_NOFOLLOW|syscall.O_NONBLOCK|syscall.O_CLOEXEC, mode)
	closeErr := directory.Close()
	if err := errors.Join(openErr, closeErr); err != nil {
		if fd >= 0 {
			err = errors.Join(err, syscall.Close(fd))
		}
		return nil, fmt.Errorf("hostfs: open no-follow file: %w", err)
	}
	if fd < 0 {
		return nil, errors.New("hostfs: invalid opened descriptor")
	}
	file := os.NewFile(uintptr(fd), name)
	if file == nil {
		return nil, errors.Join(errors.New("hostfs: invalid opened file"), syscall.Close(fd))
	}
	return file, nil
}

// CheckPrivateFile validates an opened descriptor, not a prior pathname stat.
// maximum may be zero for a deliberately empty lock file.
func CheckPrivateFile(file *os.File, owner uint32, maximum int64) error {
	if file == nil || maximum < 0 {
		return errors.New("hostfs: invalid private-file descriptor")
	}
	info, err := file.Stat()
	if err != nil {
		return fmt.Errorf("hostfs: inspect private file: %w", err)
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || !info.Mode().IsRegular() || stat.Nlink != 1 || stat.Uid != owner {
		return errors.New("hostfs: untrusted private-file identity")
	}
	isUnsafeMode := info.Mode().Perm()&0o177 != 0 || info.Mode()&(os.ModeSetuid|os.ModeSetgid|os.ModeSticky) != 0
	if isUnsafeMode || info.Size() < 0 || info.Size() > maximum {
		return errors.New("hostfs: unsafe private-file permissions or size")
	}
	return nil
}

func validName(name string) bool {
	return name != "" && name != "." && name != ".." && filepath.Base(name) == name && !filepath.IsAbs(name)
}
