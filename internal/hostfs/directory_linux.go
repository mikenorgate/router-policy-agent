// Package hostfs confines privileged local files to ownership-checked roots.
package hostfs

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"
)

// DirectoryOptions names a deployment-owned directory, never a directory
// attribute. Private requires an owner-only final directory.
type DirectoryOptions struct {
	Path     string
	OwnerUID uint32
	Private  bool
}

// OpenDirectory pins a clean absolute directory after checking every ancestor.
// Symlinks and untrusted writable ancestors are rejected. A root-owned sticky
// ancestor is safe for an already existing, trusted-owner child (for example a
// private test directory in /tmp); the final directory cannot use that exception.
func OpenDirectory(ctx context.Context, options DirectoryOptions) (*os.Root, error) {
	if ctx == nil || !filepath.IsAbs(options.Path) || filepath.Clean(options.Path) != options.Path {
		return nil, errors.New("hostfs: clean absolute directory required")
	}
	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("hostfs: open directory canceled: %w", err)
	}
	root, err := os.OpenRoot("/")
	if err != nil {
		return nil, fmt.Errorf("hostfs: open filesystem root: %w", err)
	}
	if err := checkDirectory(root, options.OwnerUID, false, false); err != nil {
		return nil, errors.Join(err, root.Close())
	}
	parts := strings.Split(strings.TrimPrefix(options.Path, "/"), "/")
	if options.Path == "/" {
		return nil, errors.Join(errors.New("hostfs: filesystem root is not a private object root"), root.Close())
	}
	for index, part := range parts {
		if err := ctx.Err(); err != nil {
			return nil, errors.Join(err, root.Close())
		}
		info, err := root.Lstat(part)
		if err != nil {
			return nil, errors.Join(fmt.Errorf("hostfs: inspect directory: %w", err), root.Close())
		}
		isFinal := index == len(parts)-1
		if err := directoryInfo(info, options.OwnerUID, isFinal, options.Private); err != nil {
			return nil, errors.Join(err, root.Close())
		}
		// The checked parent cannot be modified by an untrusted identity. Check
		// the opened directory too, rather than trusting only the pathname stat.
		next, openErr := root.OpenRoot(part)
		closeErr := root.Close()
		if err := errors.Join(openErr, closeErr); err != nil {
			if next != nil {
				err = errors.Join(err, next.Close())
			}
			return nil, fmt.Errorf("hostfs: enter directory: %w", err)
		}
		root = next
		if err := checkDirectory(root, options.OwnerUID, isFinal, options.Private); err != nil {
			return nil, errors.Join(err, root.Close())
		}
	}
	return root, nil
}

func checkDirectory(root *os.Root, owner uint32, isFinal, isPrivate bool) error {
	file, err := root.OpenFile(".", os.O_RDONLY|syscall.O_DIRECTORY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return fmt.Errorf("hostfs: open directory descriptor: %w", err)
	}
	info, statErr := file.Stat()
	closeErr := file.Close()
	if err := errors.Join(statErr, closeErr); err != nil {
		return fmt.Errorf("hostfs: inspect directory descriptor: %w", err)
	}
	return directoryInfo(info, owner, isFinal, isPrivate)
}

func directoryInfo(info os.FileInfo, owner uint32, isFinal, isPrivate bool) error {
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return errors.New("hostfs: real directory required")
	}
	if stat.Uid != 0 && stat.Uid != owner || isFinal && stat.Uid != owner {
		return errors.New("hostfs: untrusted directory owner")
	}
	isWritable := info.Mode().Perm()&0o022 != 0
	isSafeStickyAncestor := !isFinal && stat.Uid == 0 && info.Mode()&os.ModeSticky != 0
	if isWritable && !isSafeStickyAncestor || isFinal && isPrivate && info.Mode().Perm()&0o077 != 0 {
		return errors.New("hostfs: unsafe directory permissions")
	}
	return nil
}
