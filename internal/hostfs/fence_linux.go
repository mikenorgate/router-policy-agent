package hostfs

import (
	"context"
	"errors"
	"fmt"
	"math"
	"os"
	"syscall"
	"time"
)

const maximumFenceDuration = 2 * time.Second

// Fence serializes cooperating privileged processes through one descriptor-
// owned advisory lock. Its directory must be separate from a lifetime-locked
// state store. All writers must use it; it cannot restrain another netlink
// writer or establish that a protected firewall is installed. Do not copy it.
type Fence struct {
	noCopy   noCopy
	options  DirectoryOptions
	root     *os.Root
	lock     *os.File
	fd       int
	gate     chan struct{}
	isBroken bool
}

type noCopy struct{}

func (*noCopy) Lock()   {}
func (*noCopy) Unlock() {}

// OpenFence pins an ownership-checked private directory and empty .lock file.
// Creating the lock is not initialization of any generation or policy state.
// Newly created files must belong to the caller's configured owner identity.
func OpenFence(ctx context.Context, options DirectoryOptions) (*Fence, error) {
	uid := os.Geteuid()
	validOwner := uid >= 0 && uint64(uid) <= math.MaxUint32 && uint32(uid) == options.OwnerUID
	if !validOwner || !options.Private {
		return nil, errors.New("hostfs: fence requires its owner and a private directory")
	}
	root, err := OpenDirectory(ctx, options)
	if err != nil {
		return nil, err
	}
	lock, err := OpenLock(ctx, root, options.OwnerUID)
	if err != nil {
		return nil, errors.Join(err, root.Close())
	}
	rawFD := lock.Fd()
	if rawFD > math.MaxInt {
		return nil, errors.Join(errors.New("hostfs: invalid fence descriptor"), lock.Close(), root.Close())
	}
	return &Fence{
		options: options, root: root, lock: lock, fd: int(rawFD), gate: make(chan struct{}, 1),
	}, nil
}

// With runs one trusted operation under local and cross-process exclusion.
// Waiting and the operation share a maximum two-second context; the callback
// must honor cancellation. The pinned root is borrowed and must not be closed
// or retained. It is never supplied to a directory reader or through IPC.
// Path/lock replacement poisons the fence rather than silently following a new
// inode. A post-operation error does not undo the operation; callers must seal
// permits on failure, and all other writers still need a qualified protocol.
func (f *Fence) With(
	ctx context.Context,
	operation func(context.Context, *os.Root) error,
) (result error) {
	if ctx == nil || operation == nil {
		return errors.New("hostfs: fence requires context and operation")
	}
	bounded, cancel := context.WithTimeout(ctx, maximumFenceDuration)
	defer cancel()
	if err := f.acquire(bounded); err != nil {
		return err
	}
	defer f.release()
	if f.isBroken {
		return errors.New("hostfs: fence identity is invalid")
	}
	if err := f.wait(bounded); err != nil {
		return err
	}
	defer func() {
		if err := syscall.Flock(f.fd, syscall.LOCK_UN); err != nil {
			f.isBroken = true
			result = errors.Join(result, fmt.Errorf("hostfs: release fence: %w", err))
		}
	}()
	if err := f.check(bounded); err != nil {
		if bounded.Err() == nil {
			f.isBroken = true
		}
		return err
	}
	operationErr := operation(bounded, f.root)
	checkErr := f.check(bounded)
	if checkErr != nil && bounded.Err() == nil {
		f.isBroken = true
	}
	return errors.Join(operationErr, checkErr, bounded.Err())
}

// Close waits only within the supplied context for a local operation, then
// releases the descriptors. It never deletes or rotates the shared lock file.
func (f *Fence) Close(ctx context.Context) error {
	if err := f.acquire(ctx); err != nil {
		return err
	}
	defer f.release()
	err := errors.Join(f.lock.Close(), f.root.Close())
	f.lock, f.root = nil, nil
	return err
}

func (f *Fence) acquire(ctx context.Context) error {
	if f == nil || f.gate == nil || ctx == nil {
		return errors.New("hostfs: invalid fence or context")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	select {
	case f.gate <- struct{}{}:
		if f.root == nil || f.lock == nil {
			f.release()
			return os.ErrClosed
		}
		if err := ctx.Err(); err != nil {
			f.release()
			return err
		}
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (f *Fence) release() {
	<-f.gate
}

func (f *Fence) wait(ctx context.Context) error {
	timer := time.NewTimer(time.Hour)
	defer timer.Stop()
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		err := syscall.Flock(f.fd, syscall.LOCK_EX|syscall.LOCK_NB)
		if err == nil {
			return nil
		}
		if errors.Is(err, syscall.EINTR) {
			continue
		}
		if !errors.Is(err, syscall.EWOULDBLOCK) && !errors.Is(err, syscall.EAGAIN) {
			return fmt.Errorf("hostfs: acquire fence: %w", err)
		}
		timer.Reset(10 * time.Millisecond)
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-timer.C:
		}
	}
}

func (f *Fence) check(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := CheckPrivateFile(f.lock, f.options.OwnerUID, 0); err != nil {
		return err
	}
	openedLock, err := f.lock.Stat()
	if err != nil {
		return err
	}
	currentLock, err := f.root.Lstat(".lock")
	if err != nil {
		return errors.New("hostfs: shared fence lock is unavailable")
	}
	if currentLock.Mode()&os.ModeSymlink != 0 || !os.SameFile(openedLock, currentLock) {
		return errors.New("hostfs: shared fence lock was replaced")
	}
	currentRoot, err := OpenDirectory(ctx, f.options)
	if err != nil {
		return err
	}
	openedDirectory, openedErr := f.root.Stat(".")
	currentDirectory, currentErr := currentRoot.Stat(".")
	closeErr := currentRoot.Close()
	if err := errors.Join(openedErr, currentErr, closeErr); err != nil {
		return err
	}
	if !os.SameFile(openedDirectory, currentDirectory) {
		return errors.New("hostfs: shared fence directory was replaced")
	}
	return ctx.Err()
}
