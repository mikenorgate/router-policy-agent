package state

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

const filename = "state.json"

// ErrUninitialized requires explicit first-install initialization. Missing
// state must never be mistaken for authorization to discard existing guards.
var ErrUninitialized = errors.New("state: explicit initialization required")

// Options is helper-owned deployment configuration, not an IPC request.
// Directory must be on the deployment's encrypted persistent filesystem.
type Options struct {
	Directory string
	OwnerUID  uint32
}

// Store exclusively locks a private directory and serializes local state
// transactions. It must not be copied. No application permits are persisted.
type Store struct {
	root  *os.Root
	lock  *os.File
	owner uint32
	gate  chan struct{}
}

// Open checks ownership and permissions without initializing missing state.
// The current helper identity must own the directory and newly created files.
func Open(ctx context.Context, options Options) (*Store, error) {
	uid := os.Geteuid()
	if uid < 0 || uint64(uid) > math.MaxUint32 || uint32(uid) != options.OwnerUID {
		return nil, errors.New("state: helper must own its state directory")
	}
	root, err := hostfs.OpenDirectory(ctx, hostfs.DirectoryOptions{
		Path: options.Directory, OwnerUID: options.OwnerUID, Private: true,
	})
	if err != nil {
		return nil, err
	}
	lock, err := hostfs.OpenLock(ctx, root, options.OwnerUID)
	if err != nil {
		return nil, errors.Join(fmt.Errorf("state: open lock: %w", err), root.Close())
	}
	fd, err := descriptor(lock)
	if err == nil {
		err = syscall.Flock(fd, syscall.LOCK_EX|syscall.LOCK_NB)
	}
	if err != nil {
		return nil, errors.Join(fmt.Errorf("state: exclusive lock unavailable: %w", err), lock.Close(), root.Close())
	}
	return &Store{root: root, lock: lock, owner: options.OwnerUID, gate: make(chan struct{}, 1)}, nil
}

// Load returns an independent validated document. Corruption, missing state or
// unsafe metadata fail closed, rather than resetting clocks or expiry anchors.
func (s *Store) Load(ctx context.Context) (Document, error) {
	if err := s.acquire(ctx); err != nil {
		return Document{}, err
	}
	defer s.release()
	return s.load(ctx)
}

// Initialize creates empty state only when no state file exists. This is a
// separate explicit installation operation, never a runtime fallback.
func (s *Store) Initialize(ctx context.Context) error {
	if err := s.acquire(ctx); err != nil {
		return err
	}
	defer s.release()
	if _, err := s.load(ctx); !errors.Is(err, ErrUninitialized) {
		if err != nil {
			return err
		}
		return errors.New("state: already initialized")
	}
	return s.write(ctx, Initial())
}

// Save verifies that no durable guard, classification or immutable anchor was
// removed before atomically replacing and syncing the file and its directory.
// A failure after rename can leave advanced state; it never authorizes a grant.
func (s *Store) Save(ctx context.Context, next Document) error {
	if err := s.acquire(ctx); err != nil {
		return err
	}
	defer s.release()
	previous, err := s.load(ctx)
	if err != nil {
		return err
	}
	owned, err := Clone(next)
	if err != nil {
		return err
	}
	if err := CheckTransition(previous, owned); err != nil {
		return err
	}
	return s.write(ctx, owned)
}

// Close releases the descriptor-owned process lock after in-flight operations.
func (s *Store) Close() error {
	if s == nil || s.gate == nil {
		return errors.New("state: invalid store")
	}
	s.gate <- struct{}{}
	defer s.release()
	if s.root == nil {
		return os.ErrClosed
	}
	// A fork can transiently retain the open file description even with
	// CLOEXEC. Explicitly unlock after joining state work, before closing.
	fd, unlockErr := descriptor(s.lock)
	if unlockErr == nil {
		unlockErr = syscall.Flock(fd, syscall.LOCK_UN)
	}
	if unlockErr != nil {
		unlockErr = fmt.Errorf("state: release exclusive lock: %w", unlockErr)
	}
	err := errors.Join(unlockErr, s.lock.Close(), s.root.Close())
	s.lock, s.root = nil, nil
	return err
}

func (s *Store) acquire(ctx context.Context) error {
	if s == nil || s.gate == nil || ctx == nil {
		return errors.New("state: invalid store or context")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	select {
	case s.gate <- struct{}{}:
		if s.root == nil {
			s.release()
			return os.ErrClosed
		}
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (s *Store) release() {
	<-s.gate
}

func (s *Store) load(ctx context.Context) (Document, error) {
	file, err := hostfs.OpenRegular(ctx, s.root, hostfs.FileOptions{
		Name: filename, OwnerUID: s.owner, MaximumSize: MaximumSize,
	})
	if errors.Is(err, os.ErrNotExist) {
		return Document{}, ErrUninitialized
	}
	if err != nil {
		return Document{}, err
	}
	data, readErr := io.ReadAll(io.LimitReader(file, MaximumSize+1))
	closeErr := file.Close()
	if err := errors.Join(readErr, closeErr, ctx.Err()); err != nil {
		return Document{}, fmt.Errorf("state: read state: %w", err)
	}
	return Decode(data)
}

func (s *Store) write(ctx context.Context, document Document) (result error) {
	data, err := json.Marshal(document)
	if err != nil || len(data) > MaximumSize {
		return errors.New("state: invalid serialized state")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	directory, err := s.root.OpenFile(".", os.O_RDONLY|syscall.O_DIRECTORY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return fmt.Errorf("state: open sync directory: %w", err)
	}
	defer func() { result = errors.Join(result, directory.Close()) }()
	fd, err := descriptor(directory)
	if err != nil {
		return err
	}
	// CreateTemp uses a pinned directory descriptor, not a pathname that can
	// move between checking ownership and creating the temporary file.
	temporary, err := os.CreateTemp("/proc/self/fd/"+strconv.Itoa(fd), ".state-*")
	if err != nil {
		return fmt.Errorf("state: create temporary state: %w", err)
	}
	name := filepath.Base(temporary.Name())
	isClosed := false
	defer func() {
		if !isClosed {
			result = errors.Join(result, temporary.Close())
		}
		if err := s.root.Remove(name); err != nil && !errors.Is(err, os.ErrNotExist) {
			result = errors.Join(result, fmt.Errorf("state: remove temporary state: %w", err))
		}
	}()
	if err := hostfs.CheckPrivateFile(temporary, s.owner, 0); err != nil {
		return err
	}
	n, err := temporary.Write(data)
	if err != nil {
		return fmt.Errorf("state: write temporary state: %w", err)
	}
	if n != len(data) {
		return io.ErrShortWrite
	}
	if err := temporary.Sync(); err != nil {
		return fmt.Errorf("state: sync state: %w", err)
	}
	err = temporary.Close()
	isClosed = true
	if err != nil {
		return fmt.Errorf("state: close state: %w", err)
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := s.root.Rename(name, filename); err != nil {
		return fmt.Errorf("state: replace state: %w", err)
	}
	if err := directory.Sync(); err != nil {
		return fmt.Errorf("state: sync state directory: %w", err)
	}
	return nil
}

func descriptor(file *os.File) (int, error) {
	fd := file.Fd()
	if fd > math.MaxInt {
		return 0, errors.New("state: invalid file descriptor")
	}
	return int(fd), nil
}
