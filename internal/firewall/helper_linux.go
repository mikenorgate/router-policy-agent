package firewall

import (
	"context"
	"errors"
	"net"
	"os"
	"strconv"
	"strings"

	"github.com/mikenorgate/router-policy-agent/internal/binding"
	"github.com/mikenorgate/router-policy-agent/internal/radius"
	"github.com/mikenorgate/router-policy-agent/internal/state"
)

// RunHelper adopts the two enforcement sockets and an optional observation socket from a root supervisor
// and runs the checked helper. It never installs guards, learns release pins,
// creates socket paths, initializes history or qualifies the binding producer.
// Deployment must independently qualify the selected mode and owning writers.
func RunHelper(ctx context.Context, directory, bindingDirectory string) (result error) {
	if ctx == nil || os.Geteuid() != 0 || !helperPath(bindingDirectory, 4096) {
		return errors.New("firewall: invalid helper executable inputs")
	}
	config, err := loadHelperConfig(ctx, directory)
	if err != nil {
		return err
	}
	requestFD, statusFD, observationFD, valid := helperActivationEnvironment(os.Getpid(), os.Getenv)
	if !valid {
		return errors.New("firewall: two named supervisor sockets required")
	}
	requests, err := inheritedListener(requestFD)
	if err != nil {
		return err
	}
	defer func() { result = errors.Join(result, closeHelperListener(requests)) }()
	status, err := inheritedListener(statusFD)
	if err != nil {
		return err
	}
	defer func() { result = errors.Join(result, closeHelperListener(status)) }()
	if !configuredListenerMatches(requests, config.RequestSocket) ||
		!configuredListenerMatches(status, config.StatusSocket) {
		return errors.New("firewall: inherited sockets differ from configuration")
	}
	var observations *net.UnixListener
	if observationFD != 0 {
		observations, err = inheritedListener(observationFD)
		// The optional observer cannot prevent enforcement from starting.
		if err != nil || !configuredListenerMatches(observations, config.ObservationsSocket) {
			if observations != nil {
				_ = closeHelperListener(observations)
			}
			observations = nil
		} else {
			defer func() { result = errors.Join(result, closeHelperListener(observations)) }()
		}
	}
	return runConfiguredService(ctx, configuredOptions{
		directory: directory, requests: requests, status: status, observations: observations,
		bindingSource: config.BindingSource,
		bindings: func(ctx context.Context) (binding.Snapshot, error) {
			if config.BindingSource == radiusShadowSource {
				return radius.LoadShadowProposals(ctx, bindingDirectory)
			}
			return binding.Load(ctx, bindingDirectory)
		},
	})
}

// InitializeState is a separate first-install operation. Existing, missing or
// corrupt history is never reset by runtime startup; an existing state file
// makes this operation fail. It does not write networking or generation state.
func InitializeState(ctx context.Context, directory string) (result error) {
	config, err := loadHelperConfig(ctx, directory)
	if err != nil {
		return err
	}
	store, err := state.Open(ctx, state.Options{Directory: config.StateDir, OwnerUID: 0})
	if err != nil {
		return err
	}
	defer func() { result = errors.Join(result, store.Close()) }()
	return store.Initialize(ctx)
}

func activationEnvironment(pid int, getenv func(string) string) (uintptr, uintptr, bool) {
	if getenv("LISTEN_PID") != strconv.Itoa(pid) || getenv("LISTEN_FDS") != "2" {
		return 0, 0, false
	}
	switch getenv("LISTEN_FDNAMES") {
	case "requests:status":
		return 3, 4, true
	case "status:requests":
		return 4, 3, true
	default:
		return 0, 0, false
	}
}

func inheritedListener(fd uintptr) (*net.UnixListener, error) {
	file := os.NewFile(fd, "supervisor-socket")
	if file == nil {
		return nil, errors.New("firewall: supervisor descriptor unavailable")
	}
	listener, listenErr := net.FileListener(file)
	closeErr := file.Close()
	if err := errors.Join(listenErr, closeErr); err != nil {
		if listener != nil {
			err = errors.Join(err, listener.Close())
		}
		return nil, err
	}
	stream, ok := listener.(*net.UnixListener)
	if !ok {
		return nil, errors.Join(errors.New("firewall: unix stream socket required"), listener.Close())
	}
	stream.SetUnlinkOnClose(false)
	return stream, nil
}

func closeHelperListener(listener *net.UnixListener) error {
	err := listener.Close()
	if errors.Is(err, net.ErrClosed) {
		return nil
	}
	return err
}

// The legacy two-socket interface is retained. The optional third descriptor is
// only the read-only observation endpoint and carries a separate supervisor name.
func helperActivationEnvironment(pid int, getenv func(string) string) (uintptr, uintptr, uintptr, bool) {
	if a, b, ok := activationEnvironment(pid, getenv); ok {
		return a, b, 0, true
	}
	if getenv("LISTEN_PID") != strconv.Itoa(pid) || getenv("LISTEN_FDS") != "3" {
		return 0, 0, 0, false
	}
	names := strings.Split(getenv("LISTEN_FDNAMES"), ":")
	if len(names) != 3 {
		return 0, 0, 0, false
	}
	fds := map[string]uintptr{}
	for i, name := range names {
		if name != "requests" && name != "status" && name != "observations" {
			return 0, 0, 0, false
		}
		if fds[name] != 0 {
			return 0, 0, 0, false
		}
		fds[name] = uintptr(3 + i)
	}
	return fds["requests"], fds["status"], fds["observations"], true
}
