// Command router-policy-reader collects fresh LDAPS policy as an unprivileged process.
package main

import (
	"context"
	"os"
	"os/signal"
	"syscall"

	"github.com/mikenorgate/router-policy-agent/internal/cli"
)

func main() { os.Exit(run()) }

func run() int {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	return cli.RunReader(ctx, os.Args[1:], cli.CheckIO{Out: os.Stdout, Err: os.Stderr})
}
