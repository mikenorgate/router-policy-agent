// Command router-policy-collector publishes local IPv4 shadow evidence only.
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
	return cli.RunCollector(ctx, os.Args[1:], cli.CheckIO{Out: os.Stdout, Err: os.Stderr})
}
