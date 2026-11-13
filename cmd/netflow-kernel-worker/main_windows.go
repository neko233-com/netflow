//go:build windows

// The worker owns the elevated kernel, and accepts commands only over the
// private pipe whose server PID matches the launching desktop process.
package main

import (
	"context"
	"flag"
	"os"
	"time"

	C "github.com/metacubex/mihomo/constant"
	"github.com/neko233-com/netflow/internal/coreipc"
	"golang.org/x/sys/windows"
)

func main() {
	pipe := flag.String("pipe", "", "private named pipe")
	parent := flag.Uint("parent", 0, "launching process ID")
	flag.Parse()
	if *pipe == "" || *parent == 0 || !windows.GetCurrentProcessToken().IsElevated() {
		os.Exit(2)
	}
	// Environment variables inherited from the unprivileged desktop must not
	// disable the elevated kernel's configuration path restrictions.
	C.ConstrainPaths()
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	conn, err := coreipc.DialParent(ctx, *pipe, uint32(*parent))
	if err != nil {
		os.Exit(3)
	}
	if err = coreipc.NewWorker().Serve(conn); err != nil {
		os.Exit(4)
	}
}
