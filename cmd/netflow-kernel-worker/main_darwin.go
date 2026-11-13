//go:build darwin

package main

import (
	"context"
	"flag"
	"os"
	"time"

	C "github.com/metacubex/mihomo/constant"
	"github.com/neko233-com/netflow/internal/coreipc"
)

func main() {
	socket := flag.String("socket", "", "private local socket")
	parent := flag.Int("parent", 0, "launching process ID")
	uid := flag.Int("uid", -1, "launching user ID")
	flag.Parse()
	if *socket == "" || *parent <= 0 || *uid < 0 || os.Geteuid() != 0 {
		os.Exit(2)
	}
	C.ConstrainPaths()
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	conn, err := coreipc.DialDarwinParent(ctx, *socket, *parent, uint32(*uid))
	if err != nil {
		os.Exit(3)
	}
	if err = coreipc.NewDarwinElevatedWorker().Serve(conn); err != nil {
		os.Exit(4)
	}
}
