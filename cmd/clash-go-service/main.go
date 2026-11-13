// Command clash-go-service is the privileged helper installed as a launchd daemon.
// It listens on a unix socket and starts the embedded core so TUN can open a utun device.
package main

import (
	"flag"
	"log"
	"net"
	"os"
	"strings"

	"github.com/neko233-com/netflow/internal/core"
	"github.com/neko233-com/netflow/internal/service"
)

func main() {
	socket := flag.String("socket", service.SocketPath, "unix socket")
	tokenFile := flag.String("token-file", service.TokenPath, "auth token file")
	flag.Parse()
	token, err := os.ReadFile(*tokenFile)
	if err != nil {
		log.Fatal(err)
	}
	_ = os.Remove(*socket)
	ln, err := net.Listen("unix", *socket)
	if err != nil {
		log.Fatal(err)
	}
	if err := os.Chmod(*socket, 0o666); err != nil {
		log.Fatal(err)
	}
	if err := service.Serve(ln, strings.TrimSpace(string(token)), &coreHost{}); err != nil {
		log.Fatal(err)
	}
}

// coreHost runs mihomo in this process. The daemon is root, so TUN can open.
type coreHost struct {
	core *core.Core
}

func (h *coreHost) Start(dir string) error {
	if h.core == nil {
		h.core = core.New()
	}
	if h.core.Status().Running {
		return h.core.Reload()
	}
	return h.core.Start(dir)
}

func (h *coreHost) Running() bool {
	return h.core != nil && h.core.Status().Running
}
