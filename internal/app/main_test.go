package app

import (
	"fmt"
	"os"
	"testing"

	"github.com/metacubex/mihomo/component/profile/cachefile"
	C "github.com/metacubex/mihomo/constant"
	"github.com/neko233-com/netflow/internal/validation"
)

func TestMain(m *testing.M) {
	if len(os.Args) == 2 && os.Args[1] == "--internal-validate" {
		if err := validation.Serve(os.Stdin, os.Stdout); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		os.Exit(0)
	}
	validationExecutablePath = os.Executable
	dir, err := os.MkdirTemp("", "netflow-app-cache-")
	if err != nil {
		panic(err)
	}
	C.SetHomeDir(dir)
	cache := cachefile.Cache()
	code := m.Run()
	if cache.DB != nil {
		_ = cache.Close()
	}
	_ = os.RemoveAll(dir)
	os.Exit(code)
}
