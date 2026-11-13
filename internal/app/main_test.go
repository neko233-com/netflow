package app

import (
	"os"
	"testing"

	"github.com/metacubex/mihomo/component/profile/cachefile"
	C "github.com/metacubex/mihomo/constant"
)

func TestMain(m *testing.M) {
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
