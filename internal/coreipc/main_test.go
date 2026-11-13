package coreipc

import (
	"os"
	"testing"

	"github.com/metacubex/mihomo/component/profile/cachefile"
	C "github.com/metacubex/mihomo/constant"
)

// mihomo keeps its cache open for the process lifetime. A shared directory
// keeps per-test temp cleanup independent of that process-wide singleton.
func TestMain(m *testing.M) {
	if os.Getenv("NETFLOW_DOCKER_WORKER_CHILD") == "1" {
		os.Exit(m.Run())
	}
	dir, err := os.MkdirTemp("", "netflow-core-cache-")
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
