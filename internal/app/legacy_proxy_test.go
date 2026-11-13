package app

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/neko233-com/netflow/internal/appconfig"
	"github.com/neko233-com/netflow/internal/appdir"
	"github.com/neko233-com/netflow/internal/core"
	"github.com/neko233-com/netflow/internal/sysproxy"
)

type ownedLegacyProxy struct {
	*sysproxy.Memory
	owned, restored bool
}

func (p *ownedLegacyProxy) Owned() (bool, error) { return p.owned, nil }
func (p *ownedLegacyProxy) Restore() error       { p.restored = true; return nil }

func TestPrepareRestoresOnlyOwnedLegacyProxy(t *testing.T) {
	for _, owned := range []bool{false, true} {
		dir := t.TempDir()
		if err := os.WriteFile(filepath.Join(dir, "config.yaml"), []byte("mixed-port: 0\nport: 0\nsocks-port: 0\nlog-level: error\nrules: ['MATCH,DIRECT']\n"), 0600); err != nil {
			t.Fatal(err)
		}
		proxy := &ownedLegacyProxy{Memory: sysproxy.NewMemory(), owned: owned}
		store := appconfig.NewMemory(dir)
		if err := store.Save(appconfig.Settings{SystemProxy: true}); err != nil {
			t.Fatal(err)
		}
		a := New(Options{Dirs: appdir.Fixed(dir), Store: store, Proxy: proxy, Core: core.New()})
		if err := a.Prepare(); err != nil {
			t.Fatal(err)
		}
		if err := a.core.Stop(); err != nil {
			t.Fatal(err)
		}
		if proxy.restored != owned {
			t.Fatalf("owned=%v restored=%v", owned, proxy.restored)
		}
		saved, err := store.Load()
		if err != nil || saved.SystemProxy {
			t.Fatal("legacy preference remained active")
		}
	}
}
