package app

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/neko233-com/netflow/internal/agent"
	"github.com/neko233-com/netflow/internal/appconfig"
	"github.com/neko233-com/netflow/internal/appdir"
	"github.com/neko233-com/netflow/internal/core"
	"github.com/neko233-com/netflow/internal/rewrite"
	"github.com/neko233-com/netflow/internal/sysproxy"
	"github.com/neko233-com/netflow/internal/tun"
)

func TestGUIRulePreviewValidationDoesNotBlockEventLoop(t *testing.T) {
	dir := t.TempDir()
	base := []byte(fmt.Sprintf("mixed-port: %d\nport: 0\nsocks-port: 0\nmode: rule\nlog-level: error\ndns: {enable: false}\ntun: {enable: false}\nrules: ['MATCH,DIRECT']\n", freePort(t)))
	if err := os.WriteFile(filepath.Join(dir, "config.yaml"), base, 0600); err != nil {
		t.Fatal(err)
	}
	a := New(Options{Dirs: appdir.Fixed(dir), Store: appconfig.NewMemory(dir), Proxy: sysproxy.NewMemory(), TUN: tun.NewMemory(), Core: core.New()})
	if err := a.Prepare(); err != nil {
		t.Fatal(err)
	}
	defer a.core.Stop()
	dispatcher := newSerialDispatcher()
	defer dispatcher.close()
	a.dispatch = dispatcher.call
	type result struct {
		preview agent.Preview
		err     error
	}
	results := make(chan result, 1)
	validationSlots <- struct{}{}
	locked := true
	defer func() {
		if locked {
			<-validationSlots
		}
	}()
	dispatcher.call(func() {
		a.previewRewriteAsync(agent.Change{Scope: "global", Operation: "set", Layer: rewrite.Layer{Prepend: []string{"DOMAIN,gui.test,DIRECT"}}}, func(p agent.Preview, err error) { results <- result{p, err} })
	})
	responsive := make(chan struct{})
	go dispatcher.call(func() { close(responsive) })
	select {
	case <-responsive:
	case <-time.After(2 * time.Second):
		t.Fatal("UI loop blocked by offline validation")
	}
	<-validationSlots
	locked = false
	select {
	case got := <-results:
		if got.err != nil || got.preview.ProposalID == "" {
			t.Fatalf("preview failed: %+v %v", got.preview, got.err)
		}
		dispatcher.call(func() {
			if _, err := a.agentApply(got.preview.ProposalID); err != nil {
				t.Error(err)
			}
		})
	case <-time.After(30 * time.Second):
		t.Fatal("GUI preview did not finish")
	}
	var zero uint64
	dispatcher.call(func() {
		a.previewRollbackAsync(agent.RollbackArgs{Revision: &zero, Scope: "global"}, func(p agent.Preview, err error) { results <- result{p, err} })
	})
	select {
	case got := <-results:
		if got.err != nil || got.preview.ProposalID == "" {
			t.Fatalf("GUI rollback preview: %+v %v", got.preview, got.err)
		}
		dispatcher.call(func() {
			if _, err := a.agentApply(got.preview.ProposalID); err != nil {
				t.Error(err)
			}
			if len(a.rewrites.Snapshot().Global.Prepend) != 0 {
				t.Error("GUI rollback did not restore the original rules")
			}
		})
	case <-time.After(30 * time.Second):
		t.Fatal("GUI rollback preview did not finish")
	}
}
