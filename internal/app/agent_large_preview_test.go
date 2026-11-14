package app

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/neko233-com/netflow/internal/agent"
	"github.com/neko233-com/netflow/internal/appdir"
	"github.com/neko233-com/netflow/internal/core"
	"github.com/neko233-com/netflow/internal/rewrite"
	"github.com/neko233-com/netflow/internal/sysproxy"
	"github.com/neko233-com/netflow/internal/tun"
)

func TestHeadlessLargeRulePreviewPagesOverAgentBridge(t *testing.T) {
	const count = 70000
	var config strings.Builder
	config.WriteString("mixed-port: 0\nport: 0\nsocks-port: 0\nmode: rule\nlog-level: error\ndns: {enable: false}\ntun: {enable: false}\nrules:\n")
	for i := 0; i < count; i++ {
		fmt.Fprintf(&config, "  - DOMAIN,node-%06d.large-example.test,DIRECT\n", i)
	}
	config.WriteString("  - MATCH,DIRECT\n")
	if config.Len()*2 <= 4<<20 {
		t.Fatal("test fixture does not exceed the former bridge limit")
	}
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "config.yaml"), []byte(config.String()), 0600); err != nil {
		t.Fatal(err)
	}
	a := New(Options{Dirs: appdir.Fixed(dir), Proxy: sysproxy.NewMemory(), TUN: tun.NewMemory(), Core: core.New()})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	ready := make(chan bool, 1)
	finished := make(chan error, 1)
	go func() { finished <- a.RunHeadless(ctx, HeadlessOptions{Ready: func(tun bool) { ready <- tun }}) }()
	select {
	case tun := <-ready:
		if tun {
			t.Fatal("unexpected TUN")
		}
	case err := <-finished:
		t.Fatalf("headless startup failed: %v", err)
	case <-time.After(45 * time.Second):
		t.Fatal("headless startup timed out")
	}
	client := agent.Client{Dir: dir, Timeout: 45 * time.Second}
	var preview agent.Preview
	change := agent.Change{Scope: "global", Operation: "set", Layer: rewrite.Layer{Prepend: []string{"DOMAIN,preview-first.test,DIRECT"}}}
	if err := client.Call(context.Background(), "preview", change, &preview); err != nil {
		t.Fatal(err)
	}
	if preview.RulesBeforeTotal != count+1 || preview.RulesAfterTotal != count+2 || !preview.RulesBeforeTruncated || !preview.RulesAfterTruncated || len(preview.RulesAfter) != 100 {
		t.Fatalf("incorrect preview totals: %+v", preview)
	}
	var page agent.PreviewRulesResult
	if err := client.Call(context.Background(), "preview-rules", agent.PreviewRulesArgs{ProposalID: preview.ProposalID, Stage: "before", Limit: 1}, &page); err != nil || len(page.Rules) != 1 || page.Rules[0] != "DOMAIN,node-000000.large-example.test,DIRECT" {
		t.Fatalf("first before page incorrect: %+v %v", page, err)
	}
	if err := client.Call(context.Background(), "preview-rules", agent.PreviewRulesArgs{ProposalID: preview.ProposalID, Stage: "after", Offset: count, Limit: 10}, &page); err != nil {
		t.Fatal(err)
	}
	if page.Total != count+2 || page.NextOffset != page.Total || len(page.Rules) != 2 || page.Rules[1] != "MATCH,DIRECT" {
		t.Fatalf("last page incorrect: %+v", page)
	}
	var action agent.ActionResult
	if err := client.Call(context.Background(), "cancel-preview", agent.ApplyArgs{ProposalID: preview.ProposalID}, &action); err != nil || !action.OK {
		t.Fatalf("cancel: %+v %v", action, err)
	}
	if err := client.Call(context.Background(), "preview-rules", agent.PreviewRulesArgs{ProposalID: preview.ProposalID, Stage: "after"}, &page); err == nil {
		t.Fatal("canceled proposal remained accessible")
	}
	if err := client.Call(context.Background(), "shutdown", nil, &action); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-finished:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(30 * time.Second):
		t.Fatal("headless shutdown timed out")
	}
}
