package core

import (
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/tunnel"
	"github.com/neko233-com/netflow/internal/ruleexpiry"
)

func TestTemporaryRuleExpiresWhileReloadIsBlocked(t *testing.T) {
	entered, release := make(chan struct{}), make(chan struct{})
	var enteredOnce, releaseOnce sync.Once
	unblock := func() { releaseOnce.Do(func() { close(release) }) }
	provider := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		enteredOnce.Do(func() { close(entered) })
		select {
		case <-r.Context().Done():
			return
		case <-release:
		}
		_, _ = w.Write([]byte("proxies: [{name: fresh, type: direct}]\n"))
	}))
	defer provider.Close()
	defer unblock()
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	base := []byte("mixed-port: 0\nport: 0\nsocks-port: 0\nmode: rule\nlog-level: error\ndns: {enable: false}\ntun: {enable: false}\nrules: ['DOMAIN,temporary.test,REJECT', 'MATCH,DIRECT']\n")
	if err := os.WriteFile(path, base, 0600); err != nil {
		t.Fatal(err)
	}
	c := New()
	deadline := time.Now().Add(2 * time.Second)
	c.SetTransformer(func(data []byte, _ string) ([]byte, error) { return ruleexpiry.Encode(data, []time.Time{deadline}) })
	if err := c.Start(dir); err != nil {
		t.Fatal(err)
	}
	defer c.Stop()
	rule := tunnel.Rules()[0]
	meta := &C.Metadata{Host: "temporary.test"}
	if matched, _ := rule.Match(meta, C.RuleMatchHelper{}); !matched {
		t.Fatal("temporary rule not active")
	}
	next := append(append([]byte(nil), base...), []byte("proxy-providers:\n  slow: {type: http, url: '"+provider.URL+"', path: providers/expiry.yaml, interval: 3600, health-check: {enable: false}}\n")...)
	if err := os.WriteFile(path, next, 0600); err != nil {
		t.Fatal(err)
	}
	finished := make(chan error, 1)
	go func() { finished <- c.Reload() }()
	select {
	case <-entered:
	case <-time.After(10 * time.Second):
		t.Fatal("provider did not block")
	}
	if wait := time.Until(deadline.Add(50 * time.Millisecond)); wait > 0 {
		time.Sleep(wait)
	}
	if matched, _ := rule.Match(meta, C.RuleMatchHelper{}); matched {
		t.Fatal("old runtime rule matched after expiry while reload blocked")
	}
	if accepted, err := c.CancelActiveApply(context.Background()); err != nil || !accepted {
		t.Fatalf("cancel: %t %v", accepted, err)
	}
	unblock()
	select {
	case <-finished:
	case <-time.After(10 * time.Second):
		t.Fatal("reload did not stop")
	}
}

func TestTemporaryRuleExpiresWithoutReload(t *testing.T) {
	dir := t.TempDir()
	base := []byte("mixed-port: 0\nport: 0\nsocks-port: 0\nmode: rule\nlog-level: error\ndns: {enable: false}\ntun: {enable: false}\nrules: ['DOMAIN,temporary.test,REJECT', 'DOMAIN,temporary.test,DIRECT', 'MATCH,DIRECT']\n")
	if err := os.WriteFile(filepath.Join(dir, "config.yaml"), base, 0600); err != nil {
		t.Fatal(err)
	}
	c := New()
	deadline := time.Now().Add(700 * time.Millisecond)
	c.SetTransformer(func(data []byte, _ string) ([]byte, error) { return ruleexpiry.Encode(data, []time.Time{deadline}) })
	if err := c.Start(dir); err != nil {
		t.Fatal(err)
	}
	defer c.Stop()
	effective, err := c.EffectiveConfig()
	if err != nil || !bytes.Equal(effective, base) {
		t.Fatal("private metadata changed effective config", err)
	}
	rules := tunnel.Rules()
	if len(rules) != 3 {
		t.Fatalf("rules: %d", len(rules))
	}
	meta := &C.Metadata{Host: "temporary.test"}
	if matched, adapter := rules[0].Match(meta, C.RuleMatchHelper{}); !matched || adapter != "REJECT" {
		t.Fatalf("temporary rule before expiry: %t %q", matched, adapter)
	}
	if wait := time.Until(deadline.Add(50 * time.Millisecond)); wait > 0 {
		time.Sleep(wait)
	}
	if matched, _ := rules[0].Match(meta, C.RuleMatchHelper{}); matched {
		t.Fatal("temporary rule matched after deadline without reload")
	}
	if listed := c.Rules(); len(listed) != 2 || listed[0].Proxy != "DIRECT" {
		t.Fatalf("expired rule remained in active listing: %+v", listed)
	}
	if matched, adapter := rules[1].Match(meta, C.RuleMatchHelper{}); !matched || adapter != "DIRECT" {
		t.Fatalf("identical permanent rule was affected: %t %q", matched, adapter)
	}
}

func TestRuleExpiryRejectsInvalidRulePositions(t *testing.T) {
	if err := applyRuleExpirations(nil, []time.Time{time.Now()}); err == nil {
		t.Fatal("missing rule accepted")
	}
	if err := applyRuleExpirations([]C.Rule{nil}, []time.Time{time.Now()}); err == nil {
		t.Fatal("unwrapped rule accepted")
	}
}

func TestSubscriptionCommentCannotExpirePermanentRules(t *testing.T) {
	dir := t.TempDir()
	base := []byte("# netflow-private-rule-expiries:[1]\nmixed-port: 0\nport: 0\nsocks-port: 0\nmode: rule\nlog-level: error\ndns: {enable: false}\ntun: {enable: false}\nrules: ['DOMAIN,permanent.test,DIRECT', 'MATCH,DIRECT']\n")
	if err := os.WriteFile(filepath.Join(dir, "config.yaml"), base, 0600); err != nil {
		t.Fatal(err)
	}
	c := New()
	c.SetTransformer(func(data []byte, _ string) ([]byte, error) { return ruleexpiry.Encode(data, nil) })
	if err := c.Start(dir); err != nil {
		t.Fatal(err)
	}
	defer c.Stop()
	rules := tunnel.Rules()
	if len(rules) != 2 {
		t.Fatal("unexpected rule count")
	}
	if matched, adapter := rules[0].Match(&C.Metadata{Host: "permanent.test"}, C.RuleMatchHelper{}); !matched || adapter != "DIRECT" {
		t.Fatal("subscription comment disabled permanent rule")
	}
	if effective, err := c.EffectiveConfig(); err != nil || !bytes.Equal(effective, base) {
		t.Fatal("subscription comment was removed", err)
	}
}
