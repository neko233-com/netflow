package app

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
)

func TestFetchProfileThroughProxyNeverFallsBackToDirect(t *testing.T) {
	var direct atomic.Int32
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		direct.Add(1)
		_, _ = w.Write([]byte("rules: [MATCH,DIRECT]"))
	}))
	defer target.Close()
	var seen atomic.Bool
	proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.String() != target.URL+"/subscription" {
			t.Errorf("unexpected proxy request: %s", r.URL.String())
		}
		seen.Store(true)
		_, _ = w.Write([]byte("rules: [MATCH,DIRECT]"))
	}))
	proxyAddr := strings.TrimPrefix(proxy.URL, "http://")
	body, err := fetchProfileThroughProxy(target.URL+"/subscription", proxyAddr)
	if err != nil || len(body) == 0 || !seen.Load() {
		t.Fatalf("proxy fetch: %s %v", body, err)
	}
	proxy.Close()
	if _, err := fetchProfileThroughProxy(target.URL+"/subscription", proxyAddr); err == nil {
		t.Fatal("unavailable proxy unexpectedly succeeded")
	}
	if got := direct.Load(); got != 0 {
		t.Fatalf("direct requests = %d", got)
	}
}
