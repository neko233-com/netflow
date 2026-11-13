package app

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/neko233-com/netflow/internal/profile"
	"github.com/neko233-com/netflow/internal/sysproxy"
)

func TestSubscriptionUsesManualSystemProxyWithoutDirectFallback(t *testing.T) {
	var direct atomic.Int32
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { direct.Add(1); _, _ = w.Write([]byte("direct")) }))
	defer target.Close()
	var hits atomic.Int32
	proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { hits.Add(1); _, _ = w.Write([]byte("proxied")) }))
	addr := strings.TrimPrefix(proxy.URL, "http://")
	system := sysproxy.NewMemory()
	if err := system.Set(sysproxy.Settings{Enabled: true, HTTP: "http=" + addr}); err != nil {
		t.Fatal(err)
	}
	a := &App{proxy: system}
	client, err := a.subscriptionClient(profile.CatalogOption{UseSystemProxy: true, TimeoutSeconds: 2}, false)
	if err != nil {
		t.Fatal(err)
	}
	defer client.CloseIdleConnections()
	result, err := fetchProfileResponse(target.URL, client, "")
	if err != nil || string(result.body) != "proxied" || hits.Load() != 1 {
		t.Fatalf("proxy request: %q %v", result.body, err)
	}
	if _, err := fetchProfileResponse("https://example.invalid", client, ""); err == nil {
		t.Fatal("missing HTTPS proxy fell back to direct")
	}
	proxy.Close()
	if _, err := fetchProfileResponse(target.URL, client, ""); err == nil {
		t.Fatal("unavailable system proxy fell back to direct")
	}
	if direct.Load() != 0 {
		t.Fatal("contacted target directly")
	}
}

func TestManualSystemProxySelectsIndependentProtocols(t *testing.T) {
	lookup, err := manualSystemProxy(sysproxy.Settings{Enabled: true, SchemeSpecific: true, HTTP: "127.0.0.1:1001", HTTPS: "127.0.0.1:1002"})
	if err != nil {
		t.Fatal(err)
	}
	for scheme, want := range map[string]string{"http": "127.0.0.1:1001", "https": "127.0.0.1:1002"} {
		req, _ := http.NewRequest("GET", scheme+"://example.test", nil)
		got, err := lookup(req)
		if err != nil || got.Host != want {
			t.Fatalf("%s proxy = %v %v", scheme, got, err)
		}
	}
	for _, settings := range []sysproxy.Settings{{}, {Enabled: true}, {Enabled: true, HTTP: "http=invalid"}, {Enabled: true, HTTP: "ftp://127.0.0.1:9"}} {
		if _, err := manualSystemProxy(settings); err == nil {
			t.Fatalf("invalid proxy accepted: %+v", settings)
		}
	}
}
