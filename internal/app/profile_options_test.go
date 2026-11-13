package app

import (
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/neko233-com/netflow/internal/profile"
)

func TestSubscriptionClientHonorsTLSUserAgentTimeoutAndProxyPolicy(t *testing.T) {
	var received atomic.Bool
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("User-Agent") == "NetFlow-Test/1" {
			received.Store(true)
		}
		_, _ = w.Write([]byte("rules: [MATCH,DIRECT]"))
	}))
	defer server.Close()
	a := &App{}
	normal, err := a.subscriptionClient(profile.CatalogOption{TimeoutSeconds: 3}, false)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = fetchProfileResponse(server.URL, normal, "NetFlow-Test/1"); err == nil {
		t.Fatal("untrusted certificate accepted without opt-in")
	}
	normal.CloseIdleConnections()
	opts := profile.CatalogOption{TimeoutSeconds: 3, UserAgent: "NetFlow-Test/1", AcceptInvalid: true}
	client, err := a.subscriptionClient(opts, false)
	if err != nil {
		t.Fatal(err)
	}
	defer client.CloseIdleConnections()
	if client.Timeout != 3*time.Second {
		t.Fatalf("timeout %v", client.Timeout)
	}
	if _, err = fetchProfileResponse(server.URL, client, opts.UserAgent); err != nil || !received.Load() {
		t.Fatalf("configured fetch: %v", err)
	}
	for _, options := range []profile.CatalogOption{{UseClashProxy: true}, {UseSystemProxy: true}, {TimeoutSeconds: 301}, {UserAgent: "x\r\ny"}} {
		if _, err := a.subscriptionClient(options, false); err == nil {
			t.Fatalf("unsafe or unsupported options accepted: %+v", options)
		}
	}
}
