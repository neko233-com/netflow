package app

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/neko233-com/netflow/internal/profile"
)

func TestSubscriptionFetchErrorsDoNotExposeAddressSecrets(t *testing.T) {
	client := newSubscriptionClient("", time.Second, false)
	defer client.CloseIdleConnections()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusForbidden) }))
	address, err := url.Parse(server.URL)
	if err != nil {
		t.Fatal(err)
	}
	address.User = url.UserPassword("synthetic-user", "synthetic-password")
	address.RawQuery = "token=synthetic-token"
	for _, raw := range []string{address.String(), "http://synthetic-password@[bad?token=synthetic-token"} {
		_, err := fetchProfileResponse(raw, client, "")
		if err == nil || strings.Contains(err.Error(), "synthetic-") {
			t.Fatalf("unsafe subscription error: %v", err)
		}
	}
	server.Close()
	_, err = fetchProfileResponse(address.String(), client, "")
	if err == nil || strings.Contains(err.Error(), "synthetic-") {
		t.Fatalf("unsafe network error: %v", err)
	}
}

func TestSubscriptionFetchTimeoutRetainsDeadlineSemantics(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) { <-r.Context().Done() }))
	defer server.Close()
	client := newSubscriptionClient("", 50*time.Millisecond, false)
	defer client.CloseIdleConnections()
	_, err := fetchProfileResponse(server.URL+"/?token=synthetic-token", client, "")
	if !errors.Is(err, context.DeadlineExceeded) || strings.Contains(err.Error(), "synthetic-token") {
		t.Fatalf("unsafe timeout error: %v", err)
	}
}

func TestSubscriptionFetchCancellationStopsInFlightRequest(t *testing.T) {
	entered := make(chan struct{})
	server := httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		close(entered)
		<-r.Context().Done()
	}))
	defer server.Close()
	client := newSubscriptionClient("", 10*time.Second, false)
	defer client.CloseIdleConnections()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		_, err := fetchProfileResponseContext(ctx, server.URL, client, "")
		done <- err
	}()
	select {
	case <-entered:
	case <-time.After(5 * time.Second):
		cancel()
		t.Fatal("subscription request did not start")
	}
	cancel()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("unexpected cancellation error: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("subscription cancellation did not stop the request")
	}
}

func TestSubscriptionDirectAndRedirectPolicy(t *testing.T) {
	var plainHits atomic.Int32
	plain := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		plainHits.Add(1)
		_, _ = w.Write([]byte("rules: ['MATCH,DIRECT']"))
	}))
	defer plain.Close()
	secure := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, plain.URL, http.StatusFound)
	}))
	defer secure.Close()
	client := newSubscriptionClient("", 3*time.Second, true)
	defer client.CloseIdleConnections()
	if transport, ok := client.Transport.(*http.Transport); !ok || transport.Proxy != nil {
		t.Fatal("direct subscription inherited an environment proxy")
	}
	address, err := url.Parse(secure.URL)
	if err != nil {
		t.Fatal(err)
	}
	address.User = url.UserPassword("synthetic", "secret")
	if _, err := fetchProfileResponse(address.String(), client, ""); err == nil {
		t.Fatal("HTTPS to HTTP redirect was accepted")
	}
	if plainHits.Load() != 0 {
		t.Fatal("downgraded request reached the HTTP server")
	}
	if _, err := fetchProfileResponse(plain.URL, client, ""); err != nil || plainHits.Load() != 1 {
		t.Fatalf("explicit HTTP subscription failed: %v", err)
	}
	redirect := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, plain.URL, http.StatusFound)
	}))
	defer redirect.Close()
	called := false
	client.CheckRedirect = func(*http.Request, []*http.Request) error { called = true; return nil }
	if _, err := fetchProfileResponse(redirect.URL, client, ""); err != nil || !called || plainHits.Load() != 2 {
		t.Fatalf("safe redirect or caller policy failed: called=%v err=%v", called, err)
	}
}

func TestSubscriptionRedirectDoesNotForwardSecrets(t *testing.T) {
	headers := make(chan [2]string, 1)
	destination := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		headers <- [2]string{r.Header.Get("Referer"), r.Header.Get("Authorization")}
		_, _ = w.Write([]byte("rules: ['MATCH,DIRECT']"))
	}))
	defer destination.Close()
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, destination.URL, http.StatusFound)
	}))
	defer origin.Close()
	address, err := url.Parse(origin.URL + "/sub?token=synthetic-secret")
	if err != nil {
		t.Fatal(err)
	}
	address.User = url.UserPassword("synthetic-user", "synthetic-password")
	client := newSubscriptionClient("", 3*time.Second, false)
	defer client.CloseIdleConnections()
	// Even a caller-supplied redirect hook must not reintroduce secrets.
	client.CheckRedirect = func(req *http.Request, _ []*http.Request) error {
		req.Header.Set("Referer", address.String())
		req.Header.Set("Authorization", "synthetic-secret")
		return nil
	}
	if _, err := fetchProfileResponse(address.String(), client, ""); err != nil {
		t.Fatal(err)
	}
	if got := <-headers; got != ([2]string{}) {
		t.Fatalf("redirect forwarded sensitive headers: %q", got)
	}
}

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
