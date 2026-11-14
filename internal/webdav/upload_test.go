package webdav

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestUploadUsesHTTPSConditionalPutAndPreservesCollection(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPut || !strings.HasPrefix(r.URL.Path, "/dav/My folder/netflow-") || !strings.HasSuffix(r.URL.Path, ".zip") || r.URL.RawQuery != "token=private" {
			t.Error("invalid request destination")
		}
		user, password, ok := r.BasicAuth()
		if !ok || user != "demo" || password != "secret" || r.Header.Get("If-None-Match") != "*" || r.Header.Get("Content-Type") != "application/zip" {
			t.Error("upload authentication or preconditions missing")
		}
		body, err := io.ReadAll(r.Body)
		if err != nil || string(body) != "backup" {
			t.Errorf("invalid body: %q %v", body, err)
		}
		w.WriteHeader(http.StatusCreated)
	}))
	defer server.Close()
	name, err := (Client{HTTP: server.Client()}).Upload(context.Background(), Credentials{URL: server.URL + "/dav/My%20folder/?token=private", User: "demo", Password: "secret"}, strings.NewReader("backup"), 6)
	if err != nil || !strings.HasPrefix(name, "netflow-") || strings.Contains(name, "private") {
		t.Fatalf("upload failed: %q %v", name, err)
	}
}

type testTransport func(*http.Request) (*http.Response, error)

func (f testTransport) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

type gatedReader struct {
	started, release chan struct{}
	once             sync.Once
	sent             bool
}

func (r *gatedReader) Read(p []byte) (int, error) {
	r.once.Do(func() { close(r.started); <-r.release })
	if r.sent {
		return 0, io.EOF
	}
	r.sent = true
	return copy(p, "backup"), io.EOF
}

func TestUploadWaitsForAsynchronousRequestBodyClose(t *testing.T) {
	reader := &gatedReader{started: make(chan struct{}), release: make(chan struct{})}
	client := &http.Client{Transport: testTransport(func(r *http.Request) (*http.Response, error) {
		go func() { _, _ = io.Copy(io.Discard, r.Body); _ = r.Body.Close() }()
		return &http.Response{StatusCode: http.StatusCreated, Body: io.NopCloser(strings.NewReader("")), Header: make(http.Header), Request: r}, nil
	})}
	done := make(chan error, 1)
	go func() {
		_, err := (Client{HTTP: client}).Upload(context.Background(), Credentials{URL: "https://example.invalid/dav"}, reader, 6)
		done <- err
	}()
	<-reader.started
	select {
	case err := <-done:
		t.Fatalf("upload returned while request body was still reading: %v", err)
	case <-time.After(50 * time.Millisecond):
	}
	close(reader.release)
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("upload did not finish after body closed")
	}
}

func TestUploadRejectsRedirectAndDoesNotLeakCredentials(t *testing.T) {
	var redirected atomic.Bool
	target := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		redirected.Store(true)
		w.WriteHeader(http.StatusCreated)
	}))
	defer target.Close()
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, target.URL, http.StatusTemporaryRedirect)
	}))
	defer server.Close()
	_, err := (Client{HTTP: server.Client()}).Upload(context.Background(), Credentials{URL: server.URL + "/?token=secret", User: "demo", Password: "sensitive"}, strings.NewReader("x"), 1)
	if err == nil || redirected.Load() || strings.Contains(err.Error(), "secret") || strings.Contains(err.Error(), "sensitive") {
		t.Fatalf("unsafe redirect or error: %v", err)
	}
}

func TestUploadRequiresTLSAndRejectsInvalidOrShortInput(t *testing.T) {
	for _, endpoint := range []string{"http://example.invalid/dav", "https://example.invalid/dav#fragment", "file:///tmp/dav", ":bad"} {
		if _, err := (Client{}).Upload(context.Background(), Credentials{URL: endpoint}, strings.NewReader("x"), 1); err == nil {
			t.Fatal("accepted unsafe endpoint")
		}
	}
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.Copy(io.Discard, r.Body)
		w.WriteHeader(http.StatusCreated)
	}))
	defer server.Close()
	if _, err := (Client{HTTP: server.Client()}).Upload(context.Background(), Credentials{URL: server.URL}, strings.NewReader("x"), 4); err == nil {
		t.Fatal("accepted incomplete upload")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := (Client{HTTP: server.Client()}).Upload(ctx, Credentials{URL: server.URL}, strings.NewReader("x"), 1); err == nil {
		t.Fatal("accepted canceled upload")
	}
}
