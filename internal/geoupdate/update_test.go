package geoupdate

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

type roundTrip func(*http.Request) (*http.Response, error)

func (f roundTrip) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func fixture(t *testing.T) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("..", "app", "testdata", "GeoIP2-Country-Test.mmdb"))
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func response(data []byte) http.RoundTripper {
	return roundTrip(func(r *http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: 200, Body: io.NopCloser(bytes.NewReader(data)), Header: make(http.Header), Request: r}, nil
	})
}

func write(t *testing.T, dir, name string, value []byte) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dir, name), value, 0600); err != nil {
		t.Fatal(err)
	}
}

func TestPrepareAndResumeAfterPartialApply(t *testing.T) {
	dir, db := t.TempDir(), fixture(t)
	write(t, dir, "Country.mmdb", []byte("old country"))
	write(t, dir, "ASN.mmdb", []byte("old asn"))
	n, err := prepare(context.Background(), dir, []byte("{}"), response(db))
	if err != nil || n != 2 {
		t.Fatalf("prepare: %d %v", n, err)
	}
	if got, _ := os.ReadFile(filepath.Join(dir, "Country.mmdb")); string(got) != "old country" {
		t.Fatal("prepare changed a live database")
	}
	// A crash after replacing one file must not prevent the other from applying.
	write(t, dir, "Country.mmdb", db)
	n, err = ApplyPending(dir)
	if err != nil || n != 2 {
		t.Fatalf("resume: %d %v", n, err)
	}
	for _, name := range []string{"Country.mmdb", "ASN.mmdb"} {
		got, err := os.ReadFile(filepath.Join(dir, name))
		if err != nil || !bytes.Equal(got, db) {
			t.Fatalf("%s not applied: %v", name, err)
		}
	}
	if n, err := ApplyPending(dir); n != 0 || err != nil {
		t.Fatalf("second apply: %d %v", n, err)
	}
}

func TestDownloadFailureAndChangedOriginalArePreserved(t *testing.T) {
	dir := t.TempDir()
	write(t, dir, "Country.mmdb", []byte("old"))
	bad := roundTrip(func(*http.Request) (*http.Response, error) { return nil, errors.New("network failure") })
	if _, err := prepare(context.Background(), dir, []byte("{}"), bad); err == nil {
		t.Fatal("download failure accepted")
	}
	if _, err := os.Stat(filepath.Join(dir, PendingDirectory)); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("failed download published pending state")
	}
	if _, err := prepare(context.Background(), dir, []byte("{}"), response(fixture(t))); err != nil {
		t.Fatal(err)
	}
	write(t, dir, "Country.mmdb", []byte("user changed this"))
	if _, err := ApplyPending(dir); err == nil || !strings.Contains(err.Error(), "已更改") {
		t.Fatalf("changed original accepted: %v", err)
	}
	got, _ := os.ReadFile(filepath.Join(dir, "Country.mmdb"))
	if string(got) != "user changed this" {
		t.Fatal("changed original overwritten")
	}
	name, err := QuarantinePending(dir)
	if err != nil || !strings.HasPrefix(name, RejectedPrefix) {
		t.Fatalf("quarantine: %s %v", name, err)
	}
	if _, err := prepare(context.Background(), dir, []byte("{}"), response(fixture(t))); err != nil {
		t.Fatalf("retry: %v", err)
	}
}

func TestRejectsInvalidDownloadAndForgedManifest(t *testing.T) {
	dir := t.TempDir()
	write(t, dir, "Country.mmdb", []byte("old"))
	if _, err := prepare(context.Background(), dir, []byte("{}"), response([]byte("invalid"))); err == nil {
		t.Fatal("invalid database accepted")
	}
	if err := os.Mkdir(filepath.Join(dir, PendingDirectory), 0700); err != nil {
		t.Fatal(err)
	}
	m, _ := json.Marshal(manifest{Version: 1, Items: []item{{Name: "../outside", Kind: "mmdb", Before: strings.Repeat("0", 64), After: strings.Repeat("0", 64), Payload: "item-0"}}})
	write(t, filepath.Join(dir, PendingDirectory), "manifest.json", m)
	if _, err := ApplyPending(dir); err == nil {
		t.Fatal("path traversal accepted")
	}
}

func TestOnlyHTTPSAndNoDirectFallback(t *testing.T) {
	dir := t.TempDir()
	write(t, dir, "Country.mmdb", []byte("old"))
	called := false
	tr := roundTrip(func(*http.Request) (*http.Response, error) { called = true; return nil, errors.New("unexpected") })
	if _, err := prepare(context.Background(), dir, []byte("geox-url: {mmdb: 'http://example.com/data'}"), tr); err == nil || called {
		t.Fatal("HTTP source accepted")
	}
	if _, err := Prepare(context.Background(), dir, []byte("{}"), 0); err == nil {
		t.Fatal("missing proxy accepted")
	}
}

func TestHTTPSDownloadThroughExplicitProxy(t *testing.T) {
	db := fixture(t)
	destination := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write(db) }))
	defer destination.Close()
	proxyUsed := make(chan struct{}, 1)
	proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodConnect || r.Host != destination.Listener.Addr().String() {
			http.Error(w, "unexpected proxy target", http.StatusForbidden)
			return
		}
		upstream, err := net.Dial("tcp", r.Host)
		if err != nil {
			http.Error(w, "connect failed", http.StatusBadGateway)
			return
		}
		hijacker, ok := w.(http.Hijacker)
		if !ok {
			_ = upstream.Close()
			return
		}
		client, _, err := hijacker.Hijack()
		if err != nil {
			_ = upstream.Close()
			return
		}
		_, _ = io.WriteString(client, "HTTP/1.1 200 Connection Established\r\n\r\n")
		proxyUsed <- struct{}{}
		go func() { _, _ = io.Copy(upstream, client); _ = upstream.Close() }()
		go func() { _, _ = io.Copy(client, upstream); _ = client.Close() }()
	}))
	defer proxy.Close()
	proxyURL, err := url.Parse(proxy.URL)
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	roots.AddCert(destination.Certificate())
	transport := &http.Transport{Proxy: http.ProxyURL(proxyURL), TLSClientConfig: &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS12}}
	defer transport.CloseIdleConnections()
	dir := t.TempDir()
	write(t, dir, "Country.mmdb", []byte("old"))
	config := []byte("geox-url:\n  mmdb: " + destination.URL + "/database\n")
	if n, err := prepare(context.Background(), dir, config, transport); n != 1 || err != nil {
		t.Fatalf("prepare through proxy: %d %v", n, err)
	}
	select {
	case <-proxyUsed:
	default:
		t.Fatal("proxy was bypassed")
	}
	if n, err := ApplyPending(dir); n != 1 || err != nil {
		t.Fatalf("apply: %d %v", n, err)
	}
}
