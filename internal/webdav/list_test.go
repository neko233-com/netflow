package webdav

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
)

func davItem(href, status, kind string) string {
	return fmt.Sprintf(`<d:response><d:href>%s</d:href><d:propstat><d:prop><d:resourcetype>%s</d:resourcetype></d:prop><d:status>HTTP/1.1 %s</d:status></d:propstat></d:response>`, href, kind, status)
}

func TestListOnlyReturnsSameCollectionBackups(t *testing.T) {
	older := "netflow-20260101-120000-0123456789abcdef0123456789abcdef.zip"
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		user, pass, ok := r.BasicAuth()
		if !ok || user != "demo" || pass != "secret" || r.Method != "PROPFIND" || r.Header.Get("Depth") != "1" || r.URL.RawQuery != "token=private" {
			t.Error("invalid listing request")
		}
		w.WriteHeader(http.StatusMultiStatus)
		_, _ = fmt.Fprint(w, `<d:multistatus xmlns:d="DAV:">`+
			davItem("/dav/"+older, "200 OK", "")+
			davItem("/dav/"+testName, "200 OK", "")+
			davItem("/dav/"+testName, "200 OK", "")+
			davItem("/dav/nested/"+testName, "200 OK", "")+
			davItem("https://evil.invalid/dav/"+testName, "200 OK", "")+
			davItem("/dav/"+testName, "404 Not Found", "")+
			davItem("/dav/netflow-20250101-120000-0123456789abcdef0123456789abcdef.zip", "200 OK", "<d:collection/>")+
			`</d:multistatus>`)
	}))
	defer server.Close()
	names, err := (Client{HTTP: server.Client()}).List(context.Background(), Credentials{URL: server.URL + "/dav?token=private", User: "demo", Password: "secret"})
	if err != nil || len(names) != 2 || names[0] != testName || names[1] != older {
		t.Fatalf("unexpected listing: %v %v", names, err)
	}
}

func TestListRejectsMalformedOversizeAndRedirects(t *testing.T) {
	for _, body := range []string{"<not-dav/>", `<d:multistatus xmlns:d="DAV:">`, strings.Repeat("x", maxListBytes+1)} {
		server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusMultiStatus)
			_, _ = fmt.Fprint(w, body)
		}))
		_, err := (Client{HTTP: server.Client()}).List(context.Background(), Credentials{URL: server.URL + "/?token=synthetic-secret"})
		server.Close()
		if err == nil || strings.Contains(err.Error(), "synthetic-secret") {
			t.Fatal("invalid listing accepted or leaked secret")
		}
	}
	var redirected atomic.Bool
	target := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { redirected.Store(true) }))
	defer target.Close()
	redirect := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, target.URL, http.StatusTemporaryRedirect)
	}))
	defer redirect.Close()
	if _, err := (Client{HTTP: redirect.Client()}).List(context.Background(), Credentials{URL: redirect.URL}); err == nil || redirected.Load() {
		t.Fatal("listing followed redirect")
	}
}
