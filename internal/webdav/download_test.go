package webdav

import (
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
)

const testName = "netflow-20261114-120000-0123456789abcdef0123456789abcdef.zip"

func TestDownloadAuthenticatesAndRestrictsResourceName(t *testing.T) {
	var calls atomic.Int32
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		user, password, ok := r.BasicAuth()
		if !ok || user != "demo" || password != "secret" || r.URL.Path != "/dav/"+testName || r.URL.RawQuery != "token=private" || r.Method != http.MethodGet {
			t.Error("invalid download request")
		}
		_, _ = w.Write([]byte("backup"))
	}))
	defer server.Close()
	client := Client{HTTP: server.Client()}
	creds := Credentials{URL: server.URL + "/dav/?token=private", User: "demo", Password: "secret"}
	var body bytes.Buffer
	if err := client.Download(context.Background(), creds, testName, &body); err != nil || body.String() != "backup" {
		t.Fatalf("download failed: %v", err)
	}
	for _, invalid := range []string{"../" + testName, "netflow-other.zip", testName + "/child", "https://example.invalid/"} {
		if err := client.Download(context.Background(), creds, invalid, &body); err == nil {
			t.Fatal("accepted unsafe remote name")
		}
	}
	if calls.Load() != 1 {
		t.Fatal("invalid name reached server")
	}
}

func TestDownloadRejectsOversizeRedirectAndSecretLeaks(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Length", strconv.Itoa(MaxArchiveBytes+1))
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()
	creds := Credentials{URL: server.URL + "/?token=synthetic-secret", Password: "sensitive"}
	var dest bytes.Buffer
	if err := (Client{HTTP: server.Client()}).Download(context.Background(), creds, testName, &dest); err == nil || strings.Contains(err.Error(), "secret") || strings.Contains(err.Error(), "sensitive") {
		t.Fatal("oversize download accepted or leaked secrets")
	}
	if dest.Len() != 0 {
		t.Fatal("oversize body was written")
	}
	var redirected atomic.Bool
	target := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { redirected.Store(true) }))
	defer target.Close()
	redirect := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, target.URL, http.StatusTemporaryRedirect)
	}))
	defer redirect.Close()
	if err := (Client{HTTP: redirect.Client()}).Download(context.Background(), Credentials{URL: redirect.URL}, testName, &dest); err == nil || redirected.Load() {
		t.Fatal("followed download redirect")
	}
}
