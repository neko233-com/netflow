package agent

import (
	"context"
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestBridgeRequiresTokenAndRejectsBrowserOrigin(t *testing.T) {
	dir := t.TempDir()
	b, err := Start(dir, func(_ context.Context, method string, _ json.RawMessage) (any, error) {
		return map[string]string{"method": method}, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = b.Close() })
	var result map[string]string
	if err := (Client{Dir: dir}).Call(context.Background(), "status", nil, &result); err != nil || result["method"] != "status" {
		t.Fatalf("client: %+v %v", result, err)
	}
	for _, tc := range []struct {
		token, origin string
		want          int
	}{{"", "", 401}, {b.token, "https://example.org", 403}} {
		req, _ := http.NewRequest(http.MethodPost, "http://"+b.listener.Addr().String()+"/rpc", strings.NewReader(`{"method":"status"}`))
		if tc.token != "" {
			req.Header.Set("Authorization", "Bearer "+tc.token)
		}
		if tc.origin != "" {
			req.Header.Set("Origin", tc.origin)
		}
		res, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		res.Body.Close()
		if res.StatusCode != tc.want {
			t.Fatalf("got %d want %d", res.StatusCode, tc.want)
		}
	}
	if err := b.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(b.file); !os.IsNotExist(err) {
		t.Fatalf("endpoint remains: %v", err)
	}
}

func TestClientIgnoresStaleAndRejectsAmbiguousInstances(t *testing.T) {
	dir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dir, "agent"), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "agent", "endpoint-stale.json"), []byte(`{"address":"8.8.8.8:53","token":"0000000000000000000000000000000000000000000000000000000000000000"}`), 0600); err != nil {
		t.Fatal(err)
	}
	handler := func(context.Context, string, json.RawMessage) (any, error) { return "ok", nil }
	b1, err := Start(dir, handler)
	if err != nil {
		t.Fatal(err)
	}
	defer b1.Close()
	b2, err := Start(dir, handler)
	if err != nil {
		t.Fatal(err)
	}
	defer b2.Close()
	if err := (Client{Dir: dir}).Call(context.Background(), "status", nil, nil); err == nil || !strings.Contains(err.Error(), "multiple") {
		t.Fatalf("ambiguity: %v", err)
	}
}
