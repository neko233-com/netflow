package agent

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
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

func TestClientWaitsForSlowLocalProbe(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var in request
		if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
			t.Error(err)
			return
		}
		if in.Method == "ping" {
			time.Sleep(1200 * time.Millisecond)
		}
		_, _ = w.Write([]byte(`{"result":{"ok":true}}`))
	}))
	defer server.Close()
	dir := t.TempDir()
	parent := filepath.Join(dir, "agent")
	if err := os.MkdirAll(parent, 0700); err != nil {
		t.Fatal(err)
	}
	data, err := json.Marshal(endpoint{Address: strings.TrimPrefix(server.URL, "http://"), Token: strings.Repeat("a", 64), PID: 1})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(parent, "endpoint-slow.json"), data, 0600); err != nil {
		t.Fatal(err)
	}
	var result map[string]bool
	if err := (Client{Dir: dir}).Call(context.Background(), "status", nil, &result); err != nil || !result["ok"] {
		t.Fatalf("slow live bridge was not discovered: %v", err)
	}
}

func TestClientReportsProbeErrorWithoutLeakingToken(t *testing.T) {
	dir := t.TempDir()
	b, err := Start(dir, func(context.Context, string, json.RawMessage) (any, error) { return nil, nil })
	if err != nil {
		t.Fatal(err)
	}
	defer b.Close()
	data, err := os.ReadFile(b.file)
	if err != nil {
		t.Fatal(err)
	}
	var ep endpoint
	if err := json.Unmarshal(data, &ep); err != nil {
		t.Fatal(err)
	}
	ep.Token = strings.Repeat("a", 64)
	if ep.Token == b.token {
		ep.Token = strings.Repeat("b", 64)
	}
	data, _ = json.Marshal(ep)
	if err := os.WriteFile(b.file, data, 0600); err != nil {
		t.Fatal(err)
	}
	err = (Client{Dir: dir}).Call(context.Background(), "status", nil, nil)
	if err == nil || !strings.Contains(err.Error(), "endpoint probe failed") || !strings.Contains(err.Error(), "HTTP 401") || strings.Contains(err.Error(), ep.Token) {
		t.Fatalf("unexpected probe diagnostic: %v", err)
	}
}
