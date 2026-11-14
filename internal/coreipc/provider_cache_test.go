package coreipc

import (
	"crypto/sha256"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/metacubex/mihomo/common/utils"
	"github.com/metacubex/mihomo/component/resource"
	P "github.com/metacubex/mihomo/constant/provider"
)

// testStage stands in for the worker's private filesystem; it never points at
// the user directory, just as the elevated Windows stage does not.
type testStage struct{ dir string }

type testSnapshot struct {
	path string
	data []byte
}

func (*testSnapshot) VehicleType() P.VehicleType { return P.HTTP }
func (s *testSnapshot) WithSnapshot(fn func(P.Vehicle, utils.HashType) error) error {
	return fn(resource.NewHTTPVehicle("https://example.invalid", s.path, "", nil, time.Second, 0), utils.MakeHash(s.data))
}

func (s *testStage) Directory() string { return s.dir }
func (s *testStage) Close() error      { return nil }
func (s *testStage) Apply(files []StageFile) error {
	for _, file := range files {
		path := filepath.Join(s.dir, file.Path)
		if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
			return err
		}
		if err := os.WriteFile(path, file.Data, 0600); err != nil {
			return err
		}
	}
	return nil
}

func TestProviderCacheRejectsUserChangesAndLinks(t *testing.T) {
	dir := t.TempDir()
	root, err := os.OpenRoot(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	if err := os.Mkdir(filepath.Join(dir, "providers"), 0700); err != nil {
		t.Fatal(err)
	}
	name := filepath.Join("providers", "cache.yaml")
	if err := os.WriteFile(filepath.Join(dir, name), []byte("user edit"), 0600); err != nil {
		t.Fatal(err)
	}
	old := sha256.Sum256([]byte("previous"))
	if err := persistProviderCache(root, ProviderCache{Path: name, Data: []byte("downloaded")}, old, true); err == nil {
		t.Fatal("user modification was overwritten")
	}
	got, _ := os.ReadFile(filepath.Join(dir, name))
	if string(got) != "user edit" {
		t.Fatalf("user file changed: %q", got)
	}
	if err := persistProviderCache(root, ProviderCache{Path: name, Data: []byte("downloaded")}, [32]byte{}, false); err == nil {
		t.Fatal("new user file was overwritten")
	}
	if validProviderCachePath("config.yaml") || validProviderCachePath(filepath.Join("profiles", "p.yaml")) || validProviderCachePath(filepath.Join("verge-script-outputs", "private.json")) || validProviderCachePath("../outside") {
		t.Fatal("protected path was accepted")
	}
}

func TestOneCacheConflictDoesNotDiscardOtherUpdates(t *testing.T) {
	dir := t.TempDir()
	if err := os.Mkdir(filepath.Join(dir, "providers"), 0700); err != nil {
		t.Fatal(err)
	}
	conflict, safe := filepath.Join("providers", "conflict.yaml"), filepath.Join("providers", "safe.yaml")
	if err := os.WriteFile(filepath.Join(dir, conflict), []byte("user"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, safe), []byte("old"), 0600); err != nil {
		t.Fatal(err)
	}
	c := &Client{dir: dir, caches: newCacheState([]StageFile{{Path: conflict, Data: []byte("old")}, {Path: safe, Data: []byte("old")}}, true)}
	err := c.applyProviderCaches(ProviderCaches{Items: []ProviderCache{{Path: conflict, Version: "1", Data: []byte("new")}, {Path: safe, Version: "2", Data: []byte("new")}}})
	if err == nil || c.CacheWarning() == "" {
		t.Fatal("cache conflict was not reported")
	}
	a, _ := os.ReadFile(filepath.Join(dir, conflict))
	b, _ := os.ReadFile(filepath.Join(dir, safe))
	if string(a) != "user" || string(b) != "new" {
		t.Fatalf("partial synchronization: %q %q", a, b)
	}
}

func TestSharedProviderPathIsNotPersisted(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "cache.yaml")
	if err := os.WriteFile(path, []byte("data"), 0600); err != nil {
		t.Fatal(err)
	}
	provider := &testSnapshot{path: path, data: []byte("data")}
	var result ProviderCaches
	if err := collectProviderCaches(dir, []providerSnapshot{provider, provider}, ProviderCacheQuery{}, &result); err != nil {
		t.Fatal(err)
	}
	if result.Warning == "" || len(result.Items) != 0 {
		t.Fatalf("shared cache accepted: %+v", result)
	}
}

func TestAutomaticHTTPProviderUpdateIsPersistedWhileRunning(t *testing.T) {
	t.Setenv("CI", "1")
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/rule" {
			_, _ = w.Write([]byte("payload:\n  - '+.fresh.example'\n  - '+.second.example'\n"))
			return
		}
		_, _ = w.Write([]byte("proxies: [{name: fresh, type: direct}]\n"))
	}))
	defer server.Close()
	userDir, stageDir := t.TempDir(), t.TempDir()
	if err := os.Mkdir(filepath.Join(userDir, "providers"), 0700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(userDir, "providers", "proxy.yaml")
	if err := os.WriteFile(path, []byte("proxies: [{name: old, type: direct}]\n"), 0600); err != nil {
		t.Fatal(err)
	}
	rulePath := filepath.Join(userDir, "providers", "rule.yaml")
	if err := os.WriteFile(rulePath, []byte("payload:\n  - '+.old.example'\n"), 0600); err != nil {
		t.Fatal(err)
	}
	config := "mixed-port: 0\nport: 0\nsocks-port: 0\nlog-level: error\ndns: {enable: false}\n" +
		"proxy-providers:\n  test: {type: http, url: '" + server.URL + "/proxy', path: providers/proxy.yaml, interval: 1, health-check: {enable: false}}\n" +
		"rule-providers:\n  test: {type: http, url: '" + server.URL + "/rule', path: providers/rule.yaml, behavior: domain, format: yaml, interval: 1}\n" +
		"rules: ['RULE-SET,test,DIRECT', 'MATCH,DIRECT']\n"
	if err := os.WriteFile(filepath.Join(userDir, "config.yaml"), []byte(config), 0600); err != nil {
		t.Fatal(err)
	}
	left, right := net.Pipe()
	worker := NewWorker()
	worker.stageFactory = func() (fileStage, error) { return &testStage{dir: stageDir}, nil }
	go func() { _ = worker.Serve(right) }()
	client, err := NewClient(left)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	client.cacheInterval = 75 * time.Millisecond
	if err := client.Start(userDir); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(8 * time.Second)
	for time.Now().Before(deadline) {
		body, err := os.ReadFile(path)
		rule, ruleErr := os.ReadFile(rulePath)
		providers := client.RuleProviders()
		if err == nil && ruleErr == nil && strings.Contains(string(body), "fresh") && strings.Contains(string(rule), "fresh") && len(providers) == 1 && providers[0].Count == 2 {
			return
		}
		time.Sleep(30 * time.Millisecond)
	}
	t.Fatal("automatic provider refresh was not persisted while the worker was running")
}

func TestHTTPProviderUpdatesPersistAcrossWorkerStop(t *testing.T) {
	t.Setenv("CI", "1")
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/proxy" {
			_, _ = w.Write([]byte("proxies: [{name: fresh, type: direct}]\n"))
			return
		}
		_, _ = w.Write([]byte("payload:\n  - '+.fresh.example'\n"))
	}))
	defer server.Close()
	userDir, stageDir := t.TempDir(), t.TempDir()
	if err := os.Mkdir(filepath.Join(userDir, "providers"), 0700); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"proxy.yaml", "rule.yaml"} {
		body := "proxies: [{name: old, type: direct}]\n"
		if name == "rule.yaml" {
			body = "payload:\n  - '+.old.example'\n"
		}
		if err := os.WriteFile(filepath.Join(userDir, "providers", name), []byte(body), 0600); err != nil {
			t.Fatal(err)
		}
	}
	config := "mixed-port: 0\nport: 0\nsocks-port: 0\nlog-level: error\ndns: {enable: false}\n" +
		"proxy-providers:\n  test: {type: http, url: '" + server.URL + "/proxy', path: providers/proxy.yaml, interval: 3600, health-check: {enable: false}}\n" +
		"rule-providers:\n  test: {type: http, url: '" + server.URL + "/rule', path: providers/rule.yaml, behavior: domain, format: yaml, interval: 3600}\n" +
		"rules: ['RULE-SET,test,DIRECT', 'MATCH,DIRECT']\n"
	if err := os.WriteFile(filepath.Join(userDir, "config.yaml"), []byte(config), 0600); err != nil {
		t.Fatal(err)
	}
	left, right := net.Pipe()
	worker := NewWorker()
	worker.stageFactory = func() (fileStage, error) { return &testStage{dir: stageDir}, nil }
	go func() { _ = worker.Serve(right) }()
	client, err := NewClient(left)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	if err := client.Start(userDir); err != nil {
		t.Fatal(err)
	}
	if err := client.UpdateProxyProvider("test"); err != nil {
		t.Fatal(err)
	}
	if err := client.UpdateRuleProvider("test"); err != nil {
		t.Fatal(err)
	}
	if err := client.Stop(); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"proxy.yaml", "rule.yaml"} {
		body, err := os.ReadFile(filepath.Join(userDir, "providers", name))
		if err != nil || !strings.Contains(string(body), "fresh") {
			t.Errorf("updated %s did not survive worker stop: %q %v", name, body, err)
		}
	}
}

func TestHTTPProviderConflictKeepsUserFileAndStopsWorker(t *testing.T) {
	t.Setenv("CI", "1")
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("proxies: [{name: fresh, type: direct}]\n"))
	}))
	defer server.Close()
	userDir, stageDir := t.TempDir(), t.TempDir()
	if err := os.Mkdir(filepath.Join(userDir, "providers"), 0700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(userDir, "providers", "proxy.yaml")
	if err := os.WriteFile(path, []byte("proxies: [{name: old, type: direct}]\n"), 0600); err != nil {
		t.Fatal(err)
	}
	config := "mixed-port: 0\nport: 0\nsocks-port: 0\ndns: {enable: false}\nlog-level: error\nproxy-providers:\n  test: {type: http, url: '" + server.URL + "', path: providers/proxy.yaml, interval: 3600, health-check: {enable: false}}\nrules: ['MATCH,DIRECT']\n"
	if err := os.WriteFile(filepath.Join(userDir, "config.yaml"), []byte(config), 0600); err != nil {
		t.Fatal(err)
	}
	left, right := net.Pipe()
	worker := NewWorker()
	worker.stageFactory = func() (fileStage, error) { return &testStage{dir: stageDir}, nil }
	go func() { _ = worker.Serve(right) }()
	client, err := NewClient(left)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	client.cacheInterval = time.Hour
	if err := client.Start(userDir); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("user edit"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := client.UpdateProxyProvider("test"); err == nil {
		t.Fatal("conflict was not reported")
	}
	if err := client.Stop(); err != nil {
		t.Fatalf("kernel stop failed because of cache conflict: %v", err)
	}
	if client.CacheWarning() == "" || client.Status().Running {
		t.Fatal("missing conflict warning or stopped core")
	}
	if got, _ := os.ReadFile(path); string(got) != "user edit" {
		t.Fatalf("user edit was overwritten: %q", got)
	}
}
