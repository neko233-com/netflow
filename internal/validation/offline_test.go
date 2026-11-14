package validation

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
)

func TestOfflineCheckParsesFileProvidersWithoutNetwork(t *testing.T) {
	var count atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { count.Add(1); _, _ = w.Write([]byte("unexpected")) }))
	defer srv.Close()
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "nodes.yaml"), []byte("proxies: [{name: good, type: direct}]\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "rules.yaml"), []byte("payload: ['+.example.test']\n"), 0600); err != nil {
		t.Fatal(err)
	}
	body := "mixed-port: 0\nport: 0\nsocks-port: 0\nproxy-providers:\n  nodes: {type: file, path: nodes.yaml, health-check: {enable: false}}\n  remote: {type: http, url: '" + srv.URL + "', interval: 86400}\nproxy-groups: [{name: Select, type: select, use: [nodes]}]\nrule-providers:\n  local: {type: file, behavior: domain, format: yaml, path: rules.yaml}\nrules: ['RULE-SET,local,REJECT', 'MATCH,DIRECT']\n"
	req := Request{Directory: dir, Configs: []Config{{ID: "one", Body: []byte(body)}}}
	result, err := Check(req)
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Warnings) != 1 || result.Sources[filepath.Join(dir, "nodes.yaml")] == ([32]byte{}) || result.Sources[filepath.Join(dir, "rules.yaml")] == ([32]byte{}) {
		t.Fatalf("incomplete result: %+v", result)
	}
	if count.Load() != 0 {
		t.Fatal("validation made a request")
	}
	if err := os.WriteFile(filepath.Join(dir, "nodes.yaml"), []byte("wrong: true\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := Check(req); err == nil || !strings.Contains(err.Error(), "nodes") {
		t.Fatalf("invalid provider accepted: %v", err)
	}
	if count.Load() != 0 {
		t.Fatal("invalid provider caused a request")
	}
	if err := os.WriteFile(filepath.Join(dir, "nodes.yaml"), []byte("proxies: [{name: good, type: direct}]\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "rules.yaml"), []byte("bad: true\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := Check(req); err == nil || !strings.Contains(err.Error(), "local") {
		t.Fatalf("invalid rule provider accepted: %v", err)
	}
}

func TestOfflineCheckDoesNotDownloadMissingGeoData(t *testing.T) {
	var count atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { count.Add(1); _, _ = w.Write([]byte("invalid")) }))
	defer srv.Close()
	dir := t.TempDir()
	body := "mixed-port: 0\nport: 0\nsocks-port: 0\ngeox-url: {mmdb: '" + srv.URL + "'}\nrules: ['GEOIP,CN,DIRECT', 'MATCH,DIRECT']\n"
	if _, err := Check(Request{Directory: dir, Configs: []Config{{ID: "one", Body: []byte(body)}}}); err == nil {
		t.Fatal("missing geodata accepted")
	}
	if count.Load() != 0 {
		t.Fatal("geodata was downloaded")
	}
	if _, err := os.Stat(filepath.Join(dir, "Country.mmdb")); !os.IsNotExist(err) {
		t.Fatalf("geodata file was created: %v", err)
	}
}

func TestOfflineCheckAcceptsExistingGeoData(t *testing.T) {
	dir := t.TempDir()
	fixture, err := os.ReadFile(filepath.Join("..", "app", "testdata", "GeoIP2-Country-Test.mmdb"))
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "Country.mmdb")
	if err := os.WriteFile(path, fixture, 0600); err != nil {
		t.Fatal(err)
	}
	body := []byte("mixed-port: 0\nport: 0\nsocks-port: 0\nrules: ['GEOIP,US,DIRECT', 'MATCH,DIRECT']\n")
	result, err := Check(Request{Directory: dir, Configs: []Config{{ID: "one", Body: body}}})
	if err != nil {
		t.Fatal(err)
	}
	if result.Sources[path] == ([32]byte{}) {
		t.Fatal("geodata was not included in the source snapshot")
	}
}
