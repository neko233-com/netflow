package migration

import (
	"archive/zip"
	"bytes"
	"os"
	"path/filepath"
	"testing"

	"github.com/neko233-com/netflow/internal/appdir"
	"github.com/neko233-com/netflow/internal/profile"
	"github.com/neko233-com/netflow/internal/rewrite"
)

func fixture(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	if err := os.Mkdir(filepath.Join(dir, "profiles"), 0700); err != nil {
		t.Fatal(err)
	}
	files := map[string]string{
		"profiles.yaml":    "current: p1\nitems:\n  - uid: p1\n    type: remote\n    name: Test\n    url: https://example.test/sub\n    file: p1.yaml\n    updated: 1700000000\n    extra: {upload: 10, download: 20, total: 100, expire: 1900000000}\n    selected: [{name: Proxy, now: Node}]\n    option: {allow_auto_update: true, update_interval: 60, self_proxy: true, rules: r1, script: s1}\n  - {uid: r1, type: rules, file: r1.yaml}\n  - {uid: s1, type: script, file: s1.js}\n",
		"verge.yaml":       "profile_dns_settings:\n  p1: {enabled: true}\n",
		"dns_config.yaml":  "dns:\n  enable: false\n  nameserver: [1.1.1.1]\n",
		"profiles/p1.yaml": "mixed-port: 0\nrules: ['MATCH,DIRECT']\n",
		"profiles/r1.yaml": "prepend: [DOMAIN,example.test,DIRECT]\nappend: []\ndelete: []\n",
		"profiles/s1.js":   "function main(config) { return config; }\n",
	}
	// A rule is one YAML string, including commas.
	files["profiles/r1.yaml"] = "prepend:\n  - 'DOMAIN,example.test,DIRECT'\nappend: []\ndelete: []\n"
	for name, body := range files {
		if err := os.WriteFile(filepath.Join(dir, filepath.FromSlash(name)), []byte(body), 0600); err != nil {
			t.Fatal(err)
		}
	}
	return dir
}

func TestImportVergeDirectoryPreservesProfilesRulesAndDNS(t *testing.T) {
	source := fixture(t)
	s, err := ReadVerge(source)
	if err != nil {
		t.Fatal(err)
	}
	preview := s.Preview()
	if len(preview.Profiles) != 1 || !preview.Profiles[0].Active || len(preview.Warnings) == 0 {
		t.Fatalf("bad preview: %+v", preview)
	}
	target := t.TempDir()
	lock, err := appdir.Acquire(target)
	if err != nil {
		t.Fatal(err)
	}
	defer lock.Close()
	result, err := s.ImportVerge(target)
	if err != nil {
		t.Fatal(err)
	}
	if result.Imported != 1 || result.ActiveProfile == "" {
		t.Fatalf("bad result: %+v", result)
	}
	catalog, err := profile.NewStore(target).Load()
	if err != nil {
		t.Fatal(err)
	}
	item := catalog.Items[0]
	if catalog.Current != item.UID || item.Used != 30 || item.Total != 100 || len(item.Selected) != 1 || !item.Option.UseClashProxy || !item.Option.DNSEnabled || item.Option.VergeUID != "p1" {
		t.Fatalf("bad imported profile: %+v", item)
	}
	rules, err := rewrite.Open(target)
	if err != nil {
		t.Fatal(err)
	}
	if len(rules.Snapshot().Profiles[item.UID].Prepend) != 1 {
		t.Fatal("rules not imported")
	}
	if _, err := os.Stat(filepath.Join(target, item.Option.VergeArchive)); err != nil {
		t.Fatal("original extension archive missing")
	}
	if err := s.ValidateTarget(filepath.Join(source, "nested")); err == nil {
		t.Fatal("accepted target within Verge source")
	}
}

func TestImportVergeRejectsArchiveTraversalAndRollsBackInvalidProfile(t *testing.T) {
	archive := filepath.Join(t.TempDir(), "bad.zip")
	f, err := os.Create(archive)
	if err != nil {
		t.Fatal(err)
	}
	zw := zip.NewWriter(f)
	w, _ := zw.Create("../escape")
	_, _ = w.Write([]byte("x"))
	_ = zw.Close()
	_ = f.Close()
	if _, err = ReadVerge(archive); err == nil {
		t.Fatal("unsafe ZIP accepted")
	}
	source := fixture(t)
	s, err := ReadVerge(source)
	if err != nil {
		t.Fatal(err)
	}
	s.files["profiles/p1.yaml"] = []byte("bad: [")
	target := t.TempDir()
	if _, err = s.ImportVerge(target); err == nil {
		t.Fatal("invalid profile imported")
	}
	cat, err := profile.NewStore(target).Load()
	if err != nil || len(cat.Items) != 0 {
		t.Fatalf("partial catalog: %+v %v", cat, err)
	}
	entries, err := os.ReadDir(filepath.Join(target, "verge-imports"))
	if err != nil || len(entries) != 0 {
		t.Fatalf("staged archive remains: %v %v", entries, err)
	}
}

func TestImportVergePreservesExistingActiveProfile(t *testing.T) {
	s, err := ReadVerge(fixture(t))
	if err != nil {
		t.Fatal(err)
	}
	target := t.TempDir()
	store := profile.NewStore(target)
	existing, err := store.ImportLocal("existing.yaml", []byte("rules: ['MATCH,DIRECT']\n"))
	if err != nil {
		t.Fatal(err)
	}
	before, err := os.ReadFile(filepath.Join(target, existing.File))
	if err != nil {
		t.Fatal(err)
	}
	result, err := s.ImportVerge(target)
	if err != nil {
		t.Fatal(err)
	}
	cat, err := store.Load()
	if err != nil || len(cat.Items) != 2 || cat.Current != existing.UID || result.ActiveProfile != existing.UID {
		t.Fatal("existing active profile changed")
	}
	after, err := os.ReadFile(filepath.Join(target, existing.File))
	if err != nil || string(before) != string(after) {
		t.Fatal("existing profile file changed")
	}
}

func TestImportVergeDNSFormatsPreserveSubscriptionAndHosts(t *testing.T) {
	for _, tc := range []struct {
		name, dns string
		wantDNS   bool
	}{
		{"current", "dns:\n  nameserver: [1.1.1.1]\n  fallback: []\nhosts:\n  imported.example: 192.0.2.7\n", true},
		{"legacy", "nameserver: [1.1.1.1]\nfallback: []\nhosts:\n  imported.example: 192.0.2.7\n", true},
		{"aliases", "defaults: &d {nameserver: [1.1.1.1]}\nhost_defaults: &h {imported.example: 192.0.2.7}\ndns:\n  <<: *d\n  fallback: []\nhosts: *h\n", true},
		{"hosts-only", "hosts:\n  imported.example: 192.0.2.7\n", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			source := fixture(t)
			body := []byte("dns:\n  enable: true\n  nameserver: [8.8.8.8]\n  fallback: [9.9.9.9]\n  use-hosts: true\nrules: ['MATCH,DIRECT']\n")
			if err := os.WriteFile(filepath.Join(source, "profiles", "p1.yaml"), body, 0600); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(source, "dns_config.yaml"), []byte(tc.dns), 0600); err != nil {
				t.Fatal(err)
			}
			s, err := ReadVerge(source)
			if err != nil {
				t.Fatal(err)
			}
			target := t.TempDir()
			if _, err = s.ImportVerge(target); err != nil {
				t.Fatal(err)
			}
			catalog, err := profile.NewStore(target).Load()
			if err != nil || len(catalog.Items) != 1 {
				t.Fatalf("catalog: %+v %v", catalog, err)
			}
			option := catalog.Items[0].Option
			if !option.DNSEnabled || !option.DNSVergeMerge || option.DNSVergeHosts == "" || (option.DNSOverride != "") != tc.wantDNS {
				t.Fatalf("migration options: %+v", option)
			}
			out, err := profile.ComposeVergeDNS(body, option.DNSOverride, option.DNSVergeHosts)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Contains(out, []byte("9.9.9.9")) || !bytes.Contains(out, []byte("imported.example")) || (tc.wantDNS && !bytes.Contains(out, []byte("1.1.1.1"))) {
				t.Fatalf("incorrect DNS: %s", out)
			}
			original, err := os.ReadFile(filepath.Join(target, catalog.Items[0].File))
			if err != nil || !bytes.Equal(original, body) {
				t.Fatal("migration altered the subscription")
			}
		})
	}
}

func TestImportVergeDataExtensionsApplyFromPrivateArchive(t *testing.T) {
	source := fixture(t)
	index := "current: p1\nitems:\n  - uid: p1\n    type: local\n    name: Test\n    file: p1.yaml\n    option: {proxies: p2, groups: g1, merge: m1}\n  - {uid: p2, type: proxies, file: p2.yaml}\n  - {uid: g1, type: groups, file: g1.yaml}\n  - {uid: m1, type: merge, file: m1.yaml}\n  - {uid: Merge, type: merge, file: Merge.yaml}\n"
	files := map[string]string{
		"profiles.yaml":       index,
		"profiles/p1.yaml":    "proxies: [{name: old, type: socks5, server: 127.0.0.1, port: 1}]\nproxy-groups: [{name: Select, type: select, proxies: [old, DIRECT]}]\nrules: ['MATCH,DIRECT']\n",
		"profiles/p2.yaml":    "prepend: [{name: new, type: socks5, server: 127.0.0.1, port: 2}]\nappend: []\ndelete: [old]\n",
		"profiles/g1.yaml":    "prepend: []\nappend: [{name: Extra, type: select, proxies: [DIRECT]}]\ndelete: []\n",
		"profiles/m1.yaml":    "profile: {store-selected: false}\n",
		"profiles/Merge.yaml": "profile: {store-fake-ip: true}\n",
	}
	for name, data := range files {
		if err := os.WriteFile(filepath.Join(source, filepath.FromSlash(name)), []byte(data), 0600); err != nil {
			t.Fatal(err)
		}
	}
	s, err := ReadVerge(source)
	if err != nil {
		t.Fatal(err)
	}
	target := t.TempDir()
	if _, err := s.ImportVerge(target); err != nil {
		t.Fatal(err)
	}
	catalog, err := profile.NewStore(target).Load()
	if err != nil || len(catalog.Items) != 1 || !catalog.Items[0].Option.VergeExtensions {
		t.Fatalf("extensions not enabled: %+v %v", catalog, err)
	}
	item := catalog.Items[0]
	body, err := os.ReadFile(filepath.Join(target, item.File))
	if err != nil {
		t.Fatal(err)
	}
	out, archive, hash, err := ComposeArchived(target, item.Option.VergeArchive, item.Option.VergeUID, body)
	if err != nil {
		t.Fatal(err)
	}
	if archive == "" || hash == ([32]byte{}) || !bytes.Contains(out, []byte("name: new")) || !bytes.Contains(out, []byte("name: Extra")) || !bytes.Contains(out, []byte("store-fake-ip: true")) || bytes.Contains(out, []byte("name: old")) {
		t.Fatalf("extension composition failed: %s", out)
	}
	if _, err := ArchivePath(target, filepath.Join("..", "outside.zip")); err == nil {
		t.Fatal("accepted archive traversal")
	}
}

// Opt-in read-only integration with the user's real Verge data; target is temporary.
func TestRealVergeImport(t *testing.T) {
	source := os.Getenv("NETFLOW_TEST_VERGE_SOURCE")
	if source == "" {
		t.Skip("real Verge source not configured")
	}
	s, err := ReadVerge(source)
	if err != nil {
		t.Fatal(err)
	}
	want := len(s.Preview().Profiles)
	if want == 0 {
		t.Fatal("source has no profiles")
	}
	target := t.TempDir()
	lock, err := appdir.Acquire(target)
	if err != nil {
		t.Fatal(err)
	}
	defer lock.Close()
	result, err := s.ImportVerge(target)
	if err != nil {
		t.Fatal(err)
	}
	catalog, err := profile.NewStore(target).Load()
	if err != nil || result.Imported != want || len(catalog.Items) != want {
		t.Fatalf("profile count mismatch: %d/%d", result.Imported, want)
	}
	for _, item := range catalog.Items {
		body, err := os.ReadFile(filepath.Join(target, item.File))
		if err != nil {
			t.Fatal("imported file missing")
		}
		var original vergeItem
		for _, candidate := range s.index.Items {
			if candidate.UID == item.Option.VergeUID {
				original = candidate
				break
			}
		}
		if original.UID == "" || !bytes.Equal(body, s.files["profiles/"+original.File]) || item.Name != original.Name || item.URL != original.URL || len(item.Selected) != len(original.Selected) {
			t.Fatal("import did not preserve original subscription data")
		}
		if original.UID == s.index.Current && catalog.Current != item.UID {
			t.Fatal("active subscription was not preserved")
		}
	}
}
