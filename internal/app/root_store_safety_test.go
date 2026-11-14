package app

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/neko233-com/netflow/internal/appconfig"
	"github.com/neko233-com/netflow/internal/kernelopts"
	"github.com/neko233-com/netflow/internal/profile"
	"github.com/neko233-com/netflow/internal/rewrite"
	"github.com/neko233-com/netflow/internal/sitetest"
)

func TestRootStoresDoNotModifyHardLinkedExternalFiles(t *testing.T) {
	for _, tc := range []struct {
		name string
		body string
		save func(string) error
	}{
		{"settings.json", `{}`, func(dir string) error { return appconfig.NewFileStore(dir).Save(appconfig.Settings{TrayEvent: "open"}) }},
		{"profiles.json", `{}`, func(dir string) error { return profile.NewStore(dir).Save(profile.File{}) }},
		{"tests.json", `[]`, func(dir string) error { return sitetest.NewStore(dir).Save([]sitetest.Item{{Name: "test"}}) }},
		{"agent-rules.json", `{}`, func(dir string) error {
			s, err := rewrite.Open(dir)
			if err != nil {
				return err
			}
			_, err = s.Replace(s.Snapshot(), 0)
			return err
		}},
		{"kernel-options.json", `{}`, func(dir string) error {
			s, err := kernelopts.Open(dir)
			if err != nil {
				return err
			}
			return s.Replace(kernelopts.Options{})
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			base := t.TempDir()
			dir := filepath.Join(base, "config")
			if err := os.Mkdir(dir, 0700); err != nil {
				t.Fatal(err)
			}
			outside := filepath.Join(base, "outside")
			if err := os.WriteFile(outside, []byte(tc.body), 0600); err != nil {
				t.Fatal(err)
			}
			if err := os.Link(outside, filepath.Join(dir, tc.name)); err != nil {
				t.Skipf("hard links unavailable: %v", err)
			}
			if err := tc.save(dir); err != nil {
				t.Fatal(err)
			}
			if data, err := os.ReadFile(outside); err != nil || string(data) != tc.body {
				t.Fatal("external file was modified")
			}
		})
	}
}
