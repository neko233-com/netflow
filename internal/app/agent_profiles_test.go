package app

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/neko233-com/netflow/internal/agent"
	"github.com/neko233-com/netflow/internal/profile"
	"github.com/neko233-com/netflow/internal/rewrite"
)

type profileStatusEngine struct{ diagnosticsTestEngine }

func (profileStatusEngine) ProfileID() string { return "p1" }

func TestLegacyDefaultProfileNamesDoNotExposeURLCredentials(t *testing.T) {
	dir := t.TempDir()
	a := newProfileHarness(dir)
	raw := "https://user:synthetic-password@example.invalid?token=synthetic-token"
	legacy := "user:synthetic-password@example.invalid?token=synthetic-token"
	if err := a.profiles.Save(profile.File{Current: "p1", Items: []profile.CatalogItem{{UID: "p1", Name: legacy, URL: raw}}}); err != nil {
		t.Fatal(err)
	}
	var err error
	a.rewrites, err = rewrite.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	a.core = profileStatusEngine{}
	list, err := a.agentProfiles()
	if err != nil {
		t.Fatal(err)
	}
	status, err := a.agentStatus()
	if err != nil {
		t.Fatal(err)
	}
	data, _ := json.Marshal([]any{list, status})
	if strings.Contains(string(data), "synthetic-") || list.Profiles[0].Name != "example.invalid" || status.Profiles[0].Name != "example.invalid" {
		t.Fatal("legacy URL credentials appeared in Agent output")
	}
	a.loadProfiles()
	if len(a.model.Profiles) != 1 || a.model.Profiles[0].Name != "example.invalid" {
		t.Fatal("legacy URL credentials appeared as GUI profile name")
	}
}

func TestProfileJobLimitsDeduplicationAndSecretRedaction(t *testing.T) {
	a := &App{}
	var callbacks []func(string, error)
	start := func(done func(string, error)) { callbacks = append(callbacks, done) }
	now := time.Now()
	first, err := a.beginProfileJob("update", "id", now, start)
	if err != nil {
		t.Fatal(err)
	}
	again, err := a.beginProfileJob("update", "id", now, start)
	if err != nil || again.JobID != first.JobID || len(callbacks) != 1 {
		t.Fatal("duplicate update was not deduplicated")
	}
	callbacks[0]("id", errors.New("https://example.invalid/?token=synthetic-secret"))
	result, err := a.getProfileJob(first.JobID, now)
	if err != nil || result.State != "failed" || strings.Contains(result.Error, "synthetic-secret") || strings.Contains(result.Error, "https://") {
		t.Fatalf("failure was not redacted: %+v %v", result, err)
	}
	if _, err := a.getProfileJob(first.JobID, now.Add(profileJobRetention+time.Second)); err == nil {
		t.Fatal("expired job retained")
	}
	for i := 0; i < maxPendingProfileJobs; i++ {
		if _, err := a.beginProfileJob("import", "", now, start); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := a.beginProfileJob("import", "", now, start); err == nil {
		t.Fatal("pending job limit not enforced")
	}
}

func TestProfileImportValidation(t *testing.T) {
	form, err := profileImportForm(agent.ProfileImportArgs{URL: "https://example.invalid/sub?token=secret", Description: "test", UseCoreProxy: true, UseSystemProxy: true, AllowInsecure: true})
	if err != nil || form.Timeout != 60 || form.Interval != 1440 || !form.Clash || !form.SysProxy || !form.Insecure || form.Desc != "test" || form.Auto {
		t.Fatalf("unexpected import defaults: %+v %v", form, err)
	}
	for _, input := range []agent.ProfileImportArgs{{URL: "file:///secret"}, {URL: "https://example.invalid", Timeout: 301}, {URL: "https://example.invalid", UserAgent: "bad\nheader"}} {
		if _, err := profileImportForm(input); err == nil {
			t.Fatal("invalid profile import was accepted")
		}
	}
}
