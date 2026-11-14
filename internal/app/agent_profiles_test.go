package app

import (
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/neko233-com/netflow/internal/agent"
)

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
	form, err := profileImportForm(agent.ProfileImportArgs{URL: "https://example.invalid/sub?token=secret", UseCoreProxy: true})
	if err != nil || form.Timeout != 60 || form.Interval != 1440 || !form.Clash || form.Auto {
		t.Fatalf("unexpected import defaults: %+v %v", form, err)
	}
	for _, input := range []agent.ProfileImportArgs{{URL: "file:///secret"}, {URL: "https://example.invalid", Timeout: 301}, {URL: "https://example.invalid", UserAgent: "bad\nheader"}} {
		if _, err := profileImportForm(input); err == nil {
			t.Fatal("invalid profile import was accepted")
		}
	}
}
