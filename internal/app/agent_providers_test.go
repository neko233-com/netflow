package app

import (
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/neko233-com/netflow/internal/agent"
	"github.com/neko233-com/netflow/internal/core"
	"github.com/neko233-com/netflow/internal/coreipc"
	"github.com/neko233-com/netflow/internal/rules"
)

func TestProviderPagesPreserveFullUpdateLookup(t *testing.T) {
	engine := &switchTestEngine{running: true, id: "profile-1"}
	for i := 0; i < 250; i++ {
		engine.proxyProviders = append(engine.proxyProviders, core.ProxyProvider{Name: fmt.Sprintf("p-%03d", i), Vehicle: "HTTP"})
	}
	a := &App{core: newSwitchableEngine(engine)}
	preview, err := a.agentProviderPreview()
	if err != nil || preview.ProxyTotal != 250 || preview.ProxyNextOffset != 100 || len(preview.Proxy) != 100 {
		t.Fatalf("provider preview: %+v %v", preview, err)
	}
	page, err := a.agentProviderPage(agent.ProviderPageArgs{Kind: "proxy", Offset: 100, Limit: 150})
	if err != nil || page.Total != 250 || page.NextOffset != 250 || page.Providers[0].Name != "p-100" {
		t.Fatalf("provider page: %+v %v", page, err)
	}
	started := false
	_, err = a.beginProviderJob(agent.ProviderUpdateArgs{Kind: "proxy", Name: "p-249"}, time.Now(), func(_, _ string, done func(error)) { started = true; done(nil) })
	if err != nil || !started {
		t.Fatalf("update could not find provider after first page: %v", err)
	}
}

func TestProviderJobsDeduplicateReportAndExpire(t *testing.T) {
	engine := &switchTestEngine{running: true, id: "profile-1", proxyProviders: []core.ProxyProvider{{Name: "nodes", Vehicle: "HTTP", Count: 3}}, ruleProviders: []rules.Provider{{Name: "sites", Vehicle: "HTTP", Behavior: "Domain", Count: 2}}}
	a := &App{core: newSwitchableEngine(engine)}
	list, err := a.agentProviders()
	if err != nil || len(list.Proxy) != 1 || list.Proxy[0].Count != 3 || len(list.Rule) != 1 || list.Rule[0].Behavior != "Domain" {
		t.Fatalf("provider list: %+v %v", list, err)
	}
	var finish func(error)
	starts := 0
	start := func(kind, name string, done func(error)) { starts++; finish = done }
	now := time.Now()
	input := agent.ProviderUpdateArgs{Kind: "proxy", Name: "nodes"}
	job, err := a.beginProviderJob(input, now, start)
	if err != nil || job.State != "pending" || job.ProfileID != "profile-1" || len(job.JobID) != 32 {
		t.Fatalf("start: %+v %v", job, err)
	}
	again, err := a.beginProviderJob(input, now, start)
	if err != nil || again.JobID != job.JobID || starts != 1 {
		t.Fatalf("duplicate: %+v %v", again, err)
	}
	finish(errors.New("request https://example.test/?token=secret active profile changed before provider update"))
	result, err := a.getProviderJob(job.JobID, time.Now())
	if err != nil || result.State != "failed" || strings.Contains(result.Error, "secret") || strings.Contains(result.Error, "example.test") || strings.Contains(result.Error, "active profile changed") {
		t.Fatalf("unsafe job error: %+v %v", result, err)
	}
	if _, err := a.getProviderJob(job.JobID, time.Now().Add(providerJobRetention+time.Second)); err == nil {
		t.Fatal("completed job did not expire")
	}
	if _, err := a.beginProviderJob(agent.ProviderUpdateArgs{Kind: "proxy", Name: "missing"}, now, start); err == nil {
		t.Fatal("unknown provider accepted")
	}
	if _, err := a.beginProviderJob(agent.ProviderUpdateArgs{Kind: "other", Name: "nodes"}, now, start); err == nil {
		t.Fatal("invalid provider kind accepted")
	}
}

func TestProviderJobErrorClassificationUsesTypedErrors(t *testing.T) {
	for _, tc := range []struct {
		err  error
		want string
	}{
		{fmt.Errorf("wrapped: %w", core.ErrProviderProfileChanged), "active profile changed"},
		{fmt.Errorf("wrapped: %w", coreipc.ErrProviderCacheSync), "cache could not be persisted"},
		{errors.New("active profile changed before provider update: secret"), "check network"},
	} {
		a := &App{providerJobs: map[string]providerJobRecord{"id": {job: agent.ProviderJob{State: "pending"}}}}
		a.completeProviderJob("id", tc.err, time.Now())
		got := a.providerJobs["id"].job.Error
		if !strings.Contains(got, tc.want) || strings.Contains(got, "secret") {
			t.Fatalf("classification = %q, wanted %q", got, tc.want)
		}
	}
}

func TestProviderJobsBoundPendingWork(t *testing.T) {
	engine := &switchTestEngine{running: true, id: "p"}
	for i := 0; i < maxPendingProviderJobs+1; i++ {
		engine.proxyProviders = append(engine.proxyProviders, core.ProxyProvider{Name: string(rune('a' + i))})
	}
	a := &App{core: newSwitchableEngine(engine)}
	start := func(string, string, func(error)) {}
	for i := 0; i < maxPendingProviderJobs; i++ {
		if _, err := a.beginProviderJob(agent.ProviderUpdateArgs{Kind: "proxy", Name: string(rune('a' + i))}, time.Now(), start); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := a.beginProviderJob(agent.ProviderUpdateArgs{Kind: "proxy", Name: string(rune('a' + maxPendingProviderJobs))}, time.Now(), start); err == nil {
		t.Fatal("unbounded pending work accepted")
	}
}
