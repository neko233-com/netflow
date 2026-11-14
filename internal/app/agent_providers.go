package app

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"strings"
	"time"

	"github.com/neko233-com/netflow/internal/agent"
	"github.com/neko233-com/netflow/internal/core"
	"github.com/neko233-com/netflow/internal/coreipc"
)

const maxProviderJobs = 64
const maxPendingProviderJobs = 8
const providerJobRetention = 10 * time.Minute

type providerJobRecord struct {
	job         agent.ProviderJob
	completedAt time.Time
}

func (a *App) agentProviders() (agent.ProviderList, error) {
	result := agent.ProviderList{Proxy: []agent.ProviderInfo{}, Rule: []agent.ProviderInfo{}}
	if a.core == nil || !a.core.Status().Running {
		return result, errors.New("core is not running")
	}
	for _, p := range a.core.ProxyProviders() {
		result.Proxy = append(result.Proxy, agent.ProviderInfo{Name: p.Name, Vehicle: p.Vehicle, Count: p.Count})
	}
	for _, p := range a.core.RuleProviders() {
		result.Rule = append(result.Rule, agent.ProviderInfo{Name: p.Name, Vehicle: p.Vehicle, Behavior: p.Behavior, Count: p.Count})
	}
	return result, nil
}

func (a *App) pruneProviderJobs(now time.Time) {
	for id, record := range a.providerJobs {
		if !record.completedAt.IsZero() && now.Sub(record.completedAt) >= providerJobRetention {
			delete(a.providerJobs, id)
		}
	}
}

// beginProviderJob and its completion callback run on the desktop event loop.
// start must dispatch the actual update away from that loop.
func (a *App) beginProviderJob(input agent.ProviderUpdateArgs, now time.Time, start func(string, string, func(error))) (agent.ProviderJob, error) {
	if input.Kind != "proxy" && input.Kind != "rule" {
		return agent.ProviderJob{}, errors.New("provider kind must be proxy or rule")
	}
	if input.Name == "" || len(input.Name) > 1024 || strings.ContainsRune(input.Name, '\x00') {
		return agent.ProviderJob{}, errors.New("invalid provider name")
	}
	if a.tunBusy {
		return agent.ProviderJob{}, errors.New("TUN transition in progress")
	}
	if start == nil {
		return agent.ProviderJob{}, errors.New("provider updates are unavailable")
	}
	list, err := a.agentProviders()
	if err != nil {
		return agent.ProviderJob{}, err
	}
	items := list.Proxy
	if input.Kind == "rule" {
		items = list.Rule
	}
	found := false
	for _, item := range items {
		if item.Name == input.Name {
			found = true
			break
		}
	}
	if !found {
		return agent.ProviderJob{}, errors.New("provider not found in active profile")
	}
	profileID := a.core.ProfileID()
	if a.providerJobs == nil {
		a.providerJobs = make(map[string]providerJobRecord)
	}
	a.pruneProviderJobs(now)
	pending := 0
	for _, record := range a.providerJobs {
		if record.job.State == "pending" {
			pending++
			if record.job.Kind == input.Kind && record.job.Name == input.Name && record.job.ProfileID == profileID {
				return record.job, nil
			}
		}
	}
	if pending >= maxPendingProviderJobs {
		return agent.ProviderJob{}, errors.New("too many provider updates are pending")
	}
	if len(a.providerJobs) >= maxProviderJobs {
		var oldestID string
		var oldest time.Time
		for id, record := range a.providerJobs {
			if !record.completedAt.IsZero() && (oldestID == "" || record.completedAt.Before(oldest)) {
				oldestID, oldest = id, record.completedAt
			}
		}
		if oldestID == "" {
			return agent.ProviderJob{}, errors.New("provider job capacity reached")
		}
		delete(a.providerJobs, oldestID)
	}
	var id string
	for i := 0; i < 4; i++ {
		var random [16]byte
		if _, err := rand.Read(random[:]); err != nil {
			return agent.ProviderJob{}, err
		}
		candidate := hex.EncodeToString(random[:])
		if _, exists := a.providerJobs[candidate]; !exists {
			id = candidate
			break
		}
	}
	if id == "" {
		return agent.ProviderJob{}, errors.New("could not allocate a provider job id")
	}
	job := agent.ProviderJob{JobID: id, Kind: input.Kind, Name: input.Name, ProfileID: profileID, State: "pending", CreatedAt: now.UTC()}
	a.providerJobs[job.JobID] = providerJobRecord{job: job}
	start(input.Kind, input.Name, func(err error) { a.completeProviderJob(job.JobID, err, time.Now()) })
	return a.providerJobs[job.JobID].job, nil
}

func (a *App) completeProviderJob(id string, err error, now time.Time) {
	record, ok := a.providerJobs[id]
	if !ok || record.job.State != "pending" {
		return
	}
	record.completedAt = now
	if err == nil {
		record.job.State = "succeeded"
	} else {
		record.job.State = "failed"
		// Errors can contain provider URLs or credentials. Expose only a safe,
		// actionable summary over the agent bridge.
		switch {
		case errors.Is(err, core.ErrProviderProfileChanged):
			record.job.Error = "active profile changed before the update began"
		case errors.Is(err, coreipc.ErrProviderCacheSync):
			record.job.Error = "provider updated but a cache could not be persisted; check provider_cache_warning"
		default:
			record.job.Error = "provider update failed; check network and provider configuration"
		}
	}
	a.providerJobs[id] = record
}

func (a *App) getProviderJob(id string, now time.Time) (agent.ProviderJob, error) {
	a.pruneProviderJobs(now)
	if len(id) != 32 {
		return agent.ProviderJob{}, errors.New("invalid provider job id")
	}
	if _, err := hex.DecodeString(id); err != nil {
		return agent.ProviderJob{}, errors.New("invalid provider job id")
	}
	record, ok := a.providerJobs[id]
	if !ok {
		return agent.ProviderJob{}, errors.New("provider job not found or expired")
	}
	return record.job, nil
}
