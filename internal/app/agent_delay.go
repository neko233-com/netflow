package app

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"net"
	"strings"
	"time"

	"github.com/neko233-com/netflow/internal/agent"
	"github.com/neko233-com/netflow/internal/delay"
)

const maxDelayJobs = 64
const maxPendingDelayJobs = 8
const delayJobRetention = 10 * time.Minute

type delayJobRecord struct {
	job         agent.DelayJob
	completedAt time.Time
}

func (a *App) pruneDelayJobs(now time.Time) {
	for id, record := range a.delayJobs {
		if !record.completedAt.IsZero() && now.Sub(record.completedAt) >= delayJobRetention {
			delete(a.delayJobs, id)
		}
	}
}

// beginDelayJob and its completion callback execute on the app event loop.
func (a *App) beginDelayJob(in agent.DelayArgs, now time.Time, start func(string, string, string, time.Duration, string, func(int, error))) (agent.DelayJob, error) {
	if in.Group == "" || in.Node == "" || len(in.Group) > 1024 || len(in.Node) > 1024 || strings.ContainsRune(in.Group, '\x00') || strings.ContainsRune(in.Node, '\x00') {
		return agent.DelayJob{}, errors.New("valid group and node names are required")
	}
	if a.core == nil || !a.core.Status().Running || a.model == nil || a.tunBusy || start == nil {
		return agent.DelayJob{}, errors.New("kernel unavailable or TUN transition in progress")
	}
	if in.URL == "" {
		in.URL = a.model.Prefs.DelayURL
		if !delay.ValidURL(in.URL) {
			in.URL = delay.DefaultURL
		}
	}
	if !delay.ValidURL(in.URL) {
		return agent.DelayJob{}, errors.New("test URL must be HTTP or HTTPS without credentials or fragments")
	}
	if in.TimeoutMS == 0 {
		in.TimeoutMS = a.model.Prefs.DelayTimeoutMS
		if in.TimeoutMS < 100 || in.TimeoutMS > 60000 {
			in.TimeoutMS = delay.DefaultTimeout
		}
	}
	if in.TimeoutMS < 100 || in.TimeoutMS > 60000 {
		return agent.DelayJob{}, errors.New("timeout must be 100 to 60000 milliseconds")
	}
	group, err := a.core.Group(in.Group)
	if err != nil {
		return agent.DelayJob{}, errors.New("proxy group is unavailable")
	}
	matches := 0
	for _, node := range group.Nodes {
		if node.Name == in.Node {
			matches++
		}
	}
	if matches != 1 {
		return agent.DelayJob{}, errors.New("node is missing or ambiguous in the requested group")
	}
	if a.delayJobs == nil {
		a.delayJobs = make(map[string]delayJobRecord)
	}
	a.pruneDelayJobs(now)
	pending := 0
	for _, record := range a.delayJobs {
		if record.job.State == "pending" {
			pending++
		}
	}
	if pending >= maxPendingDelayJobs {
		return agent.DelayJob{}, errors.New("too many latency tests are pending")
	}
	if len(a.delayJobs) >= maxDelayJobs {
		var oldestID string
		var oldest time.Time
		for id, record := range a.delayJobs {
			if !record.completedAt.IsZero() && (oldestID == "" || record.completedAt.Before(oldest)) {
				oldestID, oldest = id, record.completedAt
			}
		}
		if oldestID == "" {
			return agent.DelayJob{}, errors.New("latency test capacity reached")
		}
		delete(a.delayJobs, oldestID)
	}
	var id string
	for i := 0; i < 4; i++ {
		var random [16]byte
		if _, err := rand.Read(random[:]); err != nil {
			return agent.DelayJob{}, err
		}
		candidate := hex.EncodeToString(random[:])
		if _, exists := a.delayJobs[candidate]; !exists {
			id = candidate
			break
		}
	}
	if id == "" {
		return agent.DelayJob{}, errors.New("could not allocate latency job id")
	}
	job := agent.DelayJob{JobID: id, Group: in.Group, Node: in.Node, ProfileID: a.core.ProfileID(), State: "pending", CreatedAt: now.UTC()}
	a.delayJobs[id] = delayJobRecord{job: job}
	start(in.Group, in.Node, in.URL, time.Duration(in.TimeoutMS)*time.Millisecond, job.ProfileID, func(ms int, err error) { a.completeDelayJob(id, ms, err, time.Now()) })
	return a.delayJobs[id].job, nil
}

func (a *App) completeDelayJob(id string, ms int, err error, now time.Time) {
	record, ok := a.delayJobs[id]
	if !ok || record.job.State != "pending" {
		return
	}
	record.completedAt = now
	if err == nil && ms > 0 {
		record.job.State, record.job.DelayMS = "succeeded", ms
	} else {
		var networkError net.Error
		switch {
		case errors.Is(err, context.Canceled):
			record.job.State, record.job.Error = "canceled", "kernel stopped or reloaded during test"
		case errors.Is(err, context.DeadlineExceeded) || (errors.As(err, &networkError) && networkError.Timeout()):
			record.job.State, record.job.Error = "timed_out", "latency test timed out"
		default:
			record.job.State, record.job.Error = "failed", "latency test failed; check the active profile and node"
		}
	}
	a.delayJobs[id] = record
}

func (a *App) getDelayJob(id string, now time.Time) (agent.DelayJob, error) {
	a.pruneDelayJobs(now)
	if len(id) != 32 {
		return agent.DelayJob{}, errors.New("invalid latency job id")
	}
	if _, err := hex.DecodeString(id); err != nil {
		return agent.DelayJob{}, errors.New("invalid latency job id")
	}
	record, ok := a.delayJobs[id]
	if !ok {
		return agent.DelayJob{}, errors.New("latency job not found or expired")
	}
	return record.job, nil
}
