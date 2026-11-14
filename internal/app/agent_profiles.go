package app

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"strings"
	"time"

	"github.com/neko233-com/netflow/internal/agent"
	"github.com/neko233-com/netflow/internal/profile"
	"github.com/neko233-com/netflow/internal/ui"
)

const maxProfileJobs = 64
const maxPendingProfileJobs = 8
const profileJobRetention = 10 * time.Minute

type profileJobRecord struct {
	job         agent.ProfileJob
	completedAt time.Time
}

func (a *App) agentProfiles() (agent.ProfileList, error) {
	return a.agentProfilesPage(agent.PageArgs{})
}

func profilePage(catalog profile.File, active string, in agent.PageArgs) (agent.ProfileList, error) {
	items := make([]agent.Profile, 0, len(catalog.Items))
	for _, item := range catalog.Items {
		entry := agent.Profile{ID: item.UID, Name: profile.SafeDisplayName(item), Active: item.UID == active, VergeArchive: item.Option.VergeArchive != "" && item.Option.VergeUID != "", VergeScriptRollback: item.Option.VergeScriptPrevious != nil}
		if approval := item.Option.VergeScriptApproval; approval != nil {
			entry.VergeGlobalScript, entry.VergeProfileScript = approval.Global, approval.Profile
		}
		items = append(items, entry)
	}
	page, offset, next, err := boundedAgentPage(items, in.Offset, in.Limit, maxAgentPageBytes)
	if err != nil {
		return agent.ProfileList{}, err
	}
	return agent.ProfileList{Profiles: page, Total: len(items), Offset: offset, NextOffset: next}, nil
}

func (a *App) agentProfilesPage(in agent.PageArgs) (agent.ProfileList, error) {
	result := agent.ProfileList{Profiles: []agent.Profile{}}
	if a.profiles == nil {
		return result, errors.New("profile store is unavailable")
	}
	catalog, err := a.profiles.Load()
	if err != nil {
		return result, errors.New("profile catalog could not be read")
	}
	return profilePage(catalog, catalog.Current, in)
}

func (a *App) agentProfileSettings(id string) (agent.ProfileSettings, error) {
	if a.profiles == nil || id == "" || len(id) > 256 {
		return agent.ProfileSettings{}, errors.New("invalid profile id")
	}
	catalog, err := a.profiles.Load()
	if err != nil {
		return agent.ProfileSettings{}, errors.New("profile catalog could not be read")
	}
	for _, item := range catalog.Items {
		if item.UID != id {
			continue
		}
		return agent.ProfileSettings{ProfileID: item.UID, Name: profile.SafeDisplayName(item), Description: item.Description, Type: item.Type, Active: item.UID == catalog.Current,
			UserAgent: item.Option.UserAgent, Timeout: item.Option.TimeoutSeconds, Interval: item.Option.UpdateInterval, AutoUpdate: item.Option.AllowAutoUpdate,
			UseCoreProxy: item.Option.UseClashProxy, UseSystemProxy: item.Option.UseSystemProxy, AllowInsecure: item.Option.AcceptInvalid}, nil
	}
	return agent.ProfileSettings{}, errors.New("profile not found")
}

func (a *App) agentUpdateProfileSettings(in agent.ProfileSettingsPatch) (agent.ProfileSettings, error) {
	if a.profiles == nil || in.ProfileID == "" || len(in.ProfileID) > 256 {
		return agent.ProfileSettings{}, errors.New("invalid profile id")
	}
	if a.profileUpdates[in.ProfileID] {
		return agent.ProfileSettings{}, errors.New("profile update is in progress")
	}
	patch := profile.MetadataPatch{Name: in.Name, Description: in.Description, UserAgent: in.UserAgent, Timeout: in.Timeout, Interval: in.Interval,
		AutoUpdate: in.AutoUpdate, UseCoreProxy: in.UseCoreProxy, UseSystemProxy: in.UseSystemProxy, AllowInsecure: in.AllowInsecure}
	if _, err := a.profiles.PatchMetadata(in.ProfileID, patch); err != nil {
		return agent.ProfileSettings{}, err
	}
	if a.model != nil {
		a.loadProfiles()
		a.refreshHome()
	}
	return a.agentProfileSettings(in.ProfileID)
}

func (a *App) pruneProfileJobs(now time.Time) {
	for id, record := range a.profileJobs {
		if !record.completedAt.IsZero() && now.Sub(record.completedAt) >= profileJobRetention {
			delete(a.profileJobs, id)
		}
	}
}

// beginProfileJob and its callback execute on the serialized app event loop;
// start performs network I/O elsewhere and invokes its callback on that loop.
func (a *App) beginProfileJob(operation, profileID string, now time.Time, start func(func(string, error))) (agent.ProfileJob, error) {
	if operation != "import" && operation != "update" && operation != "change-url" {
		return agent.ProfileJob{}, errors.New("invalid profile operation")
	}
	if a.tunBusy {
		return agent.ProfileJob{}, errors.New("TUN transition in progress")
	}
	if start == nil {
		return agent.ProfileJob{}, errors.New("profile operations are unavailable")
	}
	if a.profileJobs == nil {
		a.profileJobs = make(map[string]profileJobRecord)
	}
	a.pruneProfileJobs(now)
	pending := 0
	for _, record := range a.profileJobs {
		if record.job.State != "pending" {
			continue
		}
		pending++
		if operation == "update" && record.job.Operation == operation && record.job.ProfileID == profileID {
			return record.job, nil
		}
	}
	if pending >= maxPendingProfileJobs {
		return agent.ProfileJob{}, errors.New("too many profile operations are pending")
	}
	if len(a.profileJobs) >= maxProfileJobs {
		var oldestID string
		var oldest time.Time
		for id, record := range a.profileJobs {
			if !record.completedAt.IsZero() && (oldestID == "" || record.completedAt.Before(oldest)) {
				oldestID, oldest = id, record.completedAt
			}
		}
		if oldestID == "" {
			return agent.ProfileJob{}, errors.New("profile job capacity reached")
		}
		delete(a.profileJobs, oldestID)
	}
	var id string
	for i := 0; i < 4; i++ {
		var random [16]byte
		if _, err := rand.Read(random[:]); err != nil {
			return agent.ProfileJob{}, err
		}
		candidate := hex.EncodeToString(random[:])
		if _, exists := a.profileJobs[candidate]; !exists {
			id = candidate
			break
		}
	}
	if id == "" {
		return agent.ProfileJob{}, errors.New("could not allocate a profile job id")
	}
	job := agent.ProfileJob{JobID: id, Operation: operation, ProfileID: profileID, State: "pending", CreatedAt: now.UTC()}
	a.profileJobs[id] = profileJobRecord{job: job}
	start(func(id string, err error) { a.completeProfileJob(job.JobID, id, err, time.Now()) })
	return a.profileJobs[job.JobID].job, nil
}

func (a *App) completeProfileJob(jobID, profileID string, err error, now time.Time) {
	record, ok := a.profileJobs[jobID]
	if !ok || record.job.State != "pending" {
		return
	}
	if profileID != "" {
		record.job.ProfileID = profileID
	}
	record.completedAt = now
	if err == nil {
		record.job.State = "succeeded"
	} else {
		record.job.State = "failed"
		// HTTP and parser errors can contain the subscription URL or secrets.
		if record.job.Operation == "import" {
			record.job.Error = "profile import failed or was partial; inspect profiles before retrying"
		} else {
			record.job.Error = "profile update failed; check network and profile configuration"
		}
	}
	a.profileJobs[jobID] = record
}

func (a *App) getProfileJob(id string, now time.Time) (agent.ProfileJob, error) {
	a.pruneProfileJobs(now)
	if len(id) != 32 {
		return agent.ProfileJob{}, errors.New("invalid profile job id")
	}
	if _, err := hex.DecodeString(id); err != nil {
		return agent.ProfileJob{}, errors.New("invalid profile job id")
	}
	record, ok := a.profileJobs[id]
	if !ok {
		return agent.ProfileJob{}, errors.New("profile job not found or expired")
	}
	return record.job, nil
}

func profileImportForm(input agent.ProfileImportArgs) (ui.ProfileForm, error) {
	input.URL = strings.TrimSpace(input.URL)
	if len(input.URL) > 8192 || !ui.ValidSubscriptionURL(input.URL) || strings.ContainsAny(input.URL, "\r\n\x00") {
		return ui.ProfileForm{}, errors.New("invalid subscription URL")
	}
	if len(input.Name) > 256 || strings.ContainsAny(input.Name, "\r\n\x00") || len(input.Description) > 2048 || strings.ContainsRune(input.Description, '\x00') || len(input.UserAgent) > 512 || strings.ContainsAny(input.UserAgent, "\r\n\x00") {
		return ui.ProfileForm{}, errors.New("invalid profile name or user agent")
	}
	if input.Timeout == 0 {
		input.Timeout = 60
	}
	if input.Interval == 0 {
		input.Interval = 1440
	}
	if input.Timeout < 1 || input.Timeout > 300 || input.Interval < 1 || input.Interval > 43200 {
		return ui.ProfileForm{}, errors.New("invalid profile timeout or update interval")
	}
	return ui.ProfileForm{Type: "remote", URL: input.URL, Name: input.Name, Desc: input.Description, UA: input.UserAgent, Timeout: input.Timeout, Interval: input.Interval, Auto: input.AutoUpdate, Clash: input.UseCoreProxy, SysProxy: input.UseSystemProxy, Insecure: input.AllowInsecure}, nil
}
