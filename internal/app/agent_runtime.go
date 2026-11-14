package app

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/neko233-com/netflow/internal/agent"
	"github.com/neko233-com/netflow/internal/migration"
	"github.com/neko233-com/netflow/internal/profile"
	"github.com/neko233-com/netflow/internal/ui"
	"github.com/neko233-com/netflow/internal/validation"
)

var vergeScriptPreviewSlots = make(chan struct{}, 1)

func (a *App) startAgent() error {
	bridge, err := agent.Start(a.dir, a.dispatchAgent)
	if err != nil {
		return err
	}
	a.agentBridge = bridge
	a.agentExpiryStop = make(chan struct{})
	go a.expiryLoop(a.agentExpiryStop)
	return nil
}

func (a *App) stopAgent() {
	if a.agentExpiryStop != nil {
		close(a.agentExpiryStop)
		a.agentExpiryStop = nil
	}
	if a.agentBridge != nil {
		_ = a.agentBridge.Close()
		a.agentBridge = nil
	}
}

func (a *App) dispatchAgent(ctx context.Context, method string, args json.RawMessage) (any, error) {
	if method == "verge-script-preview" {
		var in agent.VergeScriptPreviewArgs
		if err := decodeStrict(args, &in); err != nil {
			return nil, err
		}
		if !in.Global && !in.Profile {
			return nil, errors.New("select at least one archived script")
		}
		select {
		case vergeScriptPreviewSlots <- struct{}{}:
			defer func() { <-vergeScriptPreviewSlots }()
		case <-ctx.Done():
			return nil, ctx.Err()
		}
		var draft vergeScriptDraft
		var prepareErr error
		executed := false
		a.runOnMain(func() {
			executed = true
			if prepareErr = ctx.Err(); prepareErr == nil {
				draft, prepareErr = a.captureVergeScriptDraft(in.ProfileID)
			}
		})
		if !executed {
			return nil, errors.New("application is shutting down")
		}
		if prepareErr != nil {
			if ctx.Err() != nil {
				return nil, ctx.Err()
			}
			return nil, errors.New("script preview configuration is unavailable or has changed")
		}
		prepared, err := a.prepareVergeScript(ctx, draft, migration.ScriptSelection{Global: in.Global, Profile: in.Profile})
		if err != nil {
			return nil, err
		}
		if err := a.checkAgentSources(draft.hashes); err != nil {
			return nil, errors.New("script preview sources changed")
		}
		var result agent.VergeScriptPreview
		var finishErr error
		executed = false
		a.runOnMain(func() {
			executed = true
			if finishErr = ctx.Err(); finishErr == nil {
				result, finishErr = a.finishVergeScriptPreview(draft, prepared)
			}
		})
		if !executed {
			return nil, errors.New("application is shutting down")
		}
		return result, finishErr
	}
	if method == "chain-preview" {
		var in agent.ChainPreviewArgs
		if err := decodeStrict(args, &in); err != nil {
			return nil, err
		}
		var draft chainDraft
		var prepareErr error
		executed := false
		a.runOnMain(func() {
			executed = true
			if prepareErr = ctx.Err(); prepareErr == nil {
				draft, prepareErr = a.prepareAgentChain(in)
			}
		})
		if !executed {
			return nil, errors.New("desktop application is shutting down")
		}
		if prepareErr != nil {
			return nil, prepareErr
		}
		checked, err := validateConfigurations(ctx, a.dir, []validation.Config{{ID: draft.active.ProfileID, Body: draft.composed}})
		if err != nil {
			return nil, err
		}
		var result agent.ChainPreview
		var finishErr error
		executed = false
		a.runOnMain(func() {
			executed = true
			if finishErr = ctx.Err(); finishErr == nil {
				result, finishErr = a.finishAgentChainPreview(draft, checked)
			}
		})
		if !executed {
			return nil, errors.New("desktop application is shutting down")
		}
		return result, finishErr
	}
	if method == "preview" || method == "rollback-preview" {
		var change agent.Change
		var rollback agent.RollbackArgs
		if method == "preview" {
			if err := decodeStrict(args, &change); err != nil {
				return nil, err
			}
		} else {
			if err := decodeStrict(args, &rollback); err != nil {
				return nil, err
			}
		}
		var draft previewDraft
		var prepareErr error
		executed := false
		a.runOnMain(func() {
			executed = true
			if prepareErr = ctx.Err(); prepareErr == nil {
				if method == "preview" {
					draft, prepareErr = a.prepareAgentPreview(change)
				} else {
					draft, prepareErr = a.prepareAgentRollback(rollback)
				}
			}
		})
		if !executed {
			return nil, errors.New("desktop application is shutting down")
		}
		if prepareErr != nil {
			return nil, prepareErr
		}
		checked, err := validateConfigurations(ctx, a.dir, draft.configs)
		if err != nil {
			return nil, err
		}
		if err := a.verifyDraftSources(draft, checked); err != nil {
			return nil, err
		}
		var result agent.Preview
		var finishErr error
		executed = false
		a.runOnMain(func() {
			executed = true
			if finishErr = ctx.Err(); finishErr == nil {
				result, finishErr = a.finishAgentPreview(draft, checked)
			}
		})
		if !executed {
			return nil, errors.New("desktop application is shutting down")
		}
		return result, finishErr
	}
	var value any
	var callErr error
	executed := false
	a.runOnMain(func() {
		executed = true
		if err := ctx.Err(); err != nil {
			callErr = err
			return
		}
		if method == "show" {
			if a.headless {
				callErr = errors.New("headless instance has no window")
				return
			}
			a.showMain()
			value = map[string]bool{"shown": true}
			return
		}
		value, callErr = a.agentCommand(method, args)
	})
	if !executed {
		return nil, errors.New("desktop application is shutting down")
	}
	return value, callErr
}

func (a *App) agentCommand(method string, args json.RawMessage) (value any, callErr error) {
	switch method {
	case "verge-script-preview-config":
		var input agent.VergeScriptConfigArgs
		if callErr = decodeStrict(args, &input); callErr == nil {
			value, callErr = a.vergeScriptPreviewConfig(input)
		}
	case "verge-script-preview-rules":
		var input agent.PreviewRulesArgs
		if callErr = decodeStrict(args, &input); callErr == nil {
			value, callErr = a.vergeScriptPreviewRules(input)
		}
	case "verge-script-preview-cancel":
		var input agent.ApplyArgs
		if callErr = decodeStrict(args, &input); callErr == nil {
			preview, exists := a.agentScriptPreviews[input.ProposalID]
			delete(a.agentScriptPreviews, input.ProposalID)
			value = agent.ActionResult{OK: exists && preview.expires.After(time.Now())}
		}
	case "chain-status":
		var input agent.Empty
		if callErr = decodeStrict(args, &input); callErr == nil {
			value = a.agentChainStatus()
		}
	case "chain-apply":
		var input agent.ApplyArgs
		if callErr = decodeStrict(args, &input); callErr == nil {
			value, callErr = a.agentChainApply(input.ProposalID)
		}
	case "chain-cancel-preview":
		var input agent.ApplyArgs
		if callErr = decodeStrict(args, &input); callErr == nil {
			proposal, exists := a.agentChainProposals[input.ProposalID]
			delete(a.agentChainProposals, input.ProposalID)
			value = agent.ActionResult{OK: exists && proposal.expires.After(time.Now())}
		}
	case "chain-disconnect":
		var input agent.Empty
		if callErr = decodeStrict(args, &input); callErr == nil {
			callErr = a.disconnectChain()
			result := agent.ActionResult{OK: callErr == nil}
			if a.chainDisconnectWarning != "" {
				result.Warnings = []string{a.chainDisconnectWarning}
			}
			value = result
		}
	case "status":
		value, callErr = a.agentStatus()
	case "connections":
		var input agent.ConnectionsArgs
		if callErr = decodeStrict(args, &input); callErr == nil {
			value, callErr = a.agentConnections(input)
		}
	case "diagnostics":
		value = a.diagnostics()
	case "rewrite-history":
		var input agent.Empty
		if callErr = decodeStrict(args, &input); callErr == nil {
			value, callErr = a.agentRewriteHistory()
		}
	case "preview-rules":
		var input agent.PreviewRulesArgs
		if callErr = decodeStrict(args, &input); callErr == nil {
			value, callErr = a.agentPreviewRules(input)
		}
	case "clear-rewrite-history":
		var input agent.Empty
		if callErr = decodeStrict(args, &input); callErr == nil {
			if a.rewrites == nil {
				callErr = errors.New("rewrite store is unavailable")
			} else if callErr = a.rewrites.CheckCurrent(); callErr == nil {
				var revision uint64
				revision, callErr = a.rewrites.ClearHistory()
				value = agent.ClearRewriteHistoryResult{Revision: revision}
			}
		}
	case "kernel-options":
		value, callErr = a.agentKernelOptions()
	case "tun-autostart":
		var input agent.Empty
		if callErr = decodeStrict(args, &input); callErr == nil {
			if a.model == nil {
				callErr = errors.New("startup preferences unavailable")
			} else {
				value = agent.TunAutoStartResult{Enabled: a.model.Prefs.AutoStartTUN, AppliesTo: "gui"}
			}
		}
	case "tun-autostart-set":
		var input agent.TunArgs
		if callErr = decodeStrict(args, &input); callErr == nil {
			if input.Enabled == nil {
				callErr = errors.New("enabled is required")
			} else if callErr = a.setTUNAutoStart(*input.Enabled); callErr == nil {
				value = agent.TunAutoStartResult{Enabled: *input.Enabled, AppliesTo: "gui"}
			}
		}
	case "kernel-option":
		var input agent.KernelOptionArgs
		if callErr = decodeStrict(args, &input); callErr == nil {
			value, callErr = a.agentSetKernelOption(input)
		}
	case "shutdown":
		if !a.headless || a.headlessCancel == nil {
			callErr = errors.New("shutdown is available only for a headless instance")
		} else {
			value = agent.AfterResponse{Result: agent.ActionResult{OK: true}, After: a.headlessCancel}
		}
	case "preview":
		var change agent.Change
		if callErr = decodeStrict(args, &change); callErr == nil {
			value, callErr = a.agentPreview(change)
		}
	case "apply":
		var input agent.ApplyArgs
		if callErr = decodeStrict(args, &input); callErr == nil {
			value, callErr = a.agentApply(input.ProposalID)
		}
	case "cancel-preview":
		var input agent.ApplyArgs
		if callErr = decodeStrict(args, &input); callErr == nil {
			if input.ProposalID == "" {
				callErr = errors.New("proposal id is required")
			} else {
				proposal, exists := a.agentProposals[input.ProposalID]
				delete(a.agentProposals, input.ProposalID)
				value = agent.ActionResult{OK: exists && proposal.expires.After(time.Now())}
			}
		}
	case "groups":
		var input agent.PageArgs
		if callErr = decodeStrict(args, &input); callErr == nil {
			value, callErr = a.agentGroupsPage(input)
		}
	case "group-nodes":
		var input agent.GroupNodesArgs
		if callErr = decodeStrict(args, &input); callErr == nil {
			value, callErr = a.agentGroupNodes(input)
		}
	case "profiles":
		var input agent.PageArgs
		if callErr = decodeStrict(args, &input); callErr == nil {
			value, callErr = a.agentProfilesPage(input)
		}
	case "profile-settings":
		var input agent.ProfileArgs
		if callErr = decodeStrict(args, &input); callErr == nil {
			value, callErr = a.agentProfileSettings(input.ProfileID)
		}
	case "profile-settings-set":
		var input agent.ProfileSettingsPatch
		if callErr = decodeStrict(args, &input); callErr == nil {
			value, callErr = a.agentUpdateProfileSettings(input)
		}
	case "profile-url-set":
		var input agent.ProfileURLArgs
		if callErr = decodeStrict(args, &input); callErr == nil {
			if a.core == nil || !a.core.Status().Running || a.tunBusy {
				callErr = errors.New("core unavailable or TUN transition in progress")
				break
			}
			if input.ProfileID == "" || len(input.ProfileID) > 256 || len(input.URL) > 8192 || strings.ContainsAny(input.URL, "\r\n\x00") || !profile.ValidURL(input.URL) {
				callErr = errors.New("invalid profile id or subscription URL")
				break
			}
			if a.profileUpdates[input.ProfileID] {
				callErr = errors.New("profile update is in progress")
				break
			}
			value, callErr = a.beginProfileJob("change-url", input.ProfileID, time.Now(), func(done func(string, error)) {
				a.changeProfileURLAsync(input.ProfileID, input.URL, func(err error) { done(input.ProfileID, err) })
			})
		}
	case "import-profile":
		var input agent.ProfileImportArgs
		if callErr = decodeStrict(args, &input); callErr == nil {
			if a.core == nil || !a.core.Status().Running {
				callErr = errors.New("core is not running")
				break
			}
			var form ui.ProfileForm
			form, callErr = profileImportForm(input)
			if callErr == nil {
				value, callErr = a.beginProfileJob("import", "", time.Now(), func(done func(string, error)) {
					a.createProfileWithResult(form, done)
				})
			}
		}
	case "update-profile":
		var input agent.ProfileArgs
		if callErr = decodeStrict(args, &input); callErr == nil {
			if a.core == nil || !a.core.Status().Running {
				callErr = errors.New("core is not running")
				break
			}
			if input.ProfileID == "" || len(input.ProfileID) > 256 {
				callErr = errors.New("invalid profile id")
				break
			}
			if _, err := a.profileItem(input.ProfileID); err != nil {
				callErr = errors.New("remote profile not found")
				break
			}
			value, callErr = a.beginProfileJob("update", input.ProfileID, time.Now(), func(done func(string, error)) {
				a.updateProfileAsync(input.ProfileID, func(err error) { done(input.ProfileID, err) })
			})
		}
	case "profile-job-status":
		var input agent.ProfileJobArgs
		if callErr = decodeStrict(args, &input); callErr == nil {
			value, callErr = a.getProfileJob(input.JobID, time.Now())
		}
	case "webdav-config":
		var input agent.Empty
		if callErr = decodeStrict(args, &input); callErr == nil {
			value, callErr = a.webDAVConfigStatus()
		} else {
			callErr = errors.New("invalid WebDAV configuration request")
		}
	case "webdav-save":
		var input agent.WebDAVConfigArgs
		if callErr = decodeStrict(args, &input); callErr == nil {
			callErr = a.saveWebDAVConfig(input)
			value = agent.ActionResult{OK: callErr == nil}
		} else {
			callErr = errors.New("invalid WebDAV configuration")
		}
	case "webdav-clear":
		var input agent.Empty
		if callErr = decodeStrict(args, &input); callErr == nil {
			callErr = a.clearWebDAVConfig()
			value = agent.ActionResult{OK: callErr == nil}
		} else {
			callErr = errors.New("invalid WebDAV configuration request")
		}
	case "webdav-list":
		var input agent.WebDAVListArgs
		if callErr = decodeStrict(args, &input); callErr == nil {
			value, callErr = a.beginWebDAVList(input, time.Now(), nil)
		} else {
			callErr = errors.New("invalid WebDAV listing input")
		}
	case "webdav-upload":
		var input agent.WebDAVUploadArgs
		if callErr = decodeStrict(args, &input); callErr == nil {
			value, callErr = a.beginWebDAVUpload(input, time.Now(), nil)
		} else {
			callErr = errors.New("invalid WebDAV upload input")
		}
	case "webdav-restore":
		var input agent.WebDAVRestoreArgs
		if callErr = decodeStrict(args, &input); callErr == nil {
			value, callErr = a.beginWebDAVRestore(input, time.Now(), nil)
		} else {
			callErr = errors.New("invalid WebDAV restore input")
		}
	case "backup-schedule":
		var input agent.Empty
		if callErr = decodeStrict(args, &input); callErr == nil {
			var schedule agent.BackupSchedule
			schedule, callErr = a.loadBackupSchedule()
			schedule.LastError, schedule.NextRetry = a.backupScheduleError, a.backupRetry
			schedule.WebDAVError, schedule.WebDAVRetry = a.backupWebDAVError, a.backupWebDAVRetry
			value = schedule
		}
	case "backup-schedule-set":
		var input agent.BackupScheduleArgs
		if callErr = decodeStrict(args, &input); callErr == nil {
			value, callErr = a.setBackupSchedule(input.Enabled, input.Directory, input.IntervalHours, time.Now())
		}
	case "backup-webdav":
		var input agent.BackupWebDAVArgs
		if callErr = decodeStrict(args, &input); callErr == nil {
			value, callErr = a.setBackupWebDAV(input.Enabled)
		}
	case "backup-on-change":
		var input agent.BackupOnChangeArgs
		if callErr = decodeStrict(args, &input); callErr == nil {
			value, callErr = a.setBackupOnChange(input.Enabled)
		}
	case "backup-create":
		var input agent.BackupArgs
		if callErr = decodeStrict(args, &input); callErr == nil {
			value, callErr = a.beginBackupJob(input.Path, time.Now(), nil)
		}
	case "backup-job-status":
		var input agent.BackupJobArgs
		if callErr = decodeStrict(args, &input); callErr == nil {
			value, callErr = a.getBackupJob(input.JobID, time.Now())
		}
	case "restore-create":
		var input agent.RestoreArgs
		if callErr = decodeStrict(args, &input); callErr == nil {
			value, callErr = a.beginRestoreJob(input.Archive, input.Destination, time.Now(), nil)
		}
	case "delete-profile":
		var input agent.ProfileArgs
		if callErr = decodeStrict(args, &input); callErr == nil {
			if input.ProfileID == "" || len(input.ProfileID) > 256 || a.tunBusy {
				callErr = errors.New("invalid profile id or TUN transition in progress")
			} else if err := a.DeleteProfile(input.ProfileID); err != nil {
				callErr = errors.New("profile deletion failed or was partial; ensure it is inactive and inspect profiles before retrying")
			} else {
				value = agent.ActionResult{OK: true}
			}
		}
	case "providers":
		var input agent.Empty
		if callErr = decodeStrict(args, &input); callErr == nil {
			value, callErr = a.agentProviderPreview()
		}
	case "provider-page":
		var input agent.ProviderPageArgs
		if callErr = decodeStrict(args, &input); callErr == nil {
			value, callErr = a.agentProviderPage(input)
		}
	case "update-provider":
		var input agent.ProviderUpdateArgs
		if callErr = decodeStrict(args, &input); callErr == nil {
			if a.probeSlots == nil || a.probeStop == nil {
				callErr = errors.New("provider updates are not ready")
				break
			}
			value, callErr = a.beginProviderJob(input, time.Now(), func(kind, name string, done func(error)) {
				if kind == "proxy" {
					a.updateProxyProviderAsync(name, done)
				} else {
					a.updateRuleProviderAsync(name, done)
				}
			})
		}
	case "provider-job-status":
		var input agent.ProviderJobArgs
		if callErr = decodeStrict(args, &input); callErr == nil {
			value, callErr = a.getProviderJob(input.JobID, time.Now())
		}
	case "rules":
		var input agent.RulesArgs
		if callErr = decodeStrict(args, &input); callErr == nil {
			value, callErr = a.agentRules(input)
		}
	case "select":
		var input agent.SelectArgs
		if callErr = decodeStrict(args, &input); callErr == nil {
			value, callErr = a.agentSelect(input)
		}
	case "tun":
		var input agent.TunArgs
		if callErr = decodeStrict(args, &input); callErr == nil {
			if input.Enabled == nil {
				callErr = errors.New("enabled is required")
			} else {
				var completed, returned bool
				var immediateErr error
				a.requestTUN(*input.Enabled, func(err error) {
					a.tunActionDone(err)
					if !returned {
						completed, immediateErr = true, err
					}
				})
				returned = true
				callErr = immediateErr
				if !completed || callErr == nil {
					value = agent.TunResult{Accepted: true, Pending: !completed, TUN: a.core.Status().TUN}
				}
			}
		}
	case "update-geo":
		var input agent.Empty
		if callErr = decodeStrict(args, &input); callErr == nil {
			var returned bool
			a.updateGeoAsync(func(count int, err error) {
				if !returned {
					callErr = err
					return
				}
				if a.model != nil {
					if err != nil {
						a.model.Notice = "GeoData 更新失败: " + err.Error()
					} else {
						a.model.Notice = fmt.Sprintf("已下载 %d 个 GeoData 数据库，请退出并重新启动 NetFlow 以应用", count)
					}
				}
			})
			returned = true
			if callErr == nil {
				value = agent.GeoResult{Accepted: true, Pending: a.geoBusy}
			}
		}
	case "mode":
		var input agent.ModeArgs
		if callErr = decodeStrict(args, &input); callErr == nil {
			if a.core == nil || !a.core.Status().Running {
				callErr = errors.New("core is not running")
			} else {
				callErr = a.SetMode(input.Mode)
			}
			value = agent.ActionResult{OK: callErr == nil}
		}
	case "use-profile":
		var input agent.ProfileArgs
		if callErr = decodeStrict(args, &input); callErr == nil {
			if a.core == nil || !a.core.Status().Running {
				callErr = errors.New("core is not running")
			} else {
				callErr = a.UseProfile(input.ProfileID)
			}
			value = agent.ActionResult{OK: callErr == nil}
		}
	case "close-connection":
		var input agent.ConnectionArgs
		if callErr = decodeStrict(args, &input); callErr == nil {
			if input.ConnectionID == "" {
				callErr = errors.New("connection id is required")
			} else if a.core == nil || !a.core.Status().Running {
				callErr = errors.New("core is not running")
			} else {
				var closed bool
				closed, callErr = a.core.CloseExistingConnection(input.ConnectionID)
				value = agent.CloseResult{Closed: closed}
			}
		}
	default:
		callErr = errors.New("unknown agent method")
	}
	return value, callErr
}

func decodeStrict(raw json.RawMessage, out any) error {
	if len(raw) == 0 {
		raw = []byte(`{}`)
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(out); err != nil {
		return err
	}
	var extra any
	if err := decoder.Decode(&extra); err != io.EOF {
		return errors.New("unexpected trailing JSON")
	}
	return nil
}

func (a *App) expiryLoop(stop <-chan struct{}) {
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	nextProposalCleanup := time.Now().Add(15 * time.Second)
	for {
		select {
		case <-stop:
			return
		case now := <-ticker.C:
			state := a.rewrites.Snapshot()
			expired := false
			for _, c := range state.Connections {
				if !c.ExpiresAt.After(now) {
					expired = true
					break
				}
			}
			cleanupProposals := !now.Before(nextProposalCleanup)
			if cleanupProposals {
				nextProposalCleanup = now.Add(15 * time.Second)
			}
			if !expired && !cleanupProposals {
				continue
			}
			a.runOnMain(func() {
				if cleanupProposals {
					a.pruneExpiredProposals(time.Now())
					a.pruneExpiredChainProposals(time.Now())
				}
				if !expired {
					return
				}
				if err := a.expireRules(time.Now()); err != nil {
					a.rewriteWarning = "Temporary rule cleanup failed; inspect the rules file and application logs."
					if a.model != nil {
						a.model.Notice = "Agent 临时规则清理失败: " + err.Error()
						if a.win != nil {
							a.win.Invalidate()
						}
					}
				} else {
					a.rewriteWarning = ""
				}
			})
		}
	}
}

func (a *App) expireRules(now time.Time) error {
	old := a.rewrites.Snapshot()
	next := old
	next.Connections = nil
	for _, c := range old.Connections {
		if c.ExpiresAt.After(now) {
			next.Connections = append(next.Connections, c)
		}
	}
	if len(next.Connections) == len(old.Connections) {
		return nil
	}
	saved, err := a.rewrites.Replace(next, old.Revision)
	if err != nil {
		// Do not let a conflicting or unwritable state file keep an expired
		// matcher active indefinitely. Compose omits expired rules even when
		// the in-memory state still contains them. Avoid reloading every tick.
		var expired []string
		for _, c := range old.Connections {
			if !c.ExpiresAt.After(now) {
				expired = append(expired, c.ID+"/"+c.ExpiresAt.UTC().Format(time.RFC3339Nano))
			}
		}
		signature := strings.Join(expired, "\x00")
		if a.core != nil && a.core.Status().Running && signature != a.expiryFallbackSignature {
			if reloadErr := a.core.Reload(); reloadErr != nil {
				return errors.Join(err, fmt.Errorf("remove expired runtime rules: %w", reloadErr))
			}
			a.expiryFallbackSignature = signature
		}
		return err
	}
	a.expiryFallbackSignature = ""
	if a.core != nil && a.core.Status().Running {
		if err = a.core.Reload(); err != nil {
			_, restoreErr := a.rewrites.Replace(old, saved.Revision)
			if restoreErr == nil {
				restoreErr = a.core.Reload()
			}
			if restoreErr != nil {
				return errors.Join(err, fmt.Errorf("restore previous rules: %w", restoreErr))
			}
			return err
		}
	}
	return nil
}
