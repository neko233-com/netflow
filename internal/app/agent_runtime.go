package app

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/neko233-com/netflow/internal/agent"
	"github.com/neko233-com/netflow/internal/migration"
	"github.com/neko233-com/netflow/internal/profile"
	"github.com/neko233-com/netflow/internal/rewrite"
	"github.com/neko233-com/netflow/internal/scriptapproval"
	"github.com/neko233-com/netflow/internal/scriptmeta"
	"github.com/neko233-com/netflow/internal/scriptpreview"
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
	// Shutdown must remain reachable while the serialized event loop is waiting
	// for a kernel operation. The bridge invokes the cancellation only after it
	// has written the acknowledgement, as for the normal command path.
	if method == "shutdown" && a.headless {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		if a.headlessCancel == nil {
			return nil, errors.New("headless instance is not ready to shut down")
		}
		return agent.AfterResponse{Result: agent.ActionResult{OK: true}, After: a.headlessCancel}, nil
	}
	if method == "status" {
		return a.dispatchAgentStatus(ctx)
	}
	if method == "restart-core" {
		var input agent.Empty
		if err := decodeStrict(args, &input); err != nil {
			return nil, err
		}
		result := make(chan error, 1)
		executed := false
		a.runOnMainContext(ctx, func() {
			executed = true
			if err := ctx.Err(); err != nil {
				result <- err
				return
			}
			a.restartCoreAsync(func(err error) { result <- err })
		})
		if !executed {
			return nil, agentRequestUnavailable(ctx)
		}
		select {
		case err := <-result:
			return agent.ActionResult{OK: err == nil}, err
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
	if method == "cancel-apply" {
		var in agent.Empty
		if err := decodeStrict(args, &in); err != nil {
			return nil, err
		}
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		engine, ok := a.core.(interface {
			CancelActiveApply(context.Context) (bool, error)
		})
		if !ok {
			return nil, errors.New("kernel does not support canceling configuration application")
		}
		accepted, err := engine.CancelActiveApply(ctx)
		if err != nil {
			return nil, err
		}
		return agent.CancelApplyResult{Accepted: accepted}, nil
	}
	if method == "chain-apply" || method == "chain-disconnect" {
		var input agent.ApplyArgs
		if method == "chain-apply" {
			if err := decodeStrict(args, &input); err != nil {
				return nil, err
			}
		} else {
			var empty agent.Empty
			if err := decodeStrict(args, &empty); err != nil {
				return nil, err
			}
		}
		type response struct {
			value any
			err   error
		}
		result := make(chan response, 1)
		var operation *guiConfigOperation
		executed := false
		a.runOnMainContext(ctx, func() {
			executed = true
			if err := ctx.Err(); err != nil {
				result <- response{err: err}
				return
			}
			previous := a.guiOperation
			defer func() {
				if a.guiOperation != previous {
					operation = a.guiOperation
				}
			}()
			if method == "chain-disconnect" {
				a.disconnectChainAsync(func(err error) {
					out := agent.ActionResult{OK: err == nil}
					if a.chainDisconnectWarning != "" {
						out.Warnings = []string{a.chainDisconnectWarning}
					}
					result <- response{value: out, err: err}
				})
				return
			}
			a.startGUIConfigOperation("正在连接代理链", func() (*guiConfigTransaction, error) {
				p, ok := a.agentChainProposals[input.ProposalID]
				delete(a.agentChainProposals, input.ProposalID)
				if !ok || !p.expires.After(time.Now()) {
					return nil, errors.New("chain proposal missing or expired; preview again")
				}
				return a.beginChainConnect(p.draft, p.checked)
			}, func(err error) {
				if err != nil {
					result <- response{err: err}
					return
				}
				result <- response{value: a.agentChainStatus()}
			})
		})
		if !executed {
			return nil, agentRequestUnavailable(ctx)
		}
		select {
		case out := <-result:
			return out.value, out.err
		case <-ctx.Done():
			a.cancelAgentConfigOperation(operation)
			return nil, ctx.Err()
		}
	}
	if method == "kernel-option" {
		var input agent.KernelOptionArgs
		if err := decodeStrict(args, &input); err != nil {
			return nil, err
		}
		type response struct {
			value agent.KernelOptionsResult
			err   error
		}
		result := make(chan response, 1)
		var operation *guiConfigOperation
		executed := false
		a.runOnMainContext(ctx, func() {
			executed = true
			if err := ctx.Err(); err != nil {
				result <- response{err: err}
				return
			}
			previous := a.guiOperation
			a.startGUIConfigOperation("正在应用内核设置", func() (*guiConfigTransaction, error) {
				next, err := a.agentKernelOptionCandidate(input)
				if err != nil {
					return nil, err
				}
				return a.beginGUIKernelOptions(next, false)
			}, func(err error) {
				if err != nil {
					result <- response{err: err}
					return
				}
				value, err := a.agentKernelOptions()
				result <- response{value: value, err: err}
			})
			if a.guiOperation != previous {
				operation = a.guiOperation
			}
		})
		if !executed {
			return nil, agentRequestUnavailable(ctx)
		}
		select {
		case out := <-result:
			return out.value, out.err
		case <-ctx.Done():
			a.cancelAgentConfigOperation(operation)
			return nil, ctx.Err()
		}
	}
	if method == "apply" {
		var input agent.ApplyArgs
		if err := decodeStrict(args, &input); err != nil {
			return nil, err
		}
		type response struct {
			value agent.ApplyResult
			err   error
		}
		result := make(chan response, 1)
		var operation *guiConfigOperation
		executed := false
		a.runOnMainContext(ctx, func() {
			executed = true
			if err := ctx.Err(); err != nil {
				result <- response{err: err}
				return
			}
			previous := a.guiOperation
			a.agentApplyAsync(input.ProposalID, func(value agent.ApplyResult, err error) { result <- response{value, err} })
			if a.guiOperation != previous {
				operation = a.guiOperation
			}
		})
		if !executed {
			return nil, agentRequestUnavailable(ctx)
		}
		select {
		case out := <-result:
			return out.value, out.err
		case <-ctx.Done():
			a.cancelAgentConfigOperation(operation)
			return nil, ctx.Err()
		}
	}
	if method == "use-profile" || method == "mode" {
		var start func(func(error))
		if method == "use-profile" {
			var input agent.ProfileArgs
			if err := decodeStrict(args, &input); err != nil {
				return nil, err
			}
			start = func(done func(error)) { a.useProfileAsync(input.ProfileID, done) }
		} else {
			var input agent.ModeArgs
			if err := decodeStrict(args, &input); err != nil {
				return nil, err
			}
			start = func(done func(error)) { a.setModeAsync(input.Mode, done) }
		}
		result := make(chan error, 1)
		var operation *guiConfigOperation
		executed := false
		a.runOnMainContext(ctx, func() {
			executed = true
			if err := ctx.Err(); err != nil {
				result <- err
				return
			}
			if a.core == nil || !a.core.Status().Running {
				result <- errors.New("core is not running")
				return
			}
			previous := a.guiOperation
			start(func(err error) { result <- err })
			if a.guiOperation != previous {
				operation = a.guiOperation
			}
		})
		if !executed {
			return nil, agentRequestUnavailable(ctx)
		}
		select {
		case err := <-result:
			return agent.ActionResult{OK: err == nil}, err
		case <-ctx.Done():
			a.cancelAgentConfigOperation(operation)
			return nil, ctx.Err()
		}
	}
	if method == "verge-script-cache-prune" {
		var in agent.Empty
		if err := decodeStrict(args, &in); err != nil {
			return nil, err
		}
		select {
		case vergeScriptPreviewSlots <- struct{}{}:
			defer func() { <-vergeScriptPreviewSlots }()
		case <-ctx.Done():
			return nil, ctx.Err()
		}
		var refs []scriptmeta.Approval
		var profileRefs []string
		var hash [32]byte
		var captureErr error
		executed := false
		a.runOnMainContext(ctx, func() {
			executed = true
			if captureErr = ctx.Err(); captureErr != nil {
				return
			}
			if a.profiles == nil {
				captureErr = errors.New("profile store is unavailable")
				return
			}
			var catalog profile.File
			catalog, hash, captureErr = a.profiles.LoadSnapshot()
			if captureErr != nil {
				return
			}
			if hash == ([32]byte{}) {
				captureErr = errors.New("profile catalog is missing")
				return
			}
			for _, item := range catalog.Items {
				profileRefs = append(profileRefs, item.File)
				if item.Option.VergeScriptApproval != nil {
					refs = append(refs, *item.Option.VergeScriptApproval)
				}
				if item.Option.VergeScriptPrevious != nil && item.Option.VergeScriptPrevious.Approval != nil {
					refs = append(refs, *item.Option.VergeScriptPrevious.Approval)
				}
				if previous := item.Option.VergeScriptPrevious; previous != nil && previous.Subscription != nil {
					profileRefs = append(profileRefs, previous.Subscription.File)
				}
			}
		})
		if !executed {
			return nil, agentRequestUnavailable(ctx)
		}
		if captureErr != nil {
			if ctx.Err() != nil {
				return nil, ctx.Err()
			}
			return nil, errors.New("profile catalog is unavailable")
		}
		guard := func() error {
			var guardErr error
			ran := false
			a.runOnMainContext(ctx, func() {
				ran = true
				if guardErr = ctx.Err(); guardErr != nil {
					return
				}
				if a.profiles == nil {
					guardErr = errors.New("profile store is unavailable")
					return
				}
				_, current, e := a.profiles.LoadSnapshot()
				if e != nil || current != hash {
					guardErr = errors.New("profile catalog changed")
				}
			})
			if !ran {
				return agentRequestUnavailable(ctx)
			}
			return guardErr
		}
		result, err := scriptapproval.Prune(ctx, a.dir, refs, guard)
		if err != nil {
			return nil, err
		}
		profiles, err := scriptapproval.PruneSubscriptions(ctx, a.dir, profileRefs, guard)
		if err != nil {
			return nil, fmt.Errorf("script cache cleanup removed %d files before subscription cleanup failed: %w", result.Removed, err)
		}
		return agent.VergeScriptCachePruneResult{Removed: result.Removed + profiles.Removed, Bytes: result.Bytes + profiles.Bytes}, nil
	}
	if method == "verge-script-preview" || method == "verge-script-rollback-preview" || method == "verge-script-update-preview" {
		var in agent.VergeScriptPreviewArgs
		rollback := method == "verge-script-rollback-preview"
		updating := method == "verge-script-update-preview"
		var updateRequest agent.VergeScriptUpdateArgs
		if updating {
			if err := decodeStrict(args, &updateRequest); err != nil {
				return nil, err
			}
			in.ProfileID = updateRequest.ProfileID
		} else if rollback {
			var request agent.ProfileArgs
			if err := decodeStrict(args, &request); err != nil {
				return nil, err
			}
			in.ProfileID = request.ProfileID
		} else if err := decodeStrict(args, &in); err != nil {
			return nil, err
		}
		select {
		case vergeScriptPreviewSlots <- struct{}{}:
			defer func() { <-vergeScriptPreviewSlots }()
		case <-ctx.Done():
			return nil, ctx.Err()
		}
		var draft vergeScriptDraft
		var client *http.Client
		var lockedProfile string
		var prepareErr error
		executed := false
		a.runOnMainContext(ctx, func() {
			executed = true
			if prepareErr = ctx.Err(); prepareErr == nil {
				draft, prepareErr = a.captureVergeScriptDraft(in.ProfileID)
			}
			if prepareErr == nil && updating {
				if draft.item.Type != "remote" || !profile.ValidURL(draft.item.URL) || draft.item.Option.VergeScriptApproval == nil {
					prepareErr = errors.New("remote profile with approved scripts is required")
				} else if a.profileUpdates[draft.target] {
					prepareErr = errors.New("profile update is in progress")
				} else if client, prepareErr = a.subscriptionClient(draft.item.Option, false); prepareErr == nil {
					if a.profileUpdates == nil {
						a.profileUpdates = make(map[string]bool)
					}
					a.profileUpdates[draft.target], lockedProfile = true, draft.target
				}
			}
		})
		if lockedProfile != "" {
			defer func() { a.runOnMain(func() { delete(a.profileUpdates, lockedProfile) }) }()
		}
		if client != nil {
			defer client.CloseIdleConnections()
		}
		if !executed {
			return nil, agentRequestUnavailable(ctx)
		}
		if prepareErr != nil {
			if ctx.Err() != nil {
				return nil, ctx.Err()
			}
			return nil, errors.New("script preview configuration is unavailable or has changed")
		}
		var prepared scriptpreview.Prepared
		var update *vergeSubscriptionUpdate
		var err error
		if updating {
			replacing := updateRequest.URL != nil
			nextURL := ""
			if replacing {
				nextURL = strings.TrimSpace(*updateRequest.URL)
			}
			if replacing && (len(nextURL) > 8192 || strings.ContainsAny(nextURL, "\r\n\x00") || !profile.ValidURL(nextURL)) {
				return nil, errors.New("invalid replacement subscription URL")
			}
			if !replacing {
				nextURL = draft.item.URL
			}
			var source profileSourceSnapshot
			source, err = a.snapshotProfileSource(draft.item.File)
			var response subscriptionResponse
			if err == nil {
				response, err = fetchProfileResponseContext(ctx, nextURL, client, draft.item.Option.UserAgent)
			}
			if err != nil {
				if ctx.Err() != nil {
					return nil, ctx.Err()
				}
				return nil, errors.New("subscription download failed")
			}
			prepared, err = a.prepareVergeScriptUpdate(ctx, draft, source, response.body)
			if err == nil {
				metadata := draft.item
				metadata.URL = nextURL
				profile.ApplySubscriptionUserInfo(&metadata, response.headers)
				update = &vergeSubscriptionUpdate{body: response.body, replacementURL: replacing, snapshot: scriptmeta.SubscriptionSnapshot{URL: metadata.URL, Name: metadata.Name, Updated: time.Now().UTC().Truncate(time.Second), Used: metadata.Used, Total: metadata.Total, Expire: metadata.Expire}}
			}
		} else if rollback {
			prepared, err = a.prepareVergeScriptRollback(ctx, draft)
		} else if !in.Global && !in.Profile {
			prepared, err = a.prepareVergeScriptDisable(ctx, draft)
		} else {
			prepared, err = a.prepareVergeScript(ctx, draft, migration.ScriptSelection{Global: in.Global, Profile: in.Profile})
		}
		if err != nil {
			return nil, err
		}
		if err := a.checkAgentSources(draft.hashes); err != nil {
			return nil, errors.New("script preview sources changed")
		}
		var result agent.VergeScriptPreview
		var finishErr error
		executed = false
		a.runOnMainContext(ctx, func() {
			executed = true
			if finishErr = ctx.Err(); finishErr == nil {
				result, finishErr = a.finishVergeScriptPreview(draft, prepared, rollback, update)
			}
		})
		if !executed {
			return nil, agentRequestUnavailable(ctx)
		}
		return result, finishErr
	}
	if method == "verge-script-apply" {
		var in agent.ApplyArgs
		if err := decodeStrict(args, &in); err != nil {
			return nil, err
		}
		select {
		case vergeScriptPreviewSlots <- struct{}{}:
			defer func() { <-vergeScriptPreviewSlots }()
		case <-ctx.Done():
			return nil, ctx.Err()
		}
		var proposal vergeScriptPreviewPages
		var takeErr error
		executed := false
		a.runOnMainContext(ctx, func() {
			executed = true
			if takeErr = ctx.Err(); takeErr != nil {
				return
			}
			var ok bool
			proposal, ok = a.agentScriptPreviews[in.ProposalID]
			delete(a.agentScriptPreviews, in.ProposalID)
			if !ok || !proposal.expires.After(time.Now()) {
				takeErr = errors.New("script preview missing or expired")
				return
			}
			takeErr = a.checkVergeScriptDraft(proposal.draft)
		})
		if !executed {
			return nil, agentRequestUnavailable(ctx)
		}
		if takeErr != nil {
			return nil, takeErr
		}
		ready, err := a.prepareVergeScriptCommit(ctx, proposal)
		if err != nil {
			return nil, err
		}
		var active bool
		var finishErr error
		executed = false
		completed := make(chan error, 1)
		var operation *guiConfigOperation
		a.runOnMainContext(ctx, func() {
			executed = true
			finish := func(err error) {
				if err == nil && a.model != nil {
					a.loadProfiles()
					a.refreshHome()
					a.model.Notice = "Verge 脚本设置已应用"
					if a.win != nil {
						a.win.Invalidate()
					}
				}
				completed <- err
			}
			previous := a.guiOperation
			a.startGUIConfigOperation("正在应用 Verge 脚本", func() (*guiConfigTransaction, error) {
				var tx *guiConfigTransaction
				active, tx, finishErr = a.beginVergeScriptCommit(ctx, ready)
				return tx, finishErr
			}, finish)
			if a.guiOperation != previous {
				operation = a.guiOperation
			}
		})
		if !executed {
			return nil, agentRequestUnavailable(ctx)
		}
		select {
		case finishErr = <-completed:
			// The completion callback runs before the GUI transaction releases
			// its barrier. Do not acknowledge completion until queued work can
			// observe the committed or restored state.
			if operation != nil {
				select {
				case <-operation.done:
				case <-ctx.Done():
					return nil, ctx.Err()
				}
			}
		case <-ctx.Done():
			if operation != nil {
				go a.runOnMainUnrestricted(func() { a.cancelGUIConfigOperation(operation) })
			}
			return nil, ctx.Err()
		}
		if finishErr != nil {
			return nil, finishErr
		}
		var warnings []string
		if ready.approval != nil {
			warnings = append(warnings, "Script output is pinned to this subscription and archive; changes require a new preview.")
		}
		if !proposal.draft.status.Running {
			warnings = append(warnings, "The core is stopped; start it to use the saved setting.")
		} else if !active {
			warnings = append(warnings, "The profile is inactive; changes take effect when it is activated.")
		}
		return agent.VergeScriptApplyResult{Applied: true, Active: active, CoreRunning: proposal.draft.status.Running, Warnings: warnings}, nil
	}
	if method == "chain-preview" {
		var in agent.ChainPreviewArgs
		if err := decodeStrict(args, &in); err != nil {
			return nil, err
		}
		var draft chainDraft
		var prepareErr error
		executed := false
		a.runOnMainContext(ctx, func() {
			executed = true
			if prepareErr = ctx.Err(); prepareErr == nil {
				draft, prepareErr = a.prepareAgentChain(in)
			}
		})
		if !executed {
			return nil, agentRequestUnavailable(ctx)
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
		a.runOnMainContext(ctx, func() {
			executed = true
			if finishErr = ctx.Err(); finishErr == nil {
				result, finishErr = a.finishAgentChainPreview(draft, checked)
			}
		})
		if !executed {
			return nil, agentRequestUnavailable(ctx)
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
		if err := a.syncPreviewCaches(ctx); err != nil {
			return nil, err
		}
		var draft previewDraft
		var prepareErr error
		executed := false
		a.runOnMainContext(ctx, func() {
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
			return nil, agentRequestUnavailable(ctx)
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
		a.runOnMainContext(ctx, func() {
			executed = true
			if finishErr = ctx.Err(); finishErr == nil {
				result, finishErr = a.finishAgentPreview(draft, checked)
			}
		})
		if !executed {
			return nil, agentRequestUnavailable(ctx)
		}
		return result, finishErr
	}
	var value any
	var callErr error
	executed := false
	a.runOnMainContext(ctx, func() {
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
		return nil, agentRequestUnavailable(ctx)
	}
	return value, callErr
}

func agentRequestUnavailable(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	return errors.New("application is shutting down")
}

// Cancel only the transaction started by this request; the callback may run
// after that transaction has completed and another has started.
func (a *App) cancelAgentConfigOperation(operation *guiConfigOperation) {
	if operation != nil {
		go a.runOnMainUnrestricted(func() { a.cancelGUIConfigOperation(operation) })
	}
}

// A status request must not hold an HTTP handler indefinitely when a kernel
// transaction blocks the event loop. Coalesce pending reads and never return
// a stale snapshot as live state. The queued callback checks its context
// before accessing app state after the caller has timed out.
func (a *App) dispatchAgentStatus(parent context.Context) (any, error) {
	if err := parent.Err(); err != nil {
		return nil, err
	}
	if !a.agentStatusInFlight.CompareAndSwap(false, true) {
		return nil, errors.New("status unavailable: application is busy")
	}
	ctx, cancel := context.WithTimeout(parent, 2*time.Second)
	defer cancel()
	type statusResult struct {
		value agent.Status
		err   error
	}
	result := make(chan statusResult, 1)
	go func() {
		defer a.agentStatusInFlight.Store(false)
		var out statusResult
		executed := false
		a.runOnMain(func() {
			executed = true
			if out.err = ctx.Err(); out.err == nil {
				out.value, out.err = a.agentStatus()
			}
		})
		if !executed {
			out.err = errors.New("desktop application is shutting down")
		}
		result <- out
	}()
	select {
	case out := <-result:
		return out.value, out.err
	case <-ctx.Done():
		if err := parent.Err(); err != nil {
			return nil, err
		}
		return nil, errors.New("status unavailable: application is busy")
	}
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
	case "delay-test":
		var input agent.DelayArgs
		if callErr = decodeStrict(args, &input); callErr == nil {
			if a.probeSlots == nil || a.probeStop == nil {
				callErr = errors.New("latency tests are not ready")
			} else {
				value, callErr = a.beginDelayJob(input, time.Now(), a.testProxyForProfileAsync)
			}
		}
	case "delay-job-status":
		var input agent.DelayJobArgs
		if callErr = decodeStrict(args, &input); callErr == nil {
			value, callErr = a.getDelayJob(input.JobID, time.Now())
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
				previousTUN := a.core.Status().TUN
				a.requestTUN(*input.Enabled, func(err error) {
					a.tunActionDone(err)
					if !returned {
						completed, immediateErr = true, err
					}
				})
				returned = true
				callErr = immediateErr
				if !completed || callErr == nil {
					if completed {
						previousTUN = a.core.Status().TUN
					}
					value = agent.TunResult{Accepted: true, Pending: !completed, TUN: previousTUN}
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
			expired := false
			if !a.headlessRecovery {
				state := a.rewrites.Snapshot()
				for _, c := range state.Connections {
					if !c.ExpiresAt.After(now) {
						expired = true
						break
					}
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
				// The handoff is composing a stopped kernel. Retry expiration on
				// the next tick instead of mutating its rule snapshot mid-switch.
				if !expired || a.tunBusy || a.guiConfigBusy() {
					return
				}
				// A conflicting file has already had its expired runtime rules
				// removed. Avoid starting a new visible operation every tick.
				if signature := expiredRuleSignature(a.rewrites.Snapshot(), time.Now()); signature != "" && signature == a.expiryFallbackSignature {
					if err := a.rewrites.CheckCurrent(); err != nil {
						a.reportRuleExpiry(err)
						return
					}
				}
				a.expireRulesAsync(time.Now(), a.reportRuleExpiry)
			})
		}
	}
}

func expiredRuleSignature(state rewrite.State, now time.Time) string {
	var expired []string
	for _, c := range state.Connections {
		if !c.ExpiresAt.After(now) {
			expired = append(expired, c.ID+"/"+c.ExpiresAt.UTC().Format(time.RFC3339Nano))
		}
	}
	return strings.Join(expired, "\x00")
}

func (a *App) expireRules(now time.Time) error {
	tx, warning, err := a.beginRuleExpiry(now)
	if err != nil {
		return err
	}
	if tx.reload {
		err = a.core.Reload()
	}
	if err == nil {
		err = tx.commit()
	}
	if err == nil {
		return warning
	}
	needReload, restoreErr := tx.rollback()
	if restoreErr == nil && needReload {
		restoreErr = a.core.Reload()
	}
	return errors.Join(warning, tx.wrap(err, restoreErr))
}

func (a *App) reportRuleExpiry(err error) {
	if err == nil {
		a.rewriteWarning = ""
		return
	}
	a.rewriteWarning = "Temporary rule cleanup failed; inspect the rules file and application logs."
	if a.model != nil {
		switch {
		case errors.Is(err, rewrite.ErrConflict):
			a.model.Notice = "Agent 规则文件已被外部修改，请检查后重启"
		case errors.Is(err, context.Canceled):
			a.model.Notice = "Agent 临时规则清理已取消，将稍后重试"
		default:
			// Kernel diagnostics can contain subscription URLs or credentials.
			a.model.Notice = "Agent 临时规则清理失败，将稍后重试；请检查配置与日志"
		}
		if a.win != nil {
			a.win.Invalidate()
		}
	}
}

func (a *App) expireRulesAsync(now time.Time, done func(error)) {
	var warning error
	a.startGUIConfigOperation("正在清理过期规则", func() (*guiConfigTransaction, error) {
		tx, issue, err := a.beginRuleExpiry(now)
		warning = issue
		return tx, err
	}, func(err error) { done(errors.Join(warning, err)) })
}

// beginRuleExpiry runs on the application event loop. Expired rules already
// stop matching in the kernel even if persistence or reload cannot complete.
func (a *App) beginRuleExpiry(now time.Time) (*guiConfigTransaction, error, error) {
	old := a.rewrites.Snapshot()
	next := old
	next.Connections = nil
	for _, c := range old.Connections {
		if c.ExpiresAt.After(now) {
			next.Connections = append(next.Connections, c)
		}
	}
	if len(next.Connections) == len(old.Connections) {
		return &guiConfigTransaction{commit: func() error { return nil }, rollback: func() (bool, error) { return false, nil }, wrap: func(err, _ error) error { return err }}, nil, nil
	}
	saved, err := a.rewrites.Replace(next, old.Revision)
	if err != nil {
		// Do not let a conflicting or unwritable state file keep an expired
		// matcher active indefinitely. Compose omits expired rules even when
		// the in-memory state still contains them. Avoid reloading every tick.
		signature := expiredRuleSignature(old, now)
		reload := a.core != nil && a.core.Status().Running && signature != a.expiryFallbackSignature
		return &guiConfigTransaction{
			reload: reload,
			commit: func() error {
				if reload {
					a.expiryFallbackSignature = signature
				}
				return nil
			},
			rollback: func() (bool, error) { return false, nil },
			wrap:     func(cause, _ error) error { return fmt.Errorf("remove expired runtime rules: %w", cause) },
		}, err, nil
	}
	a.expiryFallbackSignature = ""
	running := a.core != nil && a.core.Status().Running
	return &guiConfigTransaction{
		reload: running,
		commit: func() error { return nil },
		rollback: func() (bool, error) {
			_, err := a.rewrites.Replace(old, saved.Revision)
			return err == nil && running, err
		},
		wrap: func(cause, restoreErr error) error {
			if restoreErr != nil {
				return errors.Join(cause, fmt.Errorf("restore previous rules: %w", restoreErr))
			}
			return cause
		},
	}, nil, nil
}
