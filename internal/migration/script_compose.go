package migration

import (
	"context"
	"errors"

	"github.com/neko233-com/netflow/internal/profile"
)

// ScriptSelection is explicit: a zero value never executes imported scripts.
type ScriptSelection struct{ Global, Profile bool }

// ScriptExecutor transforms a YAML or JSON configuration and returns JSON or
// YAML. Its implementation must impose resource limits and not persist input.
type ScriptExecutor func(context.Context, []byte, string, string) ([]byte, error)

// ComposeArchivedSnapshot applies the global merge and optional global script,
// then the profile merge and optional profile script. Callers must provide the
// correct input rule layers and validate the final result before any use; this
// function neither writes settings nor authorizes future execution.
func ComposeArchivedSnapshot(ctx context.Context, base []byte, snapshot ArchivedScriptSnapshot, extensions profile.VergeExtensions, name string, selection ScriptSelection, execute ScriptExecutor) ([]byte, error) {
	if ctx == nil {
		return nil, errors.New("context is required")
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if (selection.Global || selection.Profile) && execute == nil {
		return nil, errors.New("script executor is required")
	}
	if selection.Global && snapshot.Global == nil {
		return nil, errors.New("global script is unavailable")
	}
	if selection.Profile && snapshot.Profile == nil {
		return nil, errors.New("profile script is unavailable")
	}
	result, err := profile.ComposeVergeExtensions(base, profile.VergeExtensions{Rules: extensions.Rules, Proxies: extensions.Proxies, Groups: extensions.Groups, GlobalMerge: extensions.GlobalMerge})
	if err != nil {
		return nil, err
	}
	if selection.Global {
		result, err = execute(ctx, result, string(snapshot.Global.Source), name)
		if err != nil {
			return nil, err
		}
	}
	if err = ctx.Err(); err != nil {
		return nil, err
	}
	result, err = profile.ComposeVergeExtensions(result, profile.VergeExtensions{ProfileMerge: extensions.ProfileMerge})
	if err != nil {
		return nil, err
	}
	if selection.Profile {
		result, err = execute(ctx, result, string(snapshot.Profile.Source), name)
		if err != nil {
			return nil, err
		}
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return result, nil
}
