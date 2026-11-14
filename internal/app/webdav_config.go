package app

import (
	"encoding/json"
	"errors"

	"github.com/neko233-com/netflow/internal/agent"
	"github.com/neko233-com/netflow/internal/secretstore"
	"github.com/neko233-com/netflow/internal/webdav"
)

func (a *App) webDAVConfigStatus() (agent.WebDAVConfigStatus, error) {
	data, err := prefsMap(a.settings.Prefs)
	if err != nil {
		return agent.WebDAVConfigStatus{}, errors.New("WebDAV settings unavailable")
	}
	plain, err := plainWebDAV(data)
	if err != nil {
		return agent.WebDAVConfigStatus{}, errors.New("WebDAV settings unavailable")
	}
	protected, err := prefString(data, webDAVProtectedKey)
	if err != nil {
		return agent.WebDAVConfigStatus{}, errors.New("WebDAV settings unavailable")
	}
	return agent.WebDAVConfigStatus{Saved: !plain.empty() || protected != "", ProtectedStorageAvailable: secretstore.Available()}, nil
}

// saveWebDAVConfig replaces credentials only when explicitly called. It never
// stores new plaintext when the platform lacks account-protected storage.
func (a *App) saveWebDAVConfig(args agent.WebDAVConfigArgs) error {
	if a.backupBusy {
		return errors.New("wait for the active backup task to finish")
	}
	if err := webdav.Validate(webdav.Credentials{URL: args.URL, User: args.User, Password: args.Password}); err != nil {
		return err
	}
	if !secretstore.Available() {
		return errors.New("account-protected WebDAV storage is unavailable on this platform")
	}
	if a.store == nil {
		return errors.New("settings storage is unavailable")
	}
	data, err := prefsMap(a.settings.Prefs)
	if err != nil {
		return errors.New("WebDAV settings unavailable")
	}
	protected, err := protectWebDAV(webDAVCredentials{URL: args.URL, User: args.User, Password: args.Password})
	if err != nil {
		return errors.New("could not protect WebDAV credentials")
	}
	for _, key := range webDAVPlainKeys {
		removePref(data, key)
	}
	removePref(data, webDAVProtectedKey)
	data[webDAVProtectedKey], err = json.Marshal(protected)
	if err != nil {
		return errors.New("could not protect WebDAV credentials")
	}
	encoded, err := json.Marshal(data)
	if err != nil {
		return errors.New("could not encode WebDAV settings")
	}
	next := a.settings
	next.Prefs = string(encoded)
	if err := a.store.Save(next); err != nil {
		return errors.New("could not save WebDAV settings")
	}
	a.settings, a.webDAVProtected, a.webDAVProtectionErr = next, protected, nil
	if a.model != nil {
		a.model.Prefs.WebDAVURL, a.model.Prefs.WebDAVUser, a.model.Prefs.WebDAVPassword = "", "", ""
		a.model.WebDAVSecretStored = true
	}
	return nil
}

// clearWebDAVConfig is idempotent and removes both separately stored and
// URL-embedded credentials along with the saved address.
func (a *App) clearWebDAVConfig() error {
	if a.backupBusy {
		return errors.New("wait for the active backup task to finish")
	}
	if a.store == nil {
		return errors.New("settings storage is unavailable")
	}
	data, err := prefsMap(a.settings.Prefs)
	if err != nil {
		return errors.New("WebDAV settings unavailable")
	}
	for _, key := range webDAVPlainKeys {
		removePref(data, key)
	}
	removePref(data, webDAVProtectedKey)
	encoded, err := json.Marshal(data)
	if err != nil {
		return errors.New("could not encode WebDAV settings")
	}
	next := a.settings
	next.Prefs = string(encoded)
	if err := a.store.Save(next); err != nil {
		return errors.New("could not save WebDAV settings")
	}
	a.settings, a.webDAVProtected, a.webDAVProtectionErr = next, "", nil
	if a.model != nil {
		a.model.Prefs.WebDAVURL, a.model.Prefs.WebDAVUser, a.model.Prefs.WebDAVPassword = "", "", ""
		a.model.WebDAVSecretStored = false
	}
	return nil
}
