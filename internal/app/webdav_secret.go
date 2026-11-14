package app

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"

	"github.com/neko233-com/netflow/internal/appconfig"
	"github.com/neko233-com/netflow/internal/secretstore"
	"github.com/neko233-com/netflow/internal/ui"
)

const webDAVProtectedKey = "WebDAVConfigProtected"

var webDAVPlainKeys = []string{"WebDAVURL", "WebDAVUser", "WebDAVPassword"}

type webDAVCredentials struct {
	URL      string `json:"url,omitempty"`
	User     string `json:"user,omitempty"`
	Password string `json:"password,omitempty"`
}

func (c webDAVCredentials) empty() bool { return c.URL == "" && c.User == "" && c.Password == "" }

func prefsMap(raw string) (map[string]json.RawMessage, error) {
	if raw == "" {
		return make(map[string]json.RawMessage), nil
	}
	decoder := json.NewDecoder(strings.NewReader(raw))
	start, err := decoder.Token()
	if err != nil || start != json.Delim('{') {
		return nil, errors.New("stored preferences are invalid")
	}
	data := make(map[string]json.RawMessage)
	for decoder.More() {
		token, err := decoder.Token()
		key, ok := token.(string)
		if err != nil || !ok {
			return nil, errors.New("stored preferences are invalid")
		}
		if _, exists := data[key]; exists {
			return nil, errors.New("stored preferences contain duplicate keys")
		}
		var value json.RawMessage
		if err := decoder.Decode(&value); err != nil {
			return nil, errors.New("stored preferences are invalid")
		}
		data[key] = value
	}
	if end, err := decoder.Token(); err != nil || end != json.Delim('}') {
		return nil, errors.New("stored preferences are invalid")
	}
	var extra json.RawMessage
	if err := decoder.Decode(&extra); err != io.EOF {
		return nil, errors.New("stored preferences are invalid")
	}
	return data, nil
}

func prefString(data map[string]json.RawMessage, name string) (string, error) {
	var value string
	matched := false
	for key, raw := range data {
		if !strings.EqualFold(key, name) {
			continue
		}
		if matched {
			return "", errors.New("duplicate WebDAV preference")
		}
		matched = true
		if err := json.Unmarshal(raw, &value); err != nil {
			return "", errors.New("WebDAV preference has invalid type")
		}
	}
	return value, nil
}

func removePref(data map[string]json.RawMessage, name string) {
	for key := range data {
		if strings.EqualFold(key, name) {
			delete(data, key)
		}
	}
}

func plainWebDAV(data map[string]json.RawMessage) (webDAVCredentials, error) {
	var result webDAVCredentials
	var err error
	if result.URL, err = prefString(data, webDAVPlainKeys[0]); err != nil {
		return result, err
	}
	if result.User, err = prefString(data, webDAVPlainKeys[1]); err != nil {
		return result, err
	}
	if result.Password, err = prefString(data, webDAVPlainKeys[2]); err != nil {
		return result, err
	}
	return result, nil
}

func protectWebDAV(value webDAVCredentials) (string, error) {
	data, err := json.Marshal(value)
	if err != nil {
		return "", err
	}
	return secretstore.Protect(string(data))
}

func unprotectWebDAV(value string) (webDAVCredentials, error) {
	var result webDAVCredentials
	plain, err := secretstore.Unprotect(value)
	if err != nil {
		return result, err
	}
	if err := json.Unmarshal([]byte(plain), &result); err != nil {
		return result, errors.New("protected WebDAV configuration is invalid")
	}
	return result, nil
}

// migrateWebDAVSecret preserves all other fields and commits only after the
// entire URL, username and password have been protected for the current user.
func (a *App) migrateWebDAVSecret(settings appconfig.Settings) (appconfig.Settings, string, error) {
	data, err := prefsMap(settings.Prefs)
	if err != nil {
		return settings, "", err
	}
	plain, err := plainWebDAV(data)
	if err != nil {
		return settings, "", err
	}
	protected, err := prefString(data, webDAVProtectedKey)
	if err != nil {
		return settings, "", err
	}
	if plain.empty() {
		return settings, protected, nil
	}
	if protected != "" {
		return settings, protected, errors.New("both legacy and protected WebDAV configurations exist")
	}
	if !secretstore.Available() {
		return settings, "", secretstore.ErrUnsupported
	}
	protected, err = protectWebDAV(plain)
	if err != nil {
		return settings, "", err
	}
	for _, key := range webDAVPlainKeys {
		removePref(data, key)
	}
	data[webDAVProtectedKey], err = json.Marshal(protected)
	if err != nil {
		return settings, "", err
	}
	encoded, err := json.Marshal(data)
	if err != nil {
		return settings, "", err
	}
	next := settings
	next.Prefs = string(encoded)
	if a.store != nil {
		if err := a.store.Save(next); err != nil {
			return settings, "", err
		}
	}
	return next, protected, nil
}

func (a *App) encodePrefs(p ui.Prefs) (string, string, error) {
	if a.webDAVProtectionErr != nil {
		return "", "", fmt.Errorf("preserve WebDAV configuration: %w", a.webDAVProtectionErr)
	}
	data, err := prefsMap(a.settings.Prefs)
	if err != nil {
		return "", "", err
	}
	protected := a.webDAVProtected
	plain := webDAVCredentials{URL: p.WebDAVURL, User: p.WebDAVUser, Password: p.WebDAVPassword}
	if !plain.empty() && protected != "" {
		return "", "", errors.New("both legacy and protected WebDAV configurations exist")
	}
	if !plain.empty() && secretstore.Available() {
		protected, err = protectWebDAV(plain)
		if err != nil {
			return "", "", fmt.Errorf("protect WebDAV configuration: %w", err)
		}
		p.WebDAVURL, p.WebDAVUser, p.WebDAVPassword = "", "", ""
	}
	encoded, err := json.Marshal(p)
	if err != nil {
		return "", "", err
	}
	var updates map[string]json.RawMessage
	if err := json.Unmarshal(encoded, &updates); err != nil {
		return "", "", err
	}
	for key, value := range updates {
		removePref(data, key)
		data[key] = value
	}
	removePref(data, webDAVProtectedKey)
	if protected != "" {
		for _, key := range webDAVPlainKeys {
			removePref(data, key)
		}
		data[webDAVProtectedKey], err = json.Marshal(protected)
		if err != nil {
			return "", "", err
		}
	}
	encoded, err = json.Marshal(data)
	return string(encoded), protected, err
}

func (a *App) savedWebDAV() (webDAVCredentials, error) {
	data, err := prefsMap(a.settings.Prefs)
	if err != nil {
		return webDAVCredentials{}, err
	}
	plain, err := plainWebDAV(data)
	if err != nil {
		return webDAVCredentials{}, err
	}
	protected, err := prefString(data, webDAVProtectedKey)
	if err != nil {
		return webDAVCredentials{}, err
	}
	if !plain.empty() && protected != "" {
		return webDAVCredentials{}, errors.New("both legacy and protected WebDAV configurations exist")
	}
	if protected != "" {
		return unprotectWebDAV(protected)
	}
	return plain, nil
}

// clearWebDAVSecret removes only the separately stored password. URL and user
// remain intact; any credentials embedded in the URL are not altered.
func (a *App) clearWebDAVSecret() error {
	if a.backupBusy {
		return errors.New("wait for the active backup task to finish")
	}
	data, err := prefsMap(a.settings.Prefs)
	if err != nil {
		return err
	}
	protected, err := prefString(data, webDAVProtectedKey)
	if err != nil {
		return err
	}
	var value webDAVCredentials
	if protected != "" {
		value, err = a.savedWebDAV()
		if err != nil {
			return err
		}
		if value.Password == "" {
			return errors.New("no separately stored WebDAV password")
		}
		value.Password = ""
		removePref(data, webDAVProtectedKey)
		protected = ""
		if !value.empty() {
			protected, err = protectWebDAV(value)
			if err != nil {
				return err
			}
			data[webDAVProtectedKey], err = json.Marshal(protected)
			if err != nil {
				return err
			}
		}
	} else {
		// Explicitly clearing the password can safely remove duplicate legacy
		// password keys while leaving all other fields untouched.
		found := false
		for key := range data {
			if strings.EqualFold(key, webDAVPlainKeys[2]) {
				found = true
				break
			}
		}
		if !found {
			return errors.New("no separately stored WebDAV password")
		}
		removePref(data, webDAVPlainKeys[2])
		value, err = plainWebDAV(data)
		if err != nil {
			return err
		}
	}
	encoded, err := json.Marshal(data)
	if err != nil {
		return err
	}
	next := a.settings
	next.Prefs = string(encoded)
	if a.store != nil {
		if err := a.store.Save(next); err != nil {
			return err
		}
	}
	a.settings, a.webDAVProtected, a.webDAVProtectionErr = next, protected, nil
	if a.model != nil {
		a.model.Prefs.WebDAVPassword = ""
		a.model.WebDAVSecretStored = !value.empty()
	}
	return nil
}

// Copy is only invoked after an explicit user action; fields never appear in
// agent responses or UI labels. URL and username may themselves contain secrets.
func (a *App) copyWebDAVField(field string) error {
	value, err := a.savedWebDAV()
	if err != nil {
		return err
	}
	var text string
	switch field {
	case "url":
		text = value.URL
	case "user":
		text = value.User
	case "password":
		text = value.Password
	default:
		return errors.New("unknown WebDAV field")
	}
	if text == "" {
		return errors.New("the selected WebDAV field is empty")
	}
	return writeClipboard(text)
}
