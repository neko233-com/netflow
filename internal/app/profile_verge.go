package app

import (
	"errors"

	"github.com/neko233-com/netflow/internal/migration"
	"github.com/neko233-com/netflow/internal/profile"
)

func (a *App) applyProfileVergeExtensions(body []byte, id string) ([]byte, error) {
	result, _, _, err := a.applyProfileVergeExtensionsSnapshot(body, id)
	return result, err
}

func (a *App) applyProfileVergeExtensionsSnapshot(body []byte, id string) ([]byte, string, [32]byte, error) {
	var empty [32]byte
	if id == "" || a.profiles == nil {
		return body, "", empty, nil
	}
	catalog, err := a.profiles.Load()
	if err != nil {
		return nil, "", empty, err
	}
	return a.composeVergeExtensionsFromCatalog(body, id, catalog)
}

func (a *App) composeVergeExtensionsFromCatalog(body []byte, id string, catalog profile.File) ([]byte, string, [32]byte, error) {
	var empty [32]byte
	if id == "" {
		return body, "", empty, nil
	}
	for _, item := range catalog.Items {
		if item.UID != id {
			continue
		}
		if !item.Option.VergeExtensions {
			return body, "", empty, nil
		}
		return migration.ComposeArchived(a.dir, item.Option.VergeArchive, item.Option.VergeUID, body)
	}
	return nil, "", empty, errors.New("Verge 扩展对应的订阅不存在")
}
