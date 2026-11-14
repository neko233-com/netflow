package app

import (
	"context"
	"errors"

	"github.com/neko233-com/netflow/internal/migration"
	"github.com/neko233-com/netflow/internal/profile"
	"github.com/neko233-com/netflow/internal/scriptapproval"
)

func (a *App) applyProfileVergeExtensions(body []byte, id string) ([]byte, error) {
	result, _, err := a.applyProfileVergeExtensionsSnapshot(body, id)
	return result, err
}

func (a *App) applyProfileVergeExtensionsSnapshot(body []byte, id string) ([]byte, map[string][32]byte, error) {
	if id == "" || a.profiles == nil {
		return body, nil, nil
	}
	catalog, err := a.profiles.Load()
	if err != nil {
		return nil, nil, err
	}
	return a.composeVergeExtensionsFromCatalog(body, id, catalog)
}

func (a *App) composeVergeExtensionsFromCatalog(body []byte, id string, catalog profile.File) ([]byte, map[string][32]byte, error) {
	if id == "" {
		return body, nil, nil
	}
	for _, item := range catalog.Items {
		if item.UID != id {
			continue
		}
		var sources map[string][32]byte
		var err error
		if item.Option.VergeScriptApproval != nil {
			resolved, err := scriptapproval.ResolveSnapshot(context.Background(), a.dir, *item.Option.VergeScriptApproval, body, item.Name, item.Option.VergeArchive, item.Option.VergeUID)
			if err != nil {
				if errors.Is(err, scriptapproval.ErrChanged) {
					return nil, nil, errors.New("已批准的脚本输入或结果已变化；请预览并关闭脚本，更新订阅后重新预览启用")
				}
				return nil, nil, err
			}
			sources = resolved.Sources
			body, err = profile.RestoreVergeManagedFields(context.Background(), resolved.Body, resolved.Managed)
			if err != nil {
				return nil, nil, err
			}
		} else if item.Option.VergeExtensions {
			var archivePath string
			var archiveHash [32]byte
			body, archivePath, archiveHash, err = migration.ComposeArchived(a.dir, item.Option.VergeArchive, item.Option.VergeUID, body)
			if err != nil {
				return nil, nil, err
			}
			sources = map[string][32]byte{archivePath: archiveHash}
		}
		body, err = profile.RemapVergeProviders(body, item.Option.VergeProviderPaths)
		return body, sources, err
	}
	return nil, nil, errors.New("Verge 扩展对应的订阅不存在")
}
