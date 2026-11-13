package app

import (
	"crypto/sha256"
	"errors"
	"io"
	"os"
	"path/filepath"

	"github.com/neko233-com/netflow/internal/migration"
	"github.com/neko233-com/netflow/internal/profile"
)

func (a *App) applyProfileVergeExtensions(body []byte, id string) ([]byte, error) {
	result, _, _, err := a.applyProfileVergeExtensionsSnapshot(body, id)
	return result, err
}

func (a *App) vergeProviderHashes(id string, catalog profile.File) (map[string][32]byte, error) {
	result := map[string][32]byte{}
	var paths map[string]string
	for _, item := range catalog.Items {
		if item.UID == id {
			paths = item.Option.VergeProviderPaths
			break
		}
	}
	if len(paths) == 0 {
		return result, nil
	}
	// The same validation is used for composition and hashing.
	if _, err := profile.RemapVergeProviders([]byte("{}"), paths); err != nil {
		return nil, err
	}
	root, err := os.OpenRoot(a.dir)
	if err != nil {
		return nil, err
	}
	defer root.Close()
	for _, rel := range paths {
		absolute := filepath.Join(a.dir, filepath.FromSlash(rel))
		f, err := root.Open(filepath.FromSlash(rel))
		if errors.Is(err, os.ErrNotExist) {
			result[absolute] = [32]byte{}
			continue
		}
		if err != nil {
			return nil, err
		}
		info, err := f.Stat()
		if err != nil || !info.Mode().IsRegular() || info.Size() > 8<<20 {
			_ = f.Close()
			return nil, errors.New("集合文件无效或过大")
		}
		h := sha256.New()
		n, err := io.Copy(h, io.LimitReader(f, (8<<20)+1))
		closeErr := f.Close()
		if err != nil {
			return nil, err
		}
		if n > 8<<20 {
			return nil, errors.New("集合文件无效或过大")
		}
		if closeErr != nil {
			return nil, closeErr
		}
		var sum [32]byte
		copy(sum[:], h.Sum(nil))
		result[absolute] = sum
	}
	return result, nil
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
		archivePath, archiveHash := "", empty
		var err error
		if item.Option.VergeExtensions {
			body, archivePath, archiveHash, err = migration.ComposeArchived(a.dir, item.Option.VergeArchive, item.Option.VergeUID, body)
			if err != nil {
				return nil, "", empty, err
			}
		}
		body, err = profile.RemapVergeProviders(body, item.Option.VergeProviderPaths)
		return body, archivePath, archiveHash, err
	}
	return nil, "", empty, errors.New("Verge 扩展对应的订阅不存在")
}
