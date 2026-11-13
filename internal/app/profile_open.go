package app

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
)

func profileFilePath(dir, relative string) (string, error) {
	root, err := filepath.EvalSymlinks(filepath.Join(dir, "profiles"))
	if err != nil {
		return "", err
	}
	candidate, err := filepath.EvalSymlinks(filepath.Join(dir, relative))
	if err != nil {
		return "", err
	}
	rel, err := filepath.Rel(root, candidate)
	if err != nil || rel == "." || rel == ".." || filepath.IsAbs(rel) || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return "", errors.New("订阅文件路径无效")
	}
	info, err := os.Stat(candidate)
	if err != nil {
		return "", err
	}
	if !info.Mode().IsRegular() {
		return "", errors.New("订阅文件不是普通文件")
	}
	return candidate, nil
}

func (a *App) openProfileFile(id string) error {
	if a == nil || a.profiles == nil {
		return errors.New("订阅存储不可用")
	}
	catalog, err := a.profiles.Load()
	if err != nil {
		return err
	}
	for _, item := range catalog.Items {
		if item.UID == id {
			path, err := profileFilePath(a.dir, item.File)
			if err != nil {
				return err
			}
			return openPath(path)
		}
	}
	return errors.New("订阅不存在")
}
