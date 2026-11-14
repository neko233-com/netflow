package app

import (
	"errors"
	"io"
	"os"
	"path/filepath"
)

func openProfileHandle(dir, relative string) (*os.File, string, error) {
	if !filepath.IsAbs(dir) || !filepath.IsLocal(relative) {
		return nil, "", errors.New("订阅文件路径无效")
	}
	rel, err := filepath.Rel("profiles", relative)
	if err != nil || !filepath.IsLocal(rel) || rel == "." {
		return nil, "", errors.New("订阅文件路径无效")
	}
	root, err := os.OpenRoot(dir)
	if err != nil {
		return nil, "", err
	}
	defer root.Close()
	info, err := root.Lstat("profiles")
	if err != nil {
		return nil, "", err
	}
	if !info.IsDir() {
		return nil, "", errors.New("订阅目录不能是链接或重解析点")
	}
	profiles, err := root.OpenRoot("profiles")
	if err != nil {
		return nil, "", err
	}
	defer profiles.Close()
	f, err := profiles.Open(rel)
	if err != nil {
		return nil, "", err
	}
	info, err = f.Stat()
	if err != nil || !info.Mode().IsRegular() {
		_ = f.Close()
		return nil, "", errors.New("订阅文件不是普通文件")
	}
	return f, filepath.Join(dir, relative), nil
}

func profileFilePath(dir, relative string) (string, error) {
	f, path, err := openProfileHandle(dir, relative)
	if err != nil {
		return "", err
	}
	if err := f.Close(); err != nil {
		return "", err
	}
	return path, nil
}

func readProfileFile(dir, relative string) ([]byte, string, error) {
	f, path, err := openProfileHandle(dir, relative)
	if err != nil {
		return nil, "", err
	}
	defer f.Close()
	data, err := io.ReadAll(io.LimitReader(f, (128<<20)+1))
	if err != nil {
		return nil, "", err
	}
	if len(data) > 128<<20 {
		return nil, "", errors.New("订阅文件过大")
	}
	return data, path, nil
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
