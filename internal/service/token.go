package service

import (
	"os"
	"path/filepath"
)

func userTokenPath() string {
	home, err := os.UserConfigDir()
	if err != nil {
		return filepath.Join(os.TempDir(), "clash-go-service.token")
	}
	dir := filepath.Join(home, "app.clashgo.desktop")
	_ = os.MkdirAll(dir, 0o755)
	return filepath.Join(dir, "service.token")
}
