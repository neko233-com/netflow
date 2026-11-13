// Package appdir locates the directory that holds profiles and settings.
package appdir

import (
	"errors"
	"os"
	"path/filepath"
	"runtime"
)

// SupportDirName is the directory under Application Support on macOS,
// and the bundle identifier of the app.
const SupportDirName = "netflow"

// Provider returns the directory the app may create and write.
type Provider interface {
	ConfigDir() (string, error)
}

// Default uses the current user's platform directory.
type Default struct{}

// ConfigDir returns ~/Library/Application Support/app.clashgo.desktop
// on macOS.
func (Default) ConfigDir() (string, error) {
	if override := os.Getenv("NETFLOW_CONFIG_DIR"); override != "" {
		if !filepath.IsAbs(override) {
			return "", errors.New("NETFLOW_CONFIG_DIR must be an absolute path")
		}
		return filepath.Clean(override), nil
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	switch runtime.GOOS {
	case "darwin":
		return Path(home, "darwin"), nil
	case "windows":
		if appdata := os.Getenv("AppData"); appdata != "" {
			return filepath.Join(appdata, SupportDirName), nil
		}
		return Path(home, "windows"), nil
	default:
		if xdg := os.Getenv("XDG_CONFIG_HOME"); xdg != "" {
			return filepath.Join(xdg, SupportDirName), nil
		}
		return Path(home, runtime.GOOS), nil
	}
}

// Path joins home and the platform config directory. goos is a runtime.GOOS
// value; anything other than darwin or windows uses the XDG layout.
func Path(home, goos string) string {
	switch goos {
	case "darwin":
		return filepath.Join(home, "Library", "Application Support", SupportDirName)
	case "windows":
		return filepath.Join(home, "AppData", "Roaming", SupportDirName)
	default:
		return filepath.Join(home, ".config", SupportDirName)
	}
}

// Fixed is a Provider that always returns Dir.
type Fixed string

// ConfigDir returns the fixed directory.
func (f Fixed) ConfigDir() (string, error) {
	if f == "" {
		return "", errors.New("config dir is empty")
	}
	return string(f), nil
}
