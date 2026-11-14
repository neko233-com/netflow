//go:build windows

package sysproxy

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"syscall"

	"github.com/neko233-com/netflow/internal/appdir"
	"github.com/neko233-com/netflow/internal/safepath"
	"golang.org/x/sys/windows/registry"
)

const internetSettings = `Software\Microsoft\Windows\CurrentVersion\Internet Settings`

type proxyValue struct {
	Exists bool   `json:"exists"`
	Type   uint32 `json:"type"`
	Number uint64 `json:"number,omitempty"`
	Text   string `json:"text,omitempty"`
}

type proxyBackup struct {
	Values map[string]proxyValue `json:"values"`
	Owned  string                `json:"owned"`
}

type windowsSystem struct {
	mu         sync.Mutex
	keyPath    string
	backupFile string
	notify     func()
}

func platformOther() Controller {
	return &windowsSystem{keyPath: internetSettings, notify: notifyProxyChange}
}

func backupPath() (string, error) {
	dir, err := (appdir.Default{}).ConfigDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, "system-proxy-backup.json"), nil
}

func readProxyValue(k registry.Key, name string) (proxyValue, error) {
	_, typ, err := k.GetValue(name, nil)
	if errors.Is(err, registry.ErrNotExist) {
		return proxyValue{}, nil
	}
	if err != nil {
		return proxyValue{}, err
	}
	v := proxyValue{Exists: true, Type: typ}
	switch typ {
	case registry.DWORD, registry.QWORD:
		v.Number, _, err = k.GetIntegerValue(name)
	case registry.SZ, registry.EXPAND_SZ:
		v.Text, _, err = k.GetStringValue(name)
	default:
		err = fmt.Errorf("unsupported registry value type %d for %s", typ, name)
	}
	return v, err
}

func writeProxyValue(k registry.Key, name string, v proxyValue) error {
	if !v.Exists {
		err := k.DeleteValue(name)
		if errors.Is(err, registry.ErrNotExist) {
			return nil
		}
		return err
	}
	switch v.Type {
	case registry.DWORD:
		return k.SetDWordValue(name, uint32(v.Number))
	case registry.QWORD:
		return k.SetQWordValue(name, v.Number)
	case registry.SZ:
		return k.SetStringValue(name, v.Text)
	case registry.EXPAND_SZ:
		return k.SetExpandStringValue(name, v.Text)
	default:
		return fmt.Errorf("unsupported registry value type %d for %s", v.Type, name)
	}
}

var proxyKeys = []string{"ProxyEnable", "ProxyServer", "ProxyOverride", "AutoConfigURL"}

func notifyProxyChange() {
	p := syscall.NewLazyDLL("wininet.dll").NewProc("InternetSetOptionW")
	p.Call(0, 39, 0, 0) // INTERNET_OPTION_SETTINGS_CHANGED
	p.Call(0, 37, 0, 0) // INTERNET_OPTION_REFRESH
}

func (s *windowsSystem) Current() (Settings, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	k, err := registry.OpenKey(registry.CURRENT_USER, s.keyPath, registry.QUERY_VALUE)
	if err != nil {
		return Settings{}, err
	}
	defer k.Close()
	enabled, err := readProxyValue(k, "ProxyEnable")
	if err != nil {
		return Settings{}, err
	}
	server, err := readProxyValue(k, "ProxyServer")
	if err != nil {
		return Settings{}, err
	}
	return Settings{Enabled: enabled.Number != 0, HTTP: server.Text}, nil
}

// Owned reports only a proxy installed by NetFlow, not another client's.
func (s *windowsSystem) Owned() (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	path := s.backupFile
	if path == "" {
		var err error
		path, err = backupPath()
		if err != nil {
			return false, err
		}
	}
	data, err := safepath.ReadFile(filepath.Dir(path), filepath.Base(path))
	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	var backup proxyBackup
	if err := json.Unmarshal(data, &backup); err != nil || backup.Owned == "" {
		return false, errors.New("系统代理备份无效")
	}
	k, err := registry.OpenKey(registry.CURRENT_USER, s.keyPath, registry.QUERY_VALUE)
	if err != nil {
		return false, err
	}
	defer k.Close()
	enabled, err := readProxyValue(k, "ProxyEnable")
	if err != nil {
		return false, err
	}
	server, err := readProxyValue(k, "ProxyServer")
	if err != nil {
		return false, err
	}
	return enabled.Number != 0 && server.Text == backup.Owned, nil
}

func saveBackup(path string, b proxyBackup) error {
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return err
	}
	data, err := json.Marshal(b)
	if err != nil {
		return err
	}
	return safepath.WriteFile(filepath.Dir(path), filepath.Base(path), data)
}

func (s *windowsSystem) Set(next Settings) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	path := s.backupFile
	if path == "" {
		var err error
		path, err = backupPath()
		if err != nil {
			return err
		}
	}
	k, err := registry.OpenKey(registry.CURRENT_USER, s.keyPath, registry.QUERY_VALUE|registry.SET_VALUE)
	if err != nil {
		return err
	}
	defer k.Close()
	data, err := safepath.ReadFile(filepath.Dir(path), filepath.Base(path))
	var backup proxyBackup
	if err == nil {
		if err = json.Unmarshal(data, &backup); err != nil {
			return fmt.Errorf("读取代理备份: %w", err)
		}
		if len(backup.Values) != len(proxyKeys) || backup.Owned == "" {
			return errors.New("系统代理备份无效")
		}
		for _, name := range proxyKeys {
			if _, ok := backup.Values[name]; !ok {
				return errors.New("系统代理备份无效")
			}
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	if next.Enabled {
		if _, _, err = splitEndpoint(next.HTTP); err != nil {
			return err
		}
		if _, _, err = splitEndpoint(next.SOCKS); err != nil {
			return err
		}
		owned := "http=" + next.HTTP + ";https=" + next.HTTP + ";socks=" + next.SOCKS
		if backup.Values == nil {
			backup = proxyBackup{Values: make(map[string]proxyValue), Owned: owned}
			for _, name := range proxyKeys {
				backup.Values[name], err = readProxyValue(k, name)
				if err != nil {
					return err
				}
			}
			if err = saveBackup(path, backup); err != nil {
				return err
			}
		} else {
			if backup.Owned != owned {
				return errors.New("已有系统代理备份，请先关闭代理再更改端口")
			}
			current, e := readProxyValue(k, "ProxyServer")
			if e != nil {
				return e
			}
			if current.Text != backup.Owned {
				return errors.New("系统代理已被其他程序更改，未覆盖；备份仍保留")
			}
		}
		changes := map[string]proxyValue{
			"ProxyServer":   {Exists: true, Type: registry.SZ, Text: owned},
			"ProxyOverride": {Exists: true, Type: registry.SZ, Text: "<local>;localhost;127.*"},
			"AutoConfigURL": {},
			"ProxyEnable":   {Exists: true, Type: registry.DWORD, Number: 1},
		}
		for _, name := range []string{"ProxyServer", "ProxyOverride", "AutoConfigURL", "ProxyEnable"} {
			if err = writeProxyValue(k, name, changes[name]); err != nil {
				for _, key := range proxyKeys {
					_ = writeProxyValue(k, key, backup.Values[key])
				}
				s.notify()
				return err
			}
		}
		s.notify()
		return nil
	}
	if backup.Values == nil {
		return errors.New("没有 NetFlow 的系统代理备份，未更改现有代理")
	}
	current, err := readProxyValue(k, "ProxyServer")
	if err != nil {
		return err
	}
	if current.Text != backup.Owned {
		return errors.New("系统代理已被其他程序更改，未覆盖；备份仍保留")
	}
	enabled, err := readProxyValue(k, "ProxyEnable")
	if err != nil {
		return err
	}
	if enabled.Number != 1 {
		return errors.New("系统代理已被其他程序停用，未覆盖；备份仍保留")
	}
	previous := make(map[string]proxyValue)
	for _, name := range proxyKeys {
		previous[name], err = readProxyValue(k, name)
		if err != nil {
			return err
		}
	}
	for _, name := range proxyKeys {
		if err = writeProxyValue(k, name, backup.Values[name]); err != nil {
			for _, key := range proxyKeys {
				_ = writeProxyValue(k, key, previous[key])
			}
			s.notify()
			return err
		}
	}
	s.notify()
	return safepath.CompareAndRemove(filepath.Dir(path), filepath.Base(path), data)
}

// Restore returns the settings saved when this process enabled the proxy.
func (s *windowsSystem) Restore() error { return s.Set(Settings{}) }
