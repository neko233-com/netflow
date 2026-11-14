package geoupdate

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

const CompletedPrefix = PrivatePrefix + "complete-"
const RejectedPrefix = PrivatePrefix + "rejected-"

// QuarantinePending preserves a failed transaction for inspection and allows a
// new update. It never removes or follows the pending directory.
func QuarantinePending(dir string) (string, error) {
	root, err := os.OpenRoot(dir)
	if err != nil {
		return "", err
	}
	defer root.Close()
	info, err := root.Lstat(PendingDirectory)
	if err != nil {
		return "", err
	}
	if !info.IsDir() {
		return "", errors.New("待应用 GeoData 目录无效")
	}
	name, err := temporaryName()
	if err != nil {
		return "", err
	}
	name = RejectedPrefix + strings.TrimPrefix(name, TemporaryPrefix)
	if err := root.Rename(PendingDirectory, name); err != nil {
		return "", err
	}
	return name, nil
}

// ApplyPending is called after acquiring the single-instance lock and before
// opening any database. Interrupted installations are idempotently resumed.
// A local change to an original file aborts rather than overwriting it.
func ApplyPending(dir string) (int, error) {
	if !filepath.IsAbs(dir) {
		return 0, errors.New("配置目录必须是绝对路径")
	}
	root, err := os.OpenRoot(dir)
	if err != nil {
		return 0, err
	}
	defer root.Close()
	info, err := root.Lstat(PendingDirectory)
	if errors.Is(err, os.ErrNotExist) {
		return 0, nil
	}
	if err != nil {
		return 0, err
	}
	if !info.IsDir() {
		return 0, errors.New("待应用 GeoData 目录无效")
	}
	pending, err := root.OpenRoot(PendingDirectory)
	if err != nil {
		return 0, err
	}
	defer pending.Close()
	info, err = pending.Lstat("manifest.json")
	if err != nil || !info.Mode().IsRegular() {
		return 0, errors.New("待应用 GeoData 清单不可用")
	}
	f, err := pending.Open("manifest.json")
	if err != nil {
		return 0, err
	}
	data, readErr := io.ReadAll(io.LimitReader(f, 8193))
	closeErr := f.Close()
	if readErr != nil || closeErr != nil || len(data) > 8192 {
		return 0, errors.New("待应用 GeoData 清单无效")
	}
	var m manifest
	if err := json.Unmarshal(data, &m); err != nil || m.Version != 1 || len(m.Items) == 0 || len(m.Items) > 4 {
		return 0, errors.New("待应用 GeoData 清单无效")
	}
	seen := make(map[string]bool)
	var total int
	for i, target := range m.Items {
		key := strings.ToLower(target.Name)
		if !validTarget(target) || seen[key] || target.Payload != fmt.Sprintf("item-%d", i) {
			return 0, errors.New("待应用 GeoData 项目无效")
		}
		seen[key] = true
		info, err := pending.Lstat(target.Payload)
		if err != nil || !info.Mode().IsRegular() {
			return 0, errors.New("待应用 GeoData 内容不可用")
		}
		payload, err := readBounded(pending, target.Payload)
		if err != nil || digest(payload) != target.After {
			return 0, errors.New("待应用 GeoData 内容已改变")
		}
		total += len(payload)
		if total > maxTotalBytes {
			return 0, errors.New("待应用 GeoData 超过大小限制")
		}
		if err := validate(target.Kind, payload); err != nil {
			return 0, fmt.Errorf("待应用的 %s 无效", target.Name)
		}
		info, err = root.Lstat(target.Name)
		if err != nil || !info.Mode().IsRegular() {
			return 0, fmt.Errorf("原 GeoData 文件 %s 不可用", target.Name)
		}
		current, err := readBounded(root, target.Name)
		if err != nil || (digest(current) != target.Before && digest(current) != target.After) {
			return 0, fmt.Errorf("原 GeoData 文件 %s 已更改；保留原文件", target.Name)
		}
	}
	for _, target := range m.Items {
		current, err := readBounded(root, target.Name)
		if err != nil {
			return 0, err
		}
		if digest(current) == target.After {
			continue
		}
		if digest(current) != target.Before {
			return 0, fmt.Errorf("原 GeoData 文件 %s 已更改；保留原文件", target.Name)
		}
		payload, err := readBounded(pending, target.Payload)
		if err != nil || digest(payload) != target.After {
			return 0, errors.New("待应用 GeoData 内容已改变")
		}
		name, err := temporaryName()
		if err != nil {
			return 0, err
		}
		file, err := root.OpenFile(name, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
		if err != nil {
			return 0, err
		}
		_, err = file.Write(payload)
		if err == nil {
			err = file.Sync()
		}
		if closeErr := file.Close(); err == nil {
			err = closeErr
		}
		if err == nil {
			err = root.Rename(name, target.Name)
		}
		if err != nil {
			_ = root.Remove(name)
			return 0, fmt.Errorf("应用 %s 失败: %w", target.Name, err)
		}
	}
	completed, err := temporaryName()
	if err != nil {
		return 0, err
	}
	completed = CompletedPrefix + strings.TrimPrefix(completed, TemporaryPrefix)
	if err := pending.Close(); err != nil {
		return 0, err
	}
	if err := root.Rename(PendingDirectory, completed); err != nil {
		return 0, fmt.Errorf("完成 GeoData 更新失败: %w", err)
	}
	for _, target := range m.Items {
		_ = root.Remove(filepath.Join(completed, target.Payload))
	}
	_ = root.Remove(filepath.Join(completed, "manifest.json"))
	_ = root.Remove(completed)
	return len(m.Items), nil
}

func validTarget(target item) bool {
	if !filepath.IsLocal(target.Name) || filepath.Base(target.Name) != target.Name {
		return false
	}
	if len(target.Before) != 64 || len(target.After) != 64 {
		return false
	}
	if _, err := hex.DecodeString(target.Before); err != nil {
		return false
	}
	if _, err := hex.DecodeString(target.After); err != nil {
		return false
	}
	switch strings.ToLower(target.Name) {
	case "geoip.dat":
		return target.Kind == "geoip"
	case "geosite.dat":
		return target.Kind == "geosite"
	case "asn.mmdb":
		return target.Kind == "asn"
	case "country.mmdb", "geoip.db", "geoip.metadb":
		return target.Kind == "mmdb"
	default:
		return false
	}
}

func temporaryName() (string, error) {
	var id [16]byte
	if _, err := rand.Read(id[:]); err != nil {
		return "", err
	}
	return TemporaryPrefix + hex.EncodeToString(id[:]), nil
}
