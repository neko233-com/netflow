// Package geoupdate downloads geo databases into a pending transaction. The
// files are installed on the next application start, before the kernel maps
// them. This keeps elevated TUN workers from owning the only updated copy.
package geoupdate

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/metacubex/mihomo/component/geodata"
	_ "github.com/metacubex/mihomo/component/geodata/standard"
	"github.com/oschwald/maxminddb-golang"
	"go.yaml.in/yaml/v3"
)

const (
	PrivatePrefix = ".netflow-geodata-"
	// PendingDirectory is private desktop state, not input to the TUN worker.
	PendingDirectory = PrivatePrefix + "pending"
	TemporaryPrefix  = PrivatePrefix + "tmp-"
	maxDatabaseBytes = 64 << 20
	maxTotalBytes    = 120 << 20
)

type urls struct {
	GeoIP   string `yaml:"geoip"`
	MMDB    string `yaml:"mmdb"`
	ASN     string `yaml:"asn"`
	GeoSite string `yaml:"geosite"`
}

type config struct {
	Geo urls `yaml:"geox-url"`
}

type item struct {
	Name    string `json:"name"`
	Kind    string `json:"kind"`
	Before  string `json:"before"`
	After   string `json:"after"`
	Payload string `json:"payload"`
}

type manifest struct {
	Version int    `json:"version"`
	Items   []item `json:"items"`
}

func defaultConfig() config {
	const base = "https://github.com/MetaCubeX/meta-rules-dat/releases/download/latest/"
	return config{Geo: urls{GeoIP: base + "geoip.dat", MMDB: base + "geoip.metadb", ASN: base + "GeoLite2-ASN.mmdb", GeoSite: base + "geosite.dat"}}
}

func digest(b []byte) string { sum := sha256.Sum256(b); return hex.EncodeToString(sum[:]) }

// Prepare downloads replacements for existing databases using the running
// kernel's local mixed proxy; it never falls back to an unproxied request.
// The caller must hold the application configuration-directory lock.
func Prepare(ctx context.Context, dir string, effective []byte, mixedPort int) (int, error) {
	if mixedPort < 1 || mixedPort > 65535 {
		return 0, errors.New("更新 GeoData 需要可用的混合代理端口")
	}
	proxy := &url.URL{Scheme: "http", Host: net.JoinHostPort("127.0.0.1", fmt.Sprint(mixedPort))}
	transport := &http.Transport{Proxy: http.ProxyURL(proxy)}
	defer transport.CloseIdleConnections()
	return prepare(ctx, dir, effective, transport)
}

func prepare(ctx context.Context, dir string, effective []byte, transport http.RoundTripper) (int, error) {
	if !filepath.IsAbs(dir) {
		return 0, errors.New("配置目录必须是绝对路径")
	}
	cfg := defaultConfig()
	if err := yaml.Unmarshal(effective, &cfg); err != nil {
		return 0, fmt.Errorf("读取 GeoData 地址: %w", err)
	}
	root, err := os.OpenRoot(dir)
	if err != nil {
		return 0, err
	}
	defer root.Close()
	if _, err := root.Lstat(PendingDirectory); err == nil {
		return 0, errors.New("已有待应用的 GeoData 更新，请先重启 NetFlow")
	} else if !errors.Is(err, os.ErrNotExist) {
		return 0, err
	}
	rootDir, err := root.Open(".")
	if err != nil {
		return 0, err
	}
	entries, readErr := rootDir.ReadDir(-1)
	closeErr := rootDir.Close()
	if readErr != nil {
		return 0, readErr
	}
	if closeErr != nil {
		return 0, closeErr
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].Name() < entries[j].Name() })
	var targets []item
	seenMMDB := false
	for _, entry := range entries {
		name := entry.Name()
		var kind string
		switch strings.ToLower(name) {
		case "geosite.dat":
			kind = "geosite"
		case "geoip.dat":
			kind = "geoip"
		case "asn.mmdb":
			kind = "asn"
		case "country.mmdb", "geoip.db", "geoip.metadb":
			if !seenMMDB {
				kind = "mmdb"
				seenMMDB = true
			}
		}
		if kind == "" {
			continue
		}
		info, err := root.Lstat(name)
		if err != nil {
			return 0, err
		}
		if !info.Mode().IsRegular() {
			return 0, fmt.Errorf("GeoData 文件 %s 不是普通文件", name)
		}
		before, err := readBounded(root, name)
		if err != nil {
			return 0, fmt.Errorf("读取 GeoData 文件 %s: %w", name, err)
		}
		targets = append(targets, item{Name: name, Kind: kind, Before: digest(before), Payload: fmt.Sprintf("item-%d", len(targets))})
	}
	if len(targets) == 0 {
		return 0, errors.New("配置目录中没有可更新的 GeoData 文件")
	}
	tmp, err := temporaryName()
	if err != nil {
		return 0, err
	}
	if err := root.Mkdir(tmp, 0700); err != nil {
		return 0, err
	}
	// Only remove files created by this operation; unexpected files are left.
	defer func() {
		for _, target := range targets {
			_ = root.Remove(filepath.Join(tmp, target.Payload))
		}
		_ = root.Remove(filepath.Join(tmp, "manifest.json"))
		_ = root.Remove(tmp)
	}()
	staging, err := root.OpenRoot(tmp)
	if err != nil {
		return 0, err
	}
	defer staging.Close()
	client := &http.Client{Transport: transport, Timeout: 90 * time.Second, CheckRedirect: func(req *http.Request, via []*http.Request) error {
		if len(via) >= 10 || req.URL.Scheme != "https" || req.URL.Host == "" || req.URL.User != nil {
			return errors.New("GeoData 重定向必须使用 HTTPS")
		}
		return nil
	}}
	var total int
	for i := range targets {
		var address string
		switch targets[i].Kind {
		case "geoip":
			address = cfg.Geo.GeoIP
		case "mmdb":
			address = cfg.Geo.MMDB
		case "asn":
			address = cfg.Geo.ASN
		case "geosite":
			address = cfg.Geo.GeoSite
		}
		u, err := url.Parse(address)
		if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil {
			return 0, fmt.Errorf("%s 更新地址必须是无凭据的 HTTPS URL", targets[i].Name)
		}
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
		if err != nil {
			return 0, fmt.Errorf("创建 %s 下载请求失败", targets[i].Name)
		}
		resp, err := client.Do(req)
		if err != nil {
			return 0, fmt.Errorf("下载 %s 失败，请检查代理和网络", targets[i].Name)
		}
		if resp.StatusCode != http.StatusOK {
			resp.Body.Close()
			return 0, fmt.Errorf("下载 %s 失败: HTTP %d", targets[i].Name, resp.StatusCode)
		}
		data, readErr := io.ReadAll(io.LimitReader(resp.Body, maxDatabaseBytes+1))
		closeErr := resp.Body.Close()
		if readErr != nil || closeErr != nil || len(data) == 0 || len(data) > maxDatabaseBytes {
			return 0, fmt.Errorf("下载 %s 内容无效或超过大小限制", targets[i].Name)
		}
		total += len(data)
		if total > maxTotalBytes {
			return 0, errors.New("GeoData 更新超过大小限制")
		}
		if err := validate(targets[i].Kind, data); err != nil {
			return 0, fmt.Errorf("下载的 %s 无效: %w", targets[i].Name, err)
		}
		targets[i].After = digest(data)
		if err := writeNew(staging, targets[i].Payload, data); err != nil {
			return 0, err
		}
	}
	data, err := json.Marshal(manifest{Version: 1, Items: targets})
	if err != nil {
		return 0, err
	}
	if err := writeNew(staging, "manifest.json", data); err != nil {
		return 0, err
	}
	if err := staging.Close(); err != nil {
		return 0, err
	}
	if err := root.Rename(tmp, PendingDirectory); err != nil {
		return 0, fmt.Errorf("保存 GeoData 更新失败: %w", err)
	}
	return len(targets), nil
}

func validate(kind string, data []byte) error {
	switch kind {
	case "mmdb", "asn":
		reader, err := maxminddb.FromBytes(data)
		if err != nil {
			return err
		}
		return reader.Close()
	case "geoip", "geosite":
		loader, err := geodata.GetGeoDataLoader("standard")
		if err != nil {
			return err
		}
		if kind == "geoip" {
			_, err = loader.LoadIPByBytes(data, "cn")
		} else {
			_, err = loader.LoadSiteByBytes(data, "cn")
		}
		return err
	default:
		return errors.New("未知 GeoData 类型")
	}
}

func readBounded(root *os.Root, name string) ([]byte, error) {
	f, err := root.Open(name)
	if err != nil {
		return nil, err
	}
	data, readErr := io.ReadAll(io.LimitReader(f, maxDatabaseBytes+1))
	closeErr := f.Close()
	if readErr != nil {
		return nil, readErr
	}
	if closeErr != nil {
		return nil, closeErr
	}
	if len(data) > maxDatabaseBytes {
		return nil, errors.New("文件超过大小限制")
	}
	return data, nil
}

func writeNew(root *os.Root, name string, data []byte) error {
	f, err := root.OpenFile(name, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return err
	}
	_, err = f.Write(data)
	if err == nil {
		err = f.Sync()
	}
	closeErr := f.Close()
	if err != nil {
		return err
	}
	return closeErr
}
