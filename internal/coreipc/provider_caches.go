package coreipc

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/metacubex/mihomo/common/utils"
	P "github.com/metacubex/mihomo/constant/provider"
	"github.com/metacubex/mihomo/tunnel"
)

type providerSnapshot interface {
	VehicleType() P.VehicleType
	WithSnapshot(func(P.Vehicle, utils.HashType) error) error
}

type ProviderCacheQuery struct{ Known map[string]string }
type ProviderCache struct {
	Path, Version string
	Data          []byte
}
type ProviderCaches struct {
	Items   []ProviderCache
	Warning string
}

// ProviderCaches only exposes HTTP provider files belonging to the private
// stage. The callback holds the fetcher's lock, so a concurrent auto-update
// cannot yield a partially written file.
func (w *Worker) ProviderCaches(in ProviderCacheQuery, out *ProviderCaches) error {
	w.applyMu.Lock()
	if w.closed {
		w.applyMu.Unlock()
		return errors.New("kernel transport closed")
	}
	dir, providers, err := w.providerCacheSources()
	w.applyMu.Unlock()
	if err != nil {
		return err
	}
	return collectProviderCaches(dir, providers, in, out)
}

func (w *Worker) collectProviderCaches(in ProviderCacheQuery, out *ProviderCaches) error {
	dir, providers, err := w.providerCacheSources()
	if err != nil {
		return err
	}
	return collectProviderCaches(dir, providers, in, out)
}

// The caller holds applyMu while capturing the current provider references.
func (w *Worker) providerCacheSources() (string, []providerSnapshot, error) {
	if w.stage == nil {
		return "", nil, nil
	}
	var providers []providerSnapshot
	for _, p := range tunnel.Providers() {
		if p != nil && p.VehicleType() == P.HTTP {
			if snapshot, ok := p.(providerSnapshot); ok {
				providers = append(providers, snapshot)
			} else {
				return "", nil, errors.New("HTTP proxy provider cannot be safely snapshotted")
			}
		}
	}
	for _, p := range tunnel.RuleProviders() {
		if p != nil && p.VehicleType() == P.HTTP {
			if snapshot, ok := p.(providerSnapshot); ok {
				providers = append(providers, snapshot)
			} else {
				return "", nil, errors.New("HTTP rule provider cannot be safely snapshotted")
			}
		}
	}
	return w.stage.Directory(), providers, nil
}

func collectProviderCaches(dir string, providers []providerSnapshot, in ProviderCacheQuery, out *ProviderCaches) error {
	if dir == "" {
		return nil
	}
	root, err := os.OpenRoot(dir)
	if err != nil {
		return err
	}
	defer root.Close()
	seen := make(map[string]bool, len(providers))
	duplicate := make(map[string]bool)
	var warnings []error
	var total int64
	for _, provider := range providers {
		err := provider.WithSnapshot(func(vehicle P.Vehicle, hash utils.HashType) error {
			path := vehicle.Path()
			rel, err := filepath.Rel(dir, path)
			if err != nil || !validProviderCachePath(rel) {
				return errors.New("provider cache is outside an allowed directory")
			}
			key := strings.ToLower(filepath.Clean(rel))
			if seen[key] {
				duplicate[key] = true
				return errors.New("multiple providers share one cache path")
			}
			seen[key] = true
			version := hash.String()
			if in.Known[key] == version {
				return nil
			}
			info, err := root.Lstat(rel)
			if err != nil || !info.Mode().IsRegular() {
				return errors.New("provider cache is not a regular file")
			}
			file, err := root.Open(rel)
			if err != nil {
				return err
			}
			data, readErr := io.ReadAll(io.LimitReader(file, maxStageBytes-total+1))
			closeErr := file.Close()
			if readErr != nil {
				return readErr
			}
			if closeErr != nil {
				return closeErr
			}
			total += int64(len(data))
			if total > maxStageBytes {
				return errors.New("provider caches exceed size limit")
			}
			if !utils.MakeHash(data).Equal(hash) {
				return errors.New("provider cache changed while being read")
			}
			out.Items = append(out.Items, ProviderCache{Path: rel, Version: version, Data: data})
			return nil
		})
		if err != nil {
			warnings = append(warnings, fmt.Errorf("provider cache snapshot: %w", err))
		}
	}
	if len(duplicate) > 0 {
		kept := out.Items[:0]
		for _, item := range out.Items {
			if !duplicate[strings.ToLower(filepath.Clean(item.Path))] {
				kept = append(kept, item)
			}
		}
		out.Items = kept
	}
	if warning := errors.Join(warnings...); warning != nil {
		out.Warning = warning.Error()
	}
	return nil
}

// Configuration, app state, GeoData and recovery archives must never be
// replaced by a provider cache, even if a subscription references that path.
func validProviderCachePath(path string) bool {
	if !filepath.IsLocal(path) || path == "." {
		return false
	}
	parts := strings.Split(filepath.ToSlash(filepath.Clean(path)), "/")
	first := strings.ToLower(parts[0])
	if strings.HasPrefix(first, ".") || first == "agent" || first == "profiles" || first == "verge-imports" {
		return false
	}
	if len(parts) == 1 {
		switch first {
		case "config.yaml", "config.yml", "profiles.json", "settings.json", "kernel-options.json", "agent-rules.json", "cache.db", "netflow-worker-cache.db", "geoip.dat", "geosite.dat", "country.mmdb", "geoip.db", "geoip.metadb", "asn.mmdb", "bundlemrs.7z":
			return false
		}
	}
	return true
}
