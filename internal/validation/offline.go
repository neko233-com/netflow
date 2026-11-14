// Package validation performs configuration checks in a short-lived process.
package validation

import (
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"strings"

	"github.com/metacubex/mihomo/component/geodata"
	C "github.com/metacubex/mihomo/constant"
	P "github.com/metacubex/mihomo/constant/provider"
	"github.com/metacubex/mihomo/hub/executor"
	"github.com/metacubex/mihomo/log"
	"github.com/neko233-com/netflow/internal/safepath"
)

const maxResource = 128 << 20

type Config struct {
	ID   string `json:"id"`
	Body []byte `json:"body"`
}
type Request struct {
	Directory string   `json:"directory"`
	Configs   []Config `json:"configs"`
}
type Result struct {
	Sources  map[string][32]byte `json:"sources"`
	Warnings []string            `json:"warnings,omitempty"`
}

type providerValidator interface {
	Vehicle() P.Vehicle
	ValidateBytes([]byte) error
}

// relativeSource accepts either the selected root's lexical spelling or its
// resolved spelling (for example a Windows junction or 8.3 path). The Root
// handle still enforces the actual filesystem boundary when opening it.
func relativeSource(directory, absolute string) (string, error) {
	if !filepath.IsAbs(directory) || !filepath.IsAbs(absolute) {
		return "", errors.New("source path is not absolute")
	}
	if rel, err := filepath.Rel(directory, absolute); err == nil && filepath.IsLocal(rel) && rel != "." {
		return rel, nil
	}
	resolvedRoot, err := safepath.Canonical(directory)
	if err != nil {
		return "", err
	}
	if rel, err := filepath.Rel(resolvedRoot, absolute); err == nil && filepath.IsLocal(rel) && rel != "." {
		return rel, nil
	}
	resolvedFile, err := safepath.Canonical(absolute)
	if err != nil {
		return "", errors.New("source path is outside the configuration directory")
	}
	if rel, err := filepath.Rel(resolvedRoot, resolvedFile); err == nil && filepath.IsLocal(rel) && rel != "." {
		return rel, nil
	}
	return "", errors.New("source path is outside the configuration directory")
}

// HashSource streams a bounded regular file and confines resolution to root.
func HashSource(root *os.Root, directory, absolute string) ([32]byte, error) {
	var sum [32]byte
	rel, err := relativeSource(directory, absolute)
	if err != nil {
		return sum, err
	}
	f, err := root.Open(rel)
	if err != nil {
		return sum, err
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Size() > maxResource {
		return sum, errors.New("source file is invalid or too large")
	}
	h := sha256.New()
	n, err := io.Copy(h, io.LimitReader(f, maxResource+1))
	if err != nil {
		return sum, err
	}
	if n > maxResource {
		return sum, errors.New("source file is too large")
	}
	copy(sum[:], h.Sum(nil))
	return sum, nil
}

// Check must be called only in a disposable validation process: mihomo has
// process-global configuration and provider parsers may allocate resources.
func Check(req Request) (Result, error) {
	if !filepath.IsAbs(req.Directory) || len(req.Configs) == 0 || len(req.Configs) > 5000 {
		return Result{}, errors.New("invalid validation request")
	}
	root, err := os.OpenRoot(req.Directory)
	if err != nil {
		return Result{}, err
	}
	defer root.Close()
	C.SetHomeDir(req.Directory)
	C.ConstrainPaths()
	geodata.SetOfflineValidation(true)
	log.SetLevel(log.SILENT)
	result := Result{Sources: map[string][32]byte{}}
	open := func(absolute string) (*os.File, error) {
		rel, err := relativeSource(req.Directory, absolute)
		if err != nil {
			return nil, err
		}
		f, err := root.Open(rel)
		if err != nil {
			return nil, err
		}
		info, err := f.Stat()
		if err != nil || !info.Mode().IsRegular() || info.Size() > maxResource {
			_ = f.Close()
			return nil, errors.New("provider file is invalid or too large")
		}
		return f, nil
	}
	read := func(absolute string) ([]byte, [32]byte, error) {
		var zero [32]byte
		f, err := open(absolute)
		if err != nil {
			return nil, zero, err
		}
		defer f.Close()
		data, err := io.ReadAll(io.LimitReader(f, maxResource+1))
		if err != nil {
			return nil, zero, err
		}
		if len(data) > maxResource {
			return nil, zero, errors.New("provider file is too large")
		}
		return data, sha256.Sum256(data), nil
	}
	hash := func(absolute string) ([32]byte, error) { return HashSource(root, req.Directory, absolute) }
	geoHashes := func() (map[string][32]byte, error) {
		out := map[string][32]byte{}
		// MMDB discovery updates mihomo's global GeoIP name, so resolve it
		// first and retain the conventional dat path separately.
		mmdb := C.Path.MMDB()
		for _, path := range []string{C.Path.GeoIP(), filepath.Join(req.Directory, "GeoIP.dat"), C.Path.GeoSite(), mmdb, filepath.Join(req.Directory, "Country.mmdb"), filepath.Join(req.Directory, "geoip.db"), filepath.Join(req.Directory, "geoip.metadb"), C.Path.ASN()} {
			path = filepath.Clean(path)
			sum, err := hash(path)
			if err != nil && !errors.Is(err, os.ErrNotExist) {
				return nil, err
			}
			out[path] = sum
		}
		return out, nil
	}
	before, err := geoHashes()
	if err != nil {
		return Result{}, err
	}
	for _, source := range req.Configs {
		if len(source.Body) == 0 || len(source.Body) > 8<<20 {
			return Result{}, errors.New("invalid configuration size")
		}
		cfg, err := executor.ParseWithBytes(source.Body)
		if err != nil {
			return Result{}, fmt.Errorf("profile %q: %w", source.ID, err)
		}
		validate := func(name string, provider P.Provider) error {
			v, ok := provider.(providerValidator)
			if !ok {
				return nil
			} // Inline and compatible providers were parsed with the config.
			vehicle := v.Vehicle()
			path := filepath.Clean(vehicle.Path())
			rel, relErr := relativeSource(req.Directory, path)
			if relErr != nil {
				return errors.New("provider path is outside the configuration directory")
			}
			first := strings.Split(filepath.ToSlash(rel), "/")[0]
			if strings.EqualFold(first, "verge-script-outputs") {
				return errors.New("provider path uses private script output storage")
			}
			data, sum, err := read(path)
			if errors.Is(err, os.ErrNotExist) && vehicle.Type() == P.HTTP {
				result.Sources[path] = [32]byte{}
				if len(result.Warnings) == 0 {
					result.Warnings = append(result.Warnings, "Some HTTP provider caches are missing; their downloaded contents were not validated.")
				}
				return nil
			}
			if err != nil {
				return fmt.Errorf("provider %q: %w", name, err)
			}
			if previous, ok := result.Sources[path]; ok && previous != sum {
				return errors.New("provider changed during validation")
			}
			result.Sources[path] = sum
			if err := v.ValidateBytes(data); err != nil {
				return fmt.Errorf("provider %q: %w", name, err)
			}
			after, err := hash(path)
			if err != nil || after != sum {
				return errors.New("provider changed during validation")
			}
			return nil
		}
		for name, provider := range cfg.Providers {
			if err := validate(name, provider); err != nil {
				return Result{}, fmt.Errorf("profile %q: %w", source.ID, err)
			}
		}
		for name, provider := range cfg.RuleProviders {
			if err := validate(name, provider); err != nil {
				return Result{}, fmt.Errorf("profile %q: %w", source.ID, err)
			}
		}
	}
	after, err := geoHashes()
	if err != nil || !reflect.DeepEqual(before, after) {
		return Result{}, errors.New("geodata changed during validation")
	}
	for path, hash := range before {
		result.Sources[path] = hash
	}
	return result, nil
}
