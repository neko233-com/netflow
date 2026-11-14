package coreipc

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log"
	"net/rpc"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// cacheState is protected by Client.applyMu. Its baseline is the last version
// supplied by or successfully written to the unprivileged user directory.
type cacheState struct {
	base     map[string][32]byte
	known    map[string]string
	running  bool
	isolated bool
}

var ErrProviderCacheSync = errors.New("provider updated; one or more caches were not persisted")

func newCacheState(files []StageFile, isolated bool) cacheState {
	state := cacheState{base: make(map[string][32]byte), known: make(map[string]string), running: true, isolated: isolated}
	for _, f := range files {
		state.base[strings.ToLower(filepath.Clean(f.Path))] = sha256.Sum256(f.Data)
	}
	return state
}

func (c *Client) cacheQuery() ProviderCacheQuery {
	known := make(map[string]string, len(c.caches.known))
	for k, v := range c.caches.known {
		known[k] = v
	}
	return ProviderCacheQuery{Known: known}
}

func (c *Client) setCacheWarning(err error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if err == nil {
		c.cacheWarning = ""
		return
	}
	c.cacheWarning = err.Error()
}

// CacheWarning describes the latest failed cache persistence without claiming
// the kernel stop failed after it has already released the TUN.
func (c *Client) CacheWarning() string { c.mu.Lock(); defer c.mu.Unlock(); return c.cacheWarning }

func (c *Client) syncProviderCaches() error {
	if !c.caches.running || !c.caches.isolated {
		return nil
	}
	result, err := c.readProviderCaches(c.cacheQuery(), 45*time.Second)
	if err != nil {
		c.setCacheWarning(err)
		return err
	}
	return c.applyProviderCaches(result)
}

// A slow read-only cache snapshot must not tear down a healthy TUN. Keep at
// most one abandoned read in flight; its eventual result is discarded.
func (c *Client) readProviderCaches(query ProviderCacheQuery, timeout time.Duration) (ProviderCaches, error) {
	c.mu.Lock()
	if c.cachePending {
		c.mu.Unlock()
		return ProviderCaches{}, errors.New("previous provider cache snapshot is still running")
	}
	c.cachePending = true
	c.mu.Unlock()
	result := new(ProviderCaches)
	done := c.rpc.Go("Kernel.ProviderCaches", query, result, make(chan *rpc.Call, 1)).Done
	clear := func() { c.mu.Lock(); c.cachePending = false; c.mu.Unlock() }
	timer := time.NewTimer(timeout)
	defer timer.Stop()
	select {
	case call := <-done:
		clear()
		return *result, call.Error
	case <-timer.C:
		go func() { <-done; clear() }()
		return ProviderCaches{}, errors.New("provider cache snapshot timed out")
	}
}

func (c *Client) applyProviderCaches(result ProviderCaches) error {
	var problems []error
	if result.Warning != "" {
		problems = append(problems, errors.New(result.Warning))
	}
	c.mu.Lock()
	dir := c.dir
	c.mu.Unlock()
	root, err := os.OpenRoot(dir)
	if err != nil {
		c.setCacheWarning(err)
		return err
	}
	defer root.Close()
	for _, item := range result.Items {
		if !validProviderCachePath(item.Path) {
			problems = append(problems, errors.New("provider cache path is not allowed"))
			continue
		}
		key := strings.ToLower(filepath.Clean(item.Path))
		if err = persistProviderCache(root, item, c.caches.base[key], hasCacheBaseline(c.caches.base, key)); err != nil {
			problems = append(problems, err)
			continue
		}
		c.caches.base[key] = sha256.Sum256(item.Data)
		c.caches.known[key] = item.Version
	}
	err = errors.Join(problems...)
	c.setCacheWarning(err)
	return err
}

func hasCacheBaseline(m map[string][32]byte, key string) bool { _, ok := m[key]; return ok }

// persistProviderCache refuses links/reparse points and only replaces a file
// whose contents still match the snapshot sent to the worker. A newly created
// user file is never overwritten. The final rename is atomic per file.
func persistProviderCache(root *os.Root, item ProviderCache, baseline [32]byte, existed bool) error {
	rel := filepath.Clean(item.Path)
	parts := strings.Split(rel, string(os.PathSeparator))
	parent := "."
	for _, part := range parts[:len(parts)-1] {
		parent = filepath.Join(parent, part)
		info, err := root.Lstat(parent)
		if errors.Is(err, os.ErrNotExist) {
			if err := root.Mkdir(parent, 0700); err != nil {
				return err
			}
			continue
		}
		if err != nil {
			return err
		}
		if !info.IsDir() {
			return errors.New("provider cache parent is not a regular directory")
		}
	}
	info, err := root.Lstat(rel)
	if errors.Is(err, os.ErrNotExist) {
		if existed {
			return fmt.Errorf("provider cache %s was removed by the user", rel)
		}
	} else if err != nil {
		return err
	} else {
		if !info.Mode().IsRegular() {
			return fmt.Errorf("provider cache %s is not a regular file", rel)
		}
		f, err := root.Open(rel)
		if err != nil {
			return err
		}
		data, readErr := io.ReadAll(io.LimitReader(f, maxStageBytes+1))
		closeErr := f.Close()
		if readErr != nil {
			return readErr
		}
		if closeErr != nil {
			return closeErr
		}
		if len(data) > maxStageBytes {
			return errors.New("provider cache exceeds size limit")
		}
		current, next := sha256.Sum256(data), sha256.Sum256(item.Data)
		if current == next {
			return nil
		}
		if !existed || current != baseline {
			return fmt.Errorf("provider cache %s changed in the user directory", rel)
		}
	}
	var id [16]byte
	if _, err := rand.Read(id[:]); err != nil {
		return err
	}
	tmp := filepath.Join(parent, ".netflow-provider-"+hex.EncodeToString(id[:]))
	f, err := root.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return err
	}
	defer root.Remove(tmp)
	_, err = f.Write(item.Data)
	if err == nil {
		err = f.Sync()
	}
	if closeErr := f.Close(); err == nil {
		err = closeErr
	}
	if err != nil {
		return err
	}
	return root.Rename(tmp, rel)
}

func (c *Client) startCacheLoop() {
	interval := c.cacheInterval
	if interval <= 0 {
		interval = 30 * time.Second
	}
	c.cacheLoopOnce.Do(func() {
		go func() {
			ticker := time.NewTicker(interval)
			defer ticker.Stop()
			for {
				select {
				case <-c.cacheStop:
					return
				case <-ticker.C:
					c.applyMu.Lock()
					err := c.syncProviderCaches()
					c.applyMu.Unlock()
					if err != nil {
						log.Printf("provider cache synchronization failed: %v", err)
					}
				}
			}
		}()
	})
}
