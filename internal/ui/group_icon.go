package ui

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/xml"
	"errors"
	"image"
	"io"
	"strings"
	"sync"
	"time"

	mygoui "github.com/egoist/mygo/ui"
)

const maxGroupIconBytes = 256 << 10
const maxGroupIconEntries = 64

type groupIconEntry struct {
	image   mygoui.ImageSource
	expires time.Time
	used    uint64
	cancel  context.CancelFunc
}
type groupIconCache struct {
	mu      sync.Mutex
	entries map[[32]byte]*groupIconEntry
	slots   chan struct{}
	clock   uint64
}

func newGroupIconCache() *groupIconCache {
	return &groupIconCache{entries: make(map[[32]byte]*groupIconEntry), slots: make(chan struct{}, 4)}
}

// get never performs I/O or image decoding on the native UI thread. Failed
// requests are cached briefly and both concurrency and retained images are bounded.
func (c *groupIconCache) get(raw string, load func(context.Context, string) ([]byte, error), invalidate func()) mygoui.ImageSource {
	if c == nil || raw == "" || len(raw) > maxGroupIconBytes*2 {
		return nil
	}
	dataURI := strings.HasPrefix(strings.ToLower(raw), "data:")
	if !dataURI && load == nil {
		return nil
	}
	key := sha256.Sum256([]byte(raw))
	now := time.Now()
	c.mu.Lock()
	c.clock++
	entry := c.entries[key]
	if entry == nil {
		if len(c.entries) >= maxGroupIconEntries {
			var oldest [32]byte
			var victim *groupIconEntry
			for k, e := range c.entries {
				if e.cancel == nil && (victim == nil || e.used < victim.used) {
					oldest, victim = k, e
				}
			}
			if victim == nil {
				c.mu.Unlock()
				return nil
			}
			delete(c.entries, oldest)
		}
		entry = &groupIconEntry{}
		c.entries[key] = entry
	}
	entry.used = c.clock
	current := entry.image
	if entry.cancel != nil || now.Before(entry.expires) {
		c.mu.Unlock()
		return current
	}
	select {
	case c.slots <- struct{}{}:
	default:
		c.mu.Unlock()
		return current
	}
	ctx, cancel := context.WithCancel(context.Background())
	entry.cancel = cancel
	c.mu.Unlock()
	go func() {
		defer func() { <-c.slots; cancel() }()
		var body []byte
		var err error
		if dataURI {
			body, err = decodeIconDataURI(raw)
		} else {
			body, err = load(ctx, raw)
		}
		var result mygoui.ImageSource
		if err == nil && ctx.Err() == nil {
			result, err = safelyDecodeGroupIcon(body)
		}
		c.mu.Lock()
		if currentEntry := c.entries[key]; currentEntry == entry {
			entry.cancel = nil
			if ctx.Err() != nil {
				entry.expires = time.Time{}
			} else if err != nil {
				entry.expires = time.Now().Add(time.Minute)
			} else {
				entry.image = result
				entry.expires = time.Now().Add(30 * time.Minute)
			}
		}
		c.mu.Unlock()
		if ctx.Err() == nil && invalidate != nil {
			invalidate()
		}
	}()
	return current
}
func (c *groupIconCache) cancelPending() {
	if c == nil {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	for _, entry := range c.entries {
		if entry.cancel != nil {
			entry.cancel()
		}
	}
}
func decodeIconDataURI(raw string) ([]byte, error) {
	comma := strings.IndexByte(raw, ',')
	if comma < 0 {
		return nil, errors.New("invalid data image")
	}
	header := strings.ToLower(raw[:comma])
	if !strings.HasPrefix(header, "data:image/") || !strings.HasSuffix(header, ";base64") {
		return nil, errors.New("unsupported data image")
	}
	body, err := base64.StdEncoding.DecodeString(raw[comma+1:])
	if err != nil || len(body) > maxGroupIconBytes {
		return nil, errors.New("invalid data image")
	}
	return body, nil
}
func safelyDecodeGroupIcon(body []byte) (result mygoui.ImageSource, err error) {
	defer func() {
		if recover() != nil {
			result = nil
			err = errors.New("invalid icon")
		}
	}()
	return decodeGroupIcon(body)
}
func decodeGroupIcon(body []byte) (mygoui.ImageSource, error) {
	if len(body) == 0 || len(body) > maxGroupIconBytes {
		return nil, errors.New("invalid icon size")
	}
	if config, _, err := image.DecodeConfig(bytes.NewReader(body)); err == nil {
		if config.Width < 1 || config.Height < 1 || config.Width > 512 || config.Height > 512 {
			return nil, errors.New("icon dimensions exceed limit")
		}
		return mygoui.DecodeBitmap(body)
	}
	if err := validateGroupSVG(body); err != nil {
		return nil, err
	}
	icon, err := mygoui.ParseSVG(body)
	if err != nil {
		return nil, err
	}
	w, h := mygoui.ImageSize(icon)
	if w <= 0 || h <= 0 || w > 4096 || h > 4096 {
		return nil, errors.New("invalid SVG size")
	}
	return icon, nil
}
func validateGroupSVG(body []byte) error {
	dec := xml.NewDecoder(bytes.NewReader(body))
	count := 0
	root := false
	for {
		token, err := dec.Token()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return errors.New("invalid SVG")
		}
		count++
		if count > 10000 {
			return errors.New("SVG is too complex")
		}
		switch item := token.(type) {
		case xml.Directive:
			return errors.New("SVG directives are not allowed")
		case xml.ProcInst:
			if !strings.EqualFold(item.Target, "xml") {
				return errors.New("SVG processing instructions are not allowed")
			}
		case xml.StartElement:
			name := strings.ToLower(item.Name.Local)
			if !root {
				if name != "svg" {
					return errors.New("not an SVG")
				}
				root = true
			}
			switch name {
			case "script", "foreignobject", "image", "style":
				return errors.New("unsupported SVG element")
			}
			for _, attr := range item.Attr {
				key := strings.ToLower(attr.Name.Local)
				value := strings.TrimSpace(strings.ToLower(attr.Value))
				if (key == "href" || key == "src") && !strings.HasPrefix(value, "#") {
					return errors.New("external SVG references are not allowed")
				}
				for rest := value; ; {
					at := strings.Index(rest, "url(")
					if at < 0 {
						break
					}
					rest = strings.TrimSpace(rest[at+4:])
					if !strings.HasPrefix(rest, "#") {
						return errors.New("external SVG references are not allowed")
					}
				}
			}
		}
	}
	if !root {
		return errors.New("not an SVG")
	}
	return nil
}
