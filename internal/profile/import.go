package profile

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/neko233-com/netflow/internal/safepath"
	"go.yaml.in/yaml/v3"
)

// Version is the clash-go release substituted into the default User-Agent.
// Tests and the linker may replace it. The default agent is
// "clash-go/v" + Version.
var Version = "0.0.0"

// DefaultTimeoutSeconds is the subscription fetch budget when
// ImportOption.TimeoutSeconds is nil (SUB-03).
const DefaultTimeoutSeconds = 20

const remoteFileName = "Remote File"

const uidAlphabet = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"

// ProxyKind is how ImportHTTP reaches the subscription URL.
// ProxyNone is a direct connection. ProxyLocalhost is the app's own mixed
// port. ProxySystem is the operating-system proxy. The last two are
// selected here and dialed by the injected RoundTripper; this package does
// not open a real system proxy.
type ProxyKind int

const (
	ProxyNone ProxyKind = iota
	ProxyLocalhost
	ProxySystem
)

func (k ProxyKind) String() string {
	switch k {
	case ProxyNone:
		return "none"
	case ProxyLocalhost:
		return "localhost"
	case ProxySystem:
		return "system"
	default:
		return "unknown"
	}
}

// ImportOption is the per-request override. Nil pointers mean "not set":
// UserAgent falls back to DefaultUserAgent, TimeoutSeconds to
// DefaultTimeoutSeconds, and UpdateInterval to the response header.
type ImportOption struct {
	Name           string
	Description    string
	UserAgent      *string
	WithProxy      bool
	SelfProxy      bool
	UpdateInterval *int
	TimeoutSeconds *int
}

// Option is the option block stored on a remote profile item.
type Option struct {
	UpdateInterval  *int
	Merge           string
	Script          string
	Rules           string
	Proxies         string
	Groups          string
	AllowAutoUpdate bool
}

// Item is one remote profile produced by ImportHTTP.
type Item struct {
	UID     string
	Type    string
	Name    string
	File    string
	URL     string
	Desc    string
	Extra   *Extra
	Home    string
	Updated int64
	Option  Option
	Body    string
}

// DefaultUserAgent is the User-Agent sent when ImportOption.UserAgent is nil.
func DefaultUserAgent() string {
	return "clash-go/v" + Version
}

// ProxyKindFor reports the transport class for the two proxy flags.
// selfProxy wins when both are set, matching Verge's from_url.
func ProxyKindFor(selfProxy, withProxy bool) ProxyKind {
	if selfProxy {
		return ProxyLocalhost
	}
	if withProxy {
		return ProxySystem
	}
	return ProxyNone
}

// ImportHTTP downloads a remote profile into profilesDir.
// trip supplies the RoundTripper for the resolved ProxyKind. A nil trip
// uses http.DefaultTransport for ProxyNone and returns an error for the
// other kinds.
//
// On any error the profiles directory is left without a new file.
// A successful item has Type "remote", File "{UID}.yaml", and empty child
// uids for merge, script, rules, proxies, and groups (SUB-12).
func ImportHTTP(ctx context.Context, rawURL string, opt ImportOption, profilesDir string, trip func(ProxyKind) (http.RoundTripper, error)) (Item, error) {
	if strings.TrimSpace(profilesDir) == "" {
		return Item{}, errors.New("profiles dir is empty")
	}
	if ctx == nil {
		ctx = context.Background()
	}
	parsed, err := url.ParseRequestURI(rawURL)
	if err != nil || parsed.Host == "" {
		return Item{}, fmt.Errorf("failed to parse subscription URL: %w", err)
	}

	kind := ProxyKindFor(opt.SelfProxy, opt.WithProxy)
	transport, err := transportFor(kind, trip)
	if err != nil {
		return Item{}, err
	}

	timeout := DefaultTimeoutSeconds
	if opt.TimeoutSeconds != nil {
		if *opt.TimeoutSeconds < 0 {
			return Item{}, errors.New("timeout_seconds is negative")
		}
		timeout = *opt.TimeoutSeconds
	}
	ctx, cancel := context.WithTimeout(ctx, time.Duration(timeout)*time.Second)
	defer cancel()

	ua := DefaultUserAgent()
	if opt.UserAgent != nil {
		ua = *opt.UserAgent
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, parsed.String(), nil)
	if err != nil {
		return Item{}, fmt.Errorf("failed to fetch remote profile: %w", err)
	}
	req.Header.Set("User-Agent", ua)

	resp, err := (&http.Client{Transport: transport}).Do(req)
	if err != nil {
		return Item{}, fmt.Errorf("failed to fetch remote profile: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return Item{}, fmt.Errorf("failed to fetch remote profile with status %d", resp.StatusCode)
	}
	payload, err := io.ReadAll(resp.Body)
	if err != nil {
		return Item{}, fmt.Errorf("failed to fetch remote profile: %w", err)
	}
	for bytesHasPrefixBOM(payload) {
		payload = payload[3:]
	}

	var doc any
	if err := yaml.Unmarshal(payload, &doc); err != nil {
		return Item{}, fmt.Errorf("the remote profile data is invalid yaml: %w", err)
	}
	mapping, ok := doc.(map[string]any)
	if !ok {
		return Item{}, errors.New("the remote profile data is invalid yaml: not a mapping")
	}
	if _, hasProxies := mapping["proxies"]; !hasProxies {
		if _, hasProviders := mapping["proxy-providers"]; !hasProviders {
			return Item{}, errors.New("profile does not contain `proxies` or `proxy-providers`")
		}
	}

	item, err := newRemoteItem(parsed.String(), opt, resp.Header, string(payload))
	if err != nil {
		return Item{}, err
	}
	if err := os.MkdirAll(profilesDir, 0o700); err != nil {
		return Item{}, err
	}
	created, err := safepath.CreateExclusive(profilesDir, item.File, payload, false)
	if err != nil {
		return Item{}, err
	}
	if err := created.Close(); err != nil {
		return Item{}, err
	}
	return item, nil
}

func transportFor(kind ProxyKind, trip func(ProxyKind) (http.RoundTripper, error)) (http.RoundTripper, error) {
	if trip == nil {
		if kind != ProxyNone {
			return nil, fmt.Errorf("proxy kind %s is not configured", kind)
		}
		return http.DefaultTransport, nil
	}
	rt, err := trip(kind)
	if err != nil {
		return nil, fmt.Errorf("proxy kind %s: %w", kind, err)
	}
	if rt == nil {
		return nil, fmt.Errorf("proxy kind %s returned a nil transport", kind)
	}
	return rt, nil
}

func newRemoteItem(rawURL string, opt ImportOption, header http.Header, body string) (Item, error) {
	uid, err := newUID("R")
	if err != nil {
		return Item{}, err
	}
	merge, err := newUID("m")
	if err != nil {
		return Item{}, err
	}
	script, err := newUID("s")
	if err != nil {
		return Item{}, err
	}
	rules, err := newUID("r")
	if err != nil {
		return Item{}, err
	}
	proxies, err := newUID("p")
	if err != nil {
		return Item{}, err
	}
	groups, err := newUID("g")
	if err != nil {
		return Item{}, err
	}

	var extra *Extra
	if info, ok := ParseSubscriptionUserInfo(header); ok {
		extra = &info
	}
	var interval *int
	if opt.UpdateInterval != nil {
		v := *opt.UpdateInterval
		interval = &v
	} else if mins, ok := ParseUpdateInterval(header.Get("profile-update-interval")); ok {
		interval = &mins
	}

	name := opt.Name
	if name == "" {
		name = profileName(header, rawURL)
	}
	home := ""
	if raw := header.Get("profile-web-page-url"); raw != "" {
		home = normalizeHome(raw)
	}

	return Item{
		UID:     uid,
		Type:    "remote",
		Name:    name,
		File:    uid + ".yaml",
		URL:     rawURL,
		Desc:    opt.Description,
		Extra:   extra,
		Home:    home,
		Updated: time.Now().Unix(),
		Option: Option{
			UpdateInterval:  interval,
			Merge:           merge,
			Script:          script,
			Rules:           rules,
			Proxies:         proxies,
			Groups:          groups,
			AllowAutoUpdate: true,
		},
		Body: body,
	}, nil
}

func bytesHasPrefixBOM(b []byte) bool {
	return len(b) >= 3 && b[0] == 0xEF && b[1] == 0xBB && b[2] == 0xBF
}

func newUID(prefix string) (string, error) {
	buf := make([]byte, 11)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	for i, b := range buf {
		buf[i] = uidAlphabet[int(b)%len(uidAlphabet)]
	}
	return prefix + string(buf), nil
}

func profileName(header http.Header, rawURL string) string {
	if cd := header.Get("Content-Disposition"); cd != "" {
		if name, ok := contentDispositionName(cd); ok {
			return name
		}
	}
	if name := urlLastSegment(rawURL); name != "" {
		return name
	}
	return remoteFileName
}

func contentDispositionName(cd string) (string, bool) {
	var star, plain string
	var hasStar, hasPlain bool
	for _, part := range strings.Split(cd, ";") {
		part = strings.TrimSpace(part)
		key, val, ok := strings.Cut(part, "=")
		if !ok {
			continue
		}
		key = strings.TrimSpace(key)
		val = strings.Trim(strings.TrimSpace(val), `"`)
		switch strings.ToLower(key) {
		case "filename*":
			star, hasStar = val, true
		case "filename":
			plain, hasPlain = val, true
		}
	}
	if hasStar {
		if name := decode5987(star); name != "" {
			return name, true
		}
	}
	if hasPlain && plain != "" {
		return plain, true
	}
	return "", false
}

func decode5987(v string) string {
	if _, after, ok := strings.Cut(v, "''"); ok {
		v = after
	}
	dec, err := url.PathUnescape(v)
	if err != nil || dec == "" {
		return ""
	}
	return dec
}

func urlLastSegment(raw string) string {
	u, err := url.Parse(raw)
	path := raw
	if err == nil {
		path = u.Path
	} else {
		path, _, _ = strings.Cut(raw, "?")
	}
	path = strings.TrimRight(path, "/")
	if path == "" {
		return ""
	}
	seg := path[strings.LastIndex(path, "/")+1:]
	seg = strings.TrimSpace(seg)
	if seg == "" {
		return ""
	}
	return seg
}

func normalizeHome(raw string) string {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil {
		return ""
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return ""
	}
	if u.Host == "" {
		return ""
	}
	return u.String()
}
