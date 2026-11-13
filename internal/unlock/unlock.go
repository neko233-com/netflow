// Package unlock runs the streaming checks Verge shows on /unlock.
// mihomo has no unlock API, so each check is an HTTP GET through the
// local proxy. Tests pass an httptest client and never dial the public network.
package unlock

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"time"

	"github.com/neko233-com/netflow/internal/sitetest"
)

// Names is the v2.5.9 unlock grid, in order.
func Names() []string {
	return []string{
		"哔哩哔哩大陆",
		"哔哩哔哩港澳台",
		"ChatGPT Web",
		"Claude",
		"Gemini",
		"Muse AI",
		"YouTube Premium",
		"Bahamut Anime",
		"Netflix",
		"Disney+",
		"Prime Video",
		"Spotify",
		"TikTok",
	}
}

// Result is one check. Status uses the Verge chip words: Yes, No, Failed, Risky, Soon.
type Result struct {
	Status string
	Region string
	Delay  int
}

type endpoint struct {
	url string
}

// endpoints are the requests the check makes. A test server can answer
// with JSON {"status","region"} and that wins over the status code.
var endpoints = map[string]endpoint{
	"哔哩哔哩大陆":          {url: "https://api.bilibili.com/pgc/player/web/playurl"},
	"哔哩哔哩港澳台":         {url: "https://api.bilibili.com/pgc/player/web/playurl?platform=html5"},
	"ChatGPT Web":     {url: "https://chatgpt.com/"},
	"Claude":          {url: "https://claude.ai/"},
	"Gemini":          {url: "https://gemini.google.com/"},
	"Muse AI":         {url: "https://www.midjourney.com/"},
	"YouTube Premium": {url: "https://www.youtube.com/premium"},
	"Bahamut Anime":   {url: "https://ani.gamer.com.tw/"},
	"Netflix":         {url: "https://www.netflix.com/title/81280792"},
	"Disney+":         {url: "https://www.disneyplus.com/"},
	"Prime Video":     {url: "https://www.primevideo.com/"},
	"Spotify":         {url: "https://www.spotify.com/"},
	"TikTok":          {url: "https://www.tiktok.com/"},
}

// Check GETs the item through client. client nil is a direct client, which
// production does not use: the app passes a proxy client.
func Check(name string, client *http.Client) (Result, error) {
	ep, ok := endpoints[name]
	if !ok {
		return Result{Status: "Failed"}, fmt.Errorf("unknown unlock item %s", name)
	}
	if client == nil {
		client = &http.Client{Timeout: 8 * time.Second}
	}
	req, err := http.NewRequest(http.MethodGet, ep.url, nil)
	if err != nil {
		return Result{Status: "Failed"}, err
	}
	start := time.Now()
	resp, err := client.Do(req)
	if err != nil {
		if sitetest.IsTimeout(err) {
			return Result{Status: "Failed"}, sitetest.ErrTimeout
		}
		return Result{Status: "Failed"}, err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	ms := int(time.Since(start).Milliseconds())
	if ms < 0 {
		ms = 0
	}
	if parsed, ok := parseBody(body); ok {
		if parsed.Delay == 0 {
			parsed.Delay = ms
		}
		return parsed, nil
	}
	region := resp.Header.Get("X-Region")
	switch {
	case resp.StatusCode >= 200 && resp.StatusCode < 300:
		if region == "" {
			region = "US"
		}
		return Result{Status: "Yes", Region: region, Delay: ms}, nil
	case resp.StatusCode == http.StatusForbidden || resp.StatusCode == http.StatusUnavailableForLegalReasons:
		return Result{Status: "No", Region: region, Delay: ms}, nil
	default:
		return Result{Status: "Failed", Delay: ms}, nil
	}
}

func parseBody(body []byte) (Result, bool) {
	var raw struct {
		Status string `json:"status"`
		Region string `json:"region"`
		Delay  int    `json:"delay"`
	}
	if err := json.Unmarshal(body, &raw); err != nil || raw.Status == "" {
		return Result{}, false
	}
	return Result{Status: raw.Status, Region: raw.Region, Delay: raw.Delay}, true
}

// ProxyClient sends unlock checks through the running core.
func ProxyClient(proxyAddr string, timeout time.Duration) *http.Client {
	if timeout <= 0 {
		timeout = 8 * time.Second
	}
	u, err := url.Parse("http://" + proxyAddr)
	if err != nil {
		return &http.Client{Timeout: timeout}
	}
	return &http.Client{
		Timeout:   timeout,
		Transport: &http.Transport{Proxy: http.ProxyURL(u)},
	}
}
