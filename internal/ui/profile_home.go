package ui

import (
	"net/url"
	"strings"

	mygoui "github.com/egoist/mygo/ui"
)

func safeProfileHome(raw string) bool {
	u, err := url.Parse(strings.TrimSpace(raw))
	return err == nil && (u.Scheme == "http" || u.Scheme == "https") && u.Hostname() != ""
}

func (m *Model) openProfileHome(c *mygoui.Context, raw string) {
	if !safeProfileHome(raw) {
		m.Notice = "订阅主页地址无效"
		return
	}
	c.OpenURL(strings.TrimSpace(raw))
}
