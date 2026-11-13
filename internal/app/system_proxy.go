package app

import (
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"

	"github.com/neko233-com/netflow/internal/sysproxy"
)

// manualSystemProxy deliberately uses only explicit HTTP(S) proxy endpoints.
// It never interprets PAC, automatic detection or bypass lists and never
// returns a direct route for a missing protocol.
func manualSystemProxy(settings sysproxy.Settings) (func(*http.Request) (*url.URL, error), error) {
	if !settings.Enabled {
		return nil, errors.New("系统手动代理未启用；自动代理脚本和自动检测尚不支持")
	}
	raw := map[string]string{}
	if settings.SchemeSpecific {
		raw["http"], raw["https"] = settings.HTTP, settings.HTTPS
	} else if server := strings.ToLower(strings.TrimSpace(settings.HTTP)); strings.HasPrefix(server, "http=") || strings.HasPrefix(server, "https=") || strings.HasPrefix(server, "socks=") {
		for _, part := range strings.Split(settings.HTTP, ";") {
			key, val, found := strings.Cut(strings.TrimSpace(part), "=")
			if found && (strings.EqualFold(strings.TrimSpace(key), "http") || strings.EqualFold(strings.TrimSpace(key), "https")) {
				raw[strings.ToLower(strings.TrimSpace(key))] = strings.TrimSpace(val)
			}
		}
	} else {
		raw["http"], raw["https"] = settings.HTTP, settings.HTTP
	}
	parsed := map[string]*url.URL{}
	for _, scheme := range []string{"http", "https"} {
		endpoint := strings.TrimSpace(raw[scheme])
		if endpoint == "" {
			continue
		}
		if !strings.Contains(endpoint, "://") {
			endpoint = "http://" + endpoint
		}
		proxy, err := url.Parse(endpoint)
		if err != nil || proxy.Host == "" || (proxy.Scheme != "http" && proxy.Scheme != "https") || proxy.Path != "" || proxy.RawQuery != "" || proxy.Fragment != "" {
			return nil, errors.New("系统手动代理地址无效或不是 HTTP(S) 代理")
		}
		host, port, err := net.SplitHostPort(proxy.Host)
		if err != nil || host == "" {
			return nil, errors.New("系统手动代理必须包含主机和端口")
		}
		n, err := strconv.Atoi(port)
		if err != nil || n < 1 || n > 65535 {
			return nil, errors.New("系统手动代理端口无效")
		}
		parsed[scheme] = proxy
	}
	if len(parsed) == 0 {
		return nil, errors.New("没有可用的系统手动 HTTP(S) 代理")
	}
	return func(req *http.Request) (*url.URL, error) {
		if proxy := parsed[strings.ToLower(req.URL.Scheme)]; proxy != nil {
			return proxy, nil
		}
		return nil, fmt.Errorf("系统手动代理未配置 %s，已拒绝直连", req.URL.Scheme)
	}, nil
}
