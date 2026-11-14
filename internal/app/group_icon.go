package app

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"
)

const maxGroupIconDownload = 256 << 10

type iconResolver interface {
	LookupNetIP(context.Context, string, string) ([]netip.Addr, error)
}
type iconClientFactory func(proxyAddr, serverName string) *http.Client

var blockedIconNetworks = func() []netip.Prefix {
	ranges := []string{"0.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8", "169.254.0.0/16", "192.0.0.0/24", "192.0.2.0/24", "192.88.99.0/24", "198.18.0.0/15", "198.51.100.0/24", "203.0.113.0/24", "224.0.0.0/4", "240.0.0.0/4", "64:ff9b::/96", "64:ff9b:1::/48", "100::/64", "2001::/32", "2001:db8::/32", "2002::/16"}
	result := make([]netip.Prefix, 0, len(ranges))
	for _, r := range ranges {
		result = append(result, netip.MustParsePrefix(r))
	}
	return result
}()

func publicIconIP(ip netip.Addr) bool {
	ip = ip.Unmap()
	if !ip.IsValid() || !ip.IsGlobalUnicast() || ip.IsPrivate() || ip.IsLoopback() || ip.IsLinkLocalUnicast() {
		return false
	}
	for _, blocked := range blockedIconNetworks {
		if blocked.Contains(ip) {
			return false
		}
	}
	return true
}
func iconHTTPClient(proxyAddr, serverName string) *http.Client {
	client := newSubscriptionClient(proxyAddr, 8*time.Second, false)
	transport := client.Transport.(*http.Transport)
	transport.DisableKeepAlives = true
	transport.MaxResponseHeaderBytes = 32 << 10
	transport.TLSClientConfig = &tls.Config{ServerName: serverName, MinVersion: tls.VersionTLS12}
	client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	return client
}

type kernelIconResolver struct{ engine coreEngine }

func (r kernelIconResolver) LookupNetIP(ctx context.Context, network, host string) ([]netip.Addr, error) {
	if network != "ip" {
		return nil, errors.New("invalid DNS network")
	}
	resolver, ok := r.engine.(interface {
		ResolveIconHost(context.Context, string) ([]netip.Addr, error)
	})
	if !ok {
		return nil, errors.New("kernel DNS unavailable")
	}
	return resolver.ResolveIconHost(ctx, host)
}
func (a *App) loadGroupIcon(ctx context.Context, raw string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(ctx, 8*time.Second)
	defer cancel()
	if a == nil || a.core == nil {
		return nil, errors.New("kernel unavailable")
	}
	status := a.core.Status()
	if !status.Running || status.MixedPort <= 0 {
		return nil, errors.New("kernel proxy unavailable")
	}
	proxy := net.JoinHostPort("127.0.0.1", strconv.Itoa(status.MixedPort))
	return fetchGroupIcon(ctx, raw, proxy, kernelIconResolver{engine: a.core}, iconHTTPClient)
}

// Resolve each redirect to public addresses and connect to a checked IP via the
// running core proxy. TLS still verifies the original hostname. There is no
// fallback to a direct host connection when the core proxy is unavailable.
func fetchGroupIcon(ctx context.Context, raw, proxy string, resolver iconResolver, factory iconClientFactory) ([]byte, error) {
	if len(raw) > 4096 || proxy == "" || resolver == nil || factory == nil {
		return nil, errors.New("invalid icon URL")
	}
	current, err := url.Parse(raw)
	if err != nil {
		return nil, errors.New("invalid icon URL")
	}
	previousScheme := ""
	for redirects := 0; redirects <= 3; redirects++ {
		if len(current.String()) > 4096 {
			return nil, errors.New("icon URL exceeds size limit")
		}
		scheme := strings.ToLower(current.Scheme)
		host := strings.TrimSuffix(strings.ToLower(current.Hostname()), ".")
		if (scheme != "http" && scheme != "https") || host == "" || current.User != nil || current.Opaque != "" || current.Fragment != "" || host == "localhost" || strings.HasSuffix(host, ".localhost") || strings.HasSuffix(host, ".local") {
			return nil, errors.New("unsupported icon URL")
		}
		if previousScheme == "https" && scheme != "https" {
			return nil, errors.New("insecure icon redirect")
		}
		port := current.Port()
		if port == "" {
			if scheme == "https" {
				port = "443"
			} else {
				port = "80"
			}
		}
		value, err := strconv.Atoi(port)
		if err != nil || value < 1 || value > 65535 {
			return nil, errors.New("invalid icon port")
		}
		var addresses []netip.Addr
		if ip, e := netip.ParseAddr(host); e == nil {
			addresses = []netip.Addr{ip}
		} else {
			addresses, err = resolver.LookupNetIP(ctx, "ip", host)
			if err != nil || len(addresses) == 0 {
				return nil, errors.New("icon host resolution failed")
			}
		}
		if len(addresses) > 64 {
			return nil, errors.New("too many icon host addresses")
		}
		for _, ip := range addresses {
			if !publicIconIP(ip) {
				return nil, errors.New("icon host is not public")
			}
		}
		// Prefer IPv4 when available, then try a bounded number of distinct
		// addresses. Each attempt shares the overall deadline and cannot
		// bypass the core proxy.
		addresses = append([]netip.Addr(nil), addresses...)
		sort.SliceStable(addresses, func(i, j int) bool { return addresses[i].Unmap().Is4() && !addresses[j].Unmap().Is4() })
		var response *http.Response
		var responseCancel context.CancelFunc
		seen := map[netip.Addr]bool{}
		for _, address := range addresses {
			address = address.Unmap()
			if seen[address] {
				continue
			}
			seen[address] = true
			if len(seen) > 4 {
				break
			}
			pinned := *current
			pinned.Host = net.JoinHostPort(address.String(), port)
			attemptCtx, cancel := context.WithTimeout(ctx, 3*time.Second)
			req, requestErr := http.NewRequestWithContext(attemptCtx, http.MethodGet, pinned.String(), nil)
			if requestErr != nil {
				cancel()
				return nil, errors.New("invalid icon request")
			}
			req.Host = current.Host
			req.Header.Set("Accept", "image/png, image/jpeg, image/gif, image/webp, image/svg+xml")
			response, err = factory(proxy, host).Do(req)
			if err == nil {
				responseCancel = cancel
				break
			}
			if response != nil {
				if response.Body != nil {
					response.Body.Close()
				}
				response = nil
			}
			cancel()
			if ctx.Err() != nil {
				break
			}
		}
		if response == nil {
			return nil, errors.New("icon download failed")
		}

		if response.StatusCode >= 300 && response.StatusCode <= 399 {
			location := response.Header.Get("Location")
			response.Body.Close()
			responseCancel()
			if location == "" || len(location) > 4096 {
				return nil, errors.New("invalid icon redirect")
			}
			next, e := current.Parse(location)
			if e != nil {
				return nil, errors.New("invalid icon redirect")
			}
			previousScheme = scheme
			current = next
			continue
		}
		if response.StatusCode != http.StatusOK {
			response.Body.Close()
			responseCancel()
			return nil, fmt.Errorf("icon request returned HTTP %d", response.StatusCode)
		}
		if response.ContentLength > maxGroupIconDownload {
			response.Body.Close()
			responseCancel()
			return nil, errors.New("icon exceeds size limit")
		}
		body, readErr := io.ReadAll(io.LimitReader(response.Body, maxGroupIconDownload+1))
		closeErr := response.Body.Close()
		responseCancel()
		if readErr != nil || closeErr != nil || len(body) == 0 || len(body) > maxGroupIconDownload {
			return nil, errors.New("invalid icon response")
		}
		return body, nil
	}
	return nil, errors.New("too many icon redirects")
}
