package app

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

type iconTestResolver map[string][]netip.Addr

func (r iconTestResolver) LookupNetIP(_ context.Context, _ string, host string) ([]netip.Addr, error) {
	if value, ok := r[host]; ok {
		return value, nil
	}
	return nil, errors.New("unknown host")
}

type iconRoundTrip func(*http.Request) (*http.Response, error)

func (f iconRoundTrip) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func TestGroupIconDownloadPinsPublicIPAndValidatesRedirects(t *testing.T) {
	resolver := iconTestResolver{"first.example": {netip.MustParseAddr("8.8.8.8")}, "second.example": {netip.MustParseAddr("1.1.1.1")}, "private.example": {netip.MustParseAddr("127.0.0.1")}, "mixed.example": {netip.MustParseAddr("8.8.8.8"), netip.MustParseAddr("10.0.0.1")}}
	requests := 0
	factory := func(proxy, serverName string) *http.Client {
		if proxy != "127.0.0.1:7897" {
			t.Error("unexpected proxy")
		}
		return &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }, Transport: iconRoundTrip(func(r *http.Request) (*http.Response, error) {
			requests++
			if requests == 1 {
				if serverName != "first.example" || r.URL.Host != "8.8.8.8:443" || r.Host != "first.example" {
					t.Errorf("first request not pinned: %s %s %s", serverName, r.URL.Host, r.Host)
				}
				return &http.Response{StatusCode: http.StatusFound, Header: http.Header{"Location": []string{"https://second.example/icon.png"}}, Body: io.NopCloser(strings.NewReader("")), Request: r}, nil
			}
			if serverName != "second.example" || r.URL.Host != "1.1.1.1:443" || r.Host != "second.example" {
				t.Errorf("redirect not pinned: %s %s %s", serverName, r.URL.Host, r.Host)
			}
			return &http.Response{StatusCode: http.StatusOK, Header: http.Header{}, Body: io.NopCloser(strings.NewReader("icon")), ContentLength: 4, Request: r}, nil
		})}
	}
	data, err := fetchGroupIcon(context.Background(), "https://first.example/a", "127.0.0.1:7897", resolver, factory)
	if err != nil || string(data) != "icon" || requests != 2 {
		t.Fatalf("download: %q %d %v", data, requests, err)
	}
	for _, raw := range []string{"http://127.0.0.1/", "http://169.254.169.254/", "https://private.example/a", "https://mixed.example/a", "https://user:pass@first.example/a", "file:///secret"} {
		before := requests
		if _, err := fetchGroupIcon(context.Background(), raw, "127.0.0.1:7897", resolver, factory); err == nil || requests != before {
			t.Fatalf("unsafe URL reached proxy: %s %v", raw, err)
		}
	}
	downgrade := func(_, _ string) *http.Client {
		return &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }, Transport: iconRoundTrip(func(r *http.Request) (*http.Response, error) {
			return &http.Response{StatusCode: http.StatusFound, Header: http.Header{"Location": []string{"http://second.example/icon"}}, Body: io.NopCloser(strings.NewReader("")), Request: r}, nil
		})}
	}
	if _, err := fetchGroupIcon(context.Background(), "https://first.example/a", "127.0.0.1:7897", resolver, downgrade); err == nil {
		t.Fatal("HTTPS downgrade accepted")
	}
	oversized := func(_, _ string) *http.Client {
		return &http.Client{Transport: iconRoundTrip(func(r *http.Request) (*http.Response, error) {
			return &http.Response{StatusCode: http.StatusOK, Header: http.Header{}, Body: io.NopCloser(strings.NewReader("a")), ContentLength: maxGroupIconDownload + 1, Request: r}, nil
		})}
	}
	if _, err := fetchGroupIcon(context.Background(), "https://first.example/a", "127.0.0.1:7897", resolver, oversized); err == nil {
		t.Fatal("oversized icon accepted")
	}
}
func TestGroupIconIPClassification(t *testing.T) {
	for _, ip := range []string{"127.0.0.1", "10.0.0.1", "100.64.0.1", "169.254.169.254", "198.18.0.1", "192.0.2.1", "::1", "fd00::1", "2001:db8::1", "64:ff9b::a00:1", "2002:0a00:0001::1"} {
		if publicIconIP(netip.MustParseAddr(ip)) {
			t.Fatalf("nonpublic IP accepted: %s", ip)
		}
	}
	for _, ip := range []string{"8.8.8.8", "1.1.1.1", "2606:4700:4700::1111"} {
		if !publicIconIP(netip.MustParseAddr(ip)) {
			t.Fatalf("public IP rejected: %s", ip)
		}
	}
}

// The proxy pins a public target but the fixture forwards to a local TLS
// origin, so this verifies CONNECT and hostname validation without Internet.
func TestGroupIconDownloadUsesRealProxyAndTLS(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "icons.example.test"}, DNSNames: []string{"icons.example.test"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, IsCA: true, BasicConstraintsValid: true}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	pool := x509.NewCertPool()
	pool.AddCert(cert)
	var origins, proxies atomic.Int32
	origin := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		origins.Add(1)
		if r.Host != "icons.example.test" {
			t.Errorf("unexpected origin host: %s", r.Host)
		}
		_, _ = w.Write([]byte("icon-data"))
	}))
	origin.TLS = &tls.Config{Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}}, MinVersion: tls.VersionTLS12}
	origin.StartTLS()
	defer origin.Close()
	proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "CONNECT" || r.Host != "8.8.8.8:443" {
			http.Error(w, "unexpected target", http.StatusBadRequest)
			return
		}
		proxies.Add(1)
		target, err := net.DialTimeout("tcp", origin.Listener.Addr().String(), time.Second)
		if err != nil {
			http.Error(w, "origin unavailable", http.StatusBadGateway)
			return
		}
		hijacker, ok := w.(http.Hijacker)
		if !ok {
			target.Close()
			return
		}
		conn, _, err := hijacker.Hijack()
		if err != nil {
			target.Close()
			return
		}
		_, _ = io.WriteString(conn, "HTTP/1.1 200 Connection Established\r\n\r\n")
		go func() {
			defer target.Close()
			defer conn.Close()
			go io.Copy(target, conn)
			_, _ = io.Copy(conn, target)
		}()
	}))
	proxyAddress := strings.TrimPrefix(proxy.URL, "http://")
	resolver := iconTestResolver{"icons.example.test": {netip.MustParseAddr("8.8.8.8")}}
	factory := func(proxyAddr, serverName string) *http.Client {
		client := iconHTTPClient(proxyAddr, serverName)
		client.Transport.(*http.Transport).TLSClientConfig.RootCAs = pool
		return client
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	body, err := fetchGroupIcon(ctx, "https://icons.example.test/image.png", proxyAddress, resolver, factory)
	if err != nil || string(body) != "icon-data" || origins.Load() != 1 || proxies.Load() != 1 {
		t.Fatalf("proxied TLS fetch: %q origin=%d proxy=%d %v", body, origins.Load(), proxies.Load(), err)
	}
	proxy.Close()
	if _, err := fetchGroupIcon(ctx, "https://icons.example.test/image.png", proxyAddress, resolver, factory); err == nil {
		t.Fatal("icon request fell back after proxy stopped")
	}
	if origins.Load() != 1 {
		t.Fatal("origin was reached without the proxy")
	}
}

func TestGroupIconTriesAnotherPublicAddress(t *testing.T) {
	resolver := iconTestResolver{"retry.example": {netip.MustParseAddr("2606:4700:4700::1111"), netip.MustParseAddr("8.8.8.8"), netip.MustParseAddr("1.1.1.1")}}
	var calls []string
	factory := func(_, _ string) *http.Client {
		return &http.Client{Transport: iconRoundTrip(func(r *http.Request) (*http.Response, error) {
			calls = append(calls, r.URL.Host)
			if r.URL.Host == "8.8.8.8:443" {
				return nil, errors.New("first IP unavailable")
			}
			return &http.Response{StatusCode: http.StatusOK, Header: http.Header{}, ContentLength: 2, Body: io.NopCloser(strings.NewReader("ok")), Request: r}, nil
		})}
	}
	body, err := fetchGroupIcon(context.Background(), "https://retry.example/icon", "127.0.0.1:7897", resolver, factory)
	if err != nil || string(body) != "ok" || len(calls) != 2 || calls[0] != "8.8.8.8:443" || calls[1] != "1.1.1.1:443" {
		t.Fatalf("address retry: %q %v %v", body, calls, err)
	}
}
