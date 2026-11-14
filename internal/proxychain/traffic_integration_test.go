package proxychain_test

import (
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/metacubex/mihomo/component/profile/cachefile"
	"github.com/neko233-com/netflow/internal/core"
	"github.com/neko233-com/netflow/internal/proxychain"
)

type socksServer struct {
	ln   net.Listener
	hits atomic.Int32
}

func newSOCKS(t *testing.T) *socksServer {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	s := &socksServer{ln: ln}
	go func() {
		for {
			c, e := ln.Accept()
			if e != nil {
				return
			}
			go s.serve(c)
		}
	}()
	t.Cleanup(func() { ln.Close() })
	return s
}
func (s *socksServer) serve(c net.Conn) {
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(5 * time.Second))
	h := make([]byte, 2)
	if _, e := io.ReadFull(c, h); e != nil || h[0] != 5 {
		return
	}
	methods := make([]byte, int(h[1]))
	if _, e := io.ReadFull(c, methods); e != nil {
		return
	}
	if _, e := c.Write([]byte{5, 0}); e != nil {
		return
	}
	h = make([]byte, 4)
	if _, e := io.ReadFull(c, h); e != nil || h[0] != 5 || h[1] != 1 {
		return
	}
	var host string
	switch h[3] {
	case 1:
		b := make([]byte, 4)
		if _, e := io.ReadFull(c, b); e != nil {
			return
		}
		host = net.IP(b).String()
	case 3:
		b := make([]byte, 1)
		if _, e := io.ReadFull(c, b); e != nil {
			return
		}
		name := make([]byte, int(b[0]))
		if _, e := io.ReadFull(c, name); e != nil {
			return
		}
		host = string(name)
	case 4:
		b := make([]byte, 16)
		if _, e := io.ReadFull(c, b); e != nil {
			return
		}
		host = net.IP(b).String()
	default:
		return
	}
	p := make([]byte, 2)
	if _, e := io.ReadFull(c, p); e != nil {
		return
	}
	dst, e := net.DialTimeout("tcp", net.JoinHostPort(host, strconv.Itoa(int(binary.BigEndian.Uint16(p)))), time.Second)
	if e != nil {
		return
	}
	defer dst.Close()
	s.hits.Add(1)
	if _, e = c.Write([]byte{5, 0, 0, 1, 127, 0, 0, 1, 0, 0}); e != nil {
		return
	}
	_ = c.SetDeadline(time.Time{})
	go io.Copy(dst, c)
	_, _ = io.Copy(c, dst)
}
func (s *socksServer) port() int { return s.ln.Addr().(*net.TCPAddr).Port }
func freePort(t *testing.T) int {
	t.Helper()
	l, e := net.Listen("tcp", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	defer l.Close()
	return l.Addr().(*net.TCPAddr).Port
}

// Exercise real Mihomo traffic across both hops with TUN and DNS disabled.
func TestMihomoChainTraffic(t *testing.T) {
	root := t.TempDir()
	defer cachefile.Cache().Close()
	for _, provider := range []bool{false, true} {
		t.Run(fmt.Sprint("provider=", provider), func(t *testing.T) {
			a, b := newSOCKS(t), newSOCKS(t)
			var originHits atomic.Int32
			origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { originHits.Add(1); _, _ = io.WriteString(w, "ok") }))
			defer origin.Close()
			dir := filepath.Join(root, fmt.Sprint(provider))
			if err := os.Mkdir(dir, 0700); err != nil {
				t.Fatal(err)
			}
			port := freePort(t)
			nodes := fmt.Sprintf("  - {name: entry, type: socks5, server: 127.0.0.1, port: %d}\n  - {name: 'exit`node', type: socks5, server: 127.0.0.1, port: %d}\n", a.port(), b.port())
			source := "proxies:\n" + nodes
			hops := []proxychain.Hop{{Name: "entry"}, {Name: "exit`node"}}
			if provider {
				if err := os.WriteFile(filepath.Join(dir, "nodes.yaml"), []byte("proxies:\n"+nodes), 0600); err != nil {
					t.Fatal(err)
				}
				source = "proxy-providers:\n  nodes:\n    type: file\n    path: ./nodes.yaml\n    health-check: {enable: false}\n"
				hops[0].Provider = "nodes"
				hops[1].Provider = "nodes"
			}
			base := fmt.Sprintf("mixed-port: %d\nbind-address: 127.0.0.1\nmode: rule\nlog-level: error\nipv6: false\ntun: {enable: false}\ndns: {enable: false}\n%sproxy-groups:\n  - {name: TARGET, type: select, proxies: [DIRECT]}\nrules: ['MATCH,TARGET']\n", port, source)
			spec := proxychain.Spec{Target: "TARGET", Hops: hops}
			result, err := proxychain.Compose([]byte(base), spec)
			if err != nil {
				t.Fatal(err)
			}
			if err = os.WriteFile(filepath.Join(dir, "config.yaml"), []byte(base), 0600); err != nil {
				t.Fatal(err)
			}
			c := core.New()
			c.DisableExternalController()
			c.SetTransformer(func([]byte, string) ([]byte, error) { return result.Config, nil })
			if err = c.Start(dir); err != nil {
				t.Fatalf("start: %v\n%s", err, result.Config)
			}
			defer c.Stop()
			if err = c.Select("TARGET", result.Exit); err != nil {
				t.Fatal(err)
			}
			proxyURL, _ := url.Parse(fmt.Sprintf("http://127.0.0.1:%d", port))
			tr := &http.Transport{Proxy: http.ProxyURL(proxyURL), DisableKeepAlives: true}
			defer tr.CloseIdleConnections()
			client := &http.Client{Transport: tr, Timeout: 3 * time.Second}
			resp, err := client.Get(origin.URL)
			if err != nil {
				t.Fatalf("chained request: %v", err)
			}
			body, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			if string(body) != "ok" || a.hits.Load() != 1 || b.hits.Load() != 1 {
				t.Fatalf("body=%q entry=%d exit=%d", body, a.hits.Load(), b.hits.Load())
			}
			if provider {
				// Removing an exit from the upstream subscription must fail
				// closed, rather than silently selecting an unrelated proxy.
				if err := os.WriteFile(filepath.Join(dir, "nodes.yaml"), []byte("proxies:\n"+strings.Split(nodes, "\n")[0]+"\n"), 0600); err != nil {
					t.Fatal(err)
				}
				generated := strings.TrimSuffix(result.Exit, "hop_1") + "provider_1"
				if err := c.UpdateProxyProvider(generated); err != nil {
					t.Fatal(err)
				}
				group, err := c.Group(result.Exit)
				if err != nil {
					t.Fatal(err)
				}
				if group.Now != "REJECT" {
					t.Fatalf("missing provider node must select REJECT: %+v", group)
				}
				if response, err := client.Get(origin.URL); err == nil {
					response.Body.Close()
					if response.StatusCode == http.StatusOK {
						t.Fatal("missing provider node reached origin")
					}
				}
				if originHits.Load() != 1 {
					t.Fatalf("missing provider node leaked to origin: %d", originHits.Load())
				}
				if err := os.WriteFile(filepath.Join(dir, "nodes.yaml"), []byte("proxies:\n"+nodes), 0600); err != nil {
					t.Fatal(err)
				}
				if err := c.UpdateProxyProvider(generated); err != nil {
					t.Fatal(err)
				}
				response, err := client.Get(origin.URL)
				if err != nil {
					t.Fatalf("restored provider request: %v", err)
				}
				response.Body.Close()
				if response.StatusCode != http.StatusOK || originHits.Load() != 2 || a.hits.Load() != 2 || b.hits.Load() != 2 {
					t.Fatalf("restored provider did not recover: status=%d origin=%d entry=%d exit=%d", response.StatusCode, originHits.Load(), a.hits.Load(), b.hits.Load())
				}
			}
			a.ln.Close()
			if response, err := client.Get(origin.URL); err == nil {
				response.Body.Close()
				if response.StatusCode == http.StatusOK {
					t.Fatal("request succeeded after entry failure")
				}
			}
			expected := int32(1)
			if provider {
				expected = 2
			}
			if originHits.Load() != expected {
				t.Fatalf("chain fell back to direct: origin hits=%d", originHits.Load())
			}
			raw, err := os.ReadFile(filepath.Join(dir, "config.yaml"))
			if err != nil || string(raw) != base {
				t.Fatal("original configuration changed")
			}
		})
	}
}
