// Package agent provides a local authenticated bridge and an MCP/CLI client.
package agent

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/neko233-com/netflow/internal/safepath"
)

type request struct {
	Method    string          `json:"method"`
	Arguments json.RawMessage `json:"arguments,omitempty"`
}
type response struct {
	Result json.RawMessage `json:"result,omitempty"`
	Error  string          `json:"error,omitempty"`
}

const maxBridgeResponseBytes = 32 << 20

type endpoint struct {
	Address string `json:"address"`
	Token   string `json:"token"`
	PID     int    `json:"pid"`
}
type Handler func(context.Context, string, json.RawMessage) (any, error)

// AfterResponse performs a local action after the bridge has written its reply.
// It is used for graceful shutdown, where closing the server before replying
// would make the caller unable to tell whether its request was accepted.
type AfterResponse struct {
	Result any
	After  func()
}

type Bridge struct {
	server    *http.Server
	listener  net.Listener
	file      string
	token     string
	root      *os.Root
	name      string
	info      os.FileInfo
	closeOnce sync.Once
	closeErr  error
}

// Start listens only on IPv4 loopback and advertises a random bearer token in
// the current user's configuration directory. The handler must serialize app
// mutations with the desktop event loop.
func Start(dir string, handle Handler) (*Bridge, error) {
	if dir == "" || handle == nil {
		return nil, errors.New("agent bridge is not configured")
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return nil, err
	}
	var secret [32]byte
	if _, err = rand.Read(secret[:]); err != nil {
		listener.Close()
		return nil, err
	}
	token := hex.EncodeToString(secret[:])
	if err = os.MkdirAll(dir, 0700); err != nil {
		listener.Close()
		return nil, err
	}
	parent := filepath.Join(dir, "agent")
	root, _, err := safepath.Parent(dir, filepath.Join("agent", "endpoint"), true)
	if err != nil {
		listener.Close()
		return nil, err
	}
	file, name, err := createPrivateEndpoint(root, parent, fmt.Sprintf("endpoint-%d-", os.Getpid()))
	if err != nil {
		root.Close()
		listener.Close()
		return nil, err
	}
	info, err := file.Stat()
	if err != nil {
		file.Close()
		root.Close()
		listener.Close()
		return nil, err
	}
	fileName := filepath.Join(parent, name)
	e := endpoint{Address: listener.Addr().String(), Token: token, PID: os.Getpid()}
	err = json.NewEncoder(file).Encode(e)
	if closeErr := file.Close(); err == nil {
		err = closeErr
	}
	if err != nil {
		listener.Close()
		if current, e := root.Lstat(name); e == nil && os.SameFile(info, current) {
			_ = root.Remove(name)
		}
		root.Close()
		return nil, err
	}
	b := &Bridge{listener: listener, file: fileName, token: token, root: root, name: name, info: info}
	b.server = &http.Server{ReadHeaderTimeout: 5 * time.Second, Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Host != e.Address || r.Header.Get("Origin") != "" {
			http.Error(w, "forbidden", http.StatusForbidden)
			return
		}
		header := r.Header.Get("Authorization")
		if !strings.HasPrefix(header, "Bearer ") {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		provided := strings.TrimPrefix(header, "Bearer ")
		if len(provided) != len(token) || subtle.ConstantTimeCompare([]byte(provided), []byte(token)) != 1 {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		if r.Method != http.MethodPost || r.URL.Path != "/rpc" {
			http.NotFound(w, r)
			return
		}
		r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
		var in request
		dec := json.NewDecoder(r.Body)
		dec.DisallowUnknownFields()
		if err := dec.Decode(&in); err != nil || in.Method == "" {
			http.Error(w, "invalid request", http.StatusBadRequest)
			return
		}
		var extra any
		if err := dec.Decode(&extra); err != io.EOF {
			http.Error(w, "invalid request", http.StatusBadRequest)
			return
		}
		if in.Method == "ping" {
			_ = json.NewEncoder(w).Encode(response{Result: json.RawMessage(`{"ok":true}`)})
			return
		}
		result, err := handle(r.Context(), in.Method, in.Arguments)
		w.Header().Set("Content-Type", "application/json")
		if err != nil {
			_ = json.NewEncoder(w).Encode(response{Error: err.Error()})
			return
		}
		var after func()
		if deferred, ok := result.(AfterResponse); ok {
			result, after = deferred.Result, deferred.After
		}
		payload, err := json.Marshal(result)
		if err != nil {
			_ = json.NewEncoder(w).Encode(response{Error: "encode response failed"})
			return
		}
		if err := json.NewEncoder(w).Encode(response{Result: payload}); err == nil && after != nil {
			if flusher, ok := w.(http.Flusher); ok {
				flusher.Flush()
			}
			after()
		}
	})}
	go func() { _ = b.server.Serve(listener) }()
	return b, nil
}

func (b *Bridge) Close() error {
	if b == nil {
		return nil
	}
	b.closeOnce.Do(func() {
		err := b.server.Close()
		var data []byte
		current, statErr := b.root.Lstat(b.name)
		if statErr == nil && current.Mode().IsRegular() && os.SameFile(b.info, current) {
			if f, openErr := b.root.Open(b.name); openErr == nil {
				opened, e := f.Stat()
				if e == nil && os.SameFile(b.info, opened) {
					data, _ = io.ReadAll(io.LimitReader(f, 4097))
				}
				_ = f.Close()
			}
		}
		var e endpoint
		if len(data) <= 4096 && json.Unmarshal(data, &e) == nil && e.Token == b.token {
			if latest, e := b.root.Lstat(b.name); e == nil && latest.Mode().IsRegular() && os.SameFile(b.info, latest) {
				_ = b.root.Remove(b.name)
			}
		}
		b.closeErr = errors.Join(err, b.root.Close())
	})
	return b.closeErr
}

// Client discovers a live instance and never uses environment HTTP proxies.
type Client struct {
	Dir     string
	PID     int
	Timeout time.Duration
}

func (c Client) Call(ctx context.Context, method string, args any, out any) error {
	timeout := c.Timeout
	if timeout <= 0 {
		timeout = 30 * time.Second
	}
	ctx, cancelCall := context.WithTimeout(ctx, timeout)
	defer cancelCall()
	root, _, err := safepath.Parent(c.Dir, filepath.Join("agent", "endpoint"), false)
	if err != nil {
		return errors.New("no running NetFlow agent bridge found")
	}
	defer root.Close()
	dir, err := root.Open(".")
	if err != nil {
		return errors.New("no running NetFlow agent bridge found")
	}
	entries, readErr := dir.ReadDir(-1)
	closeErr := dir.Close()
	if readErr != nil || closeErr != nil {
		return errors.New("no running NetFlow agent bridge found")
	}
	var active []endpoint
	var probeErrors []error
	for _, entry := range entries {
		if err := ctx.Err(); err != nil {
			return fmt.Errorf("agent discovery interrupted: %w", err)
		}
		if entry.IsDir() || !strings.HasPrefix(entry.Name(), "endpoint-") || !strings.HasSuffix(entry.Name(), ".json") {
			continue
		}
		info, e := root.Lstat(entry.Name())
		if e != nil || !info.Mode().IsRegular() {
			continue
		}
		f, e := root.Open(entry.Name())
		if e != nil {
			continue
		}
		opened, e := f.Stat()
		if e != nil || !opened.Mode().IsRegular() || !os.SameFile(info, opened) {
			_ = f.Close()
			continue
		}
		data, e := io.ReadAll(io.LimitReader(f, 4097))
		closeErr := f.Close()
		if e != nil || closeErr != nil || len(data) > 4096 {
			continue
		}
		var ep endpoint
		if json.Unmarshal(data, &ep) != nil || (c.PID != 0 && ep.PID != c.PID) || len(ep.Token) != 64 {
			continue
		}
		host, port, e := net.SplitHostPort(ep.Address)
		if e != nil || host != "127.0.0.1" || port == "" {
			continue
		}
		if _, e = hex.DecodeString(ep.Token); e != nil {
			continue
		}
		// A loaded single-core machine can need longer than a second to
		// answer even a local ping. This remains bounded by the caller's
		// context and the client's configured timeout.
		probeCtx, cancel := context.WithTimeout(ctx, 3*time.Second)
		e = c.call(probeCtx, ep, "ping", nil, nil)
		cancel()
		if e == nil {
			active = append(active, ep)
		} else {
			probeErrors = append(probeErrors, e)
		}
	}
	if len(active) == 0 {
		if len(probeErrors) != 0 {
			return fmt.Errorf("no running NetFlow agent bridge found; endpoint probe failed: %w", errors.Join(probeErrors...))
		}
		return errors.New("no running NetFlow agent bridge found")
	}
	if len(active) != 1 {
		return errors.New("multiple NetFlow instances found; specify the process id")
	}
	return c.call(ctx, active[0], method, args, out)
}

func (c Client) call(ctx context.Context, ep endpoint, method string, args any, out any) error {
	payload, err := json.Marshal(struct {
		Method    string `json:"method"`
		Arguments any    `json:"arguments,omitempty"`
	}{method, args})
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, "http://"+ep.Address+"/rpc", bytes.NewReader(payload))
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+ep.Token)
	req.Header.Set("Content-Type", "application/json")
	timeout := c.Timeout
	if timeout == 0 {
		timeout = 30 * time.Second
	}
	client := &http.Client{Timeout: timeout, Transport: &http.Transport{Proxy: nil}, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	defer client.CloseIdleConnections()
	res, err := client.Do(req)
	if err != nil {
		return err
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		_, _ = io.Copy(io.Discard, io.LimitReader(res.Body, 4096))
		return fmt.Errorf("agent bridge returned HTTP %d", res.StatusCode)
	}
	data, err := io.ReadAll(io.LimitReader(res.Body, maxBridgeResponseBytes+1))
	if err != nil {
		return err
	}
	if len(data) > maxBridgeResponseBytes {
		return errors.New("agent response exceeds the 32 MiB limit")
	}
	var result response
	if err = json.Unmarshal(data, &result); err != nil {
		return err
	}
	if result.Error != "" {
		return errors.New(result.Error)
	}
	if out != nil {
		return json.Unmarshal(result.Result, out)
	}
	return nil
}
