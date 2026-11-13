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
	"time"
)

type request struct {
	Method    string          `json:"method"`
	Arguments json.RawMessage `json:"arguments,omitempty"`
}
type response struct {
	Result json.RawMessage `json:"result,omitempty"`
	Error  string          `json:"error,omitempty"`
}
type endpoint struct {
	Address string `json:"address"`
	Token   string `json:"token"`
	PID     int    `json:"pid"`
}
type Handler func(context.Context, string, json.RawMessage) (any, error)

type Bridge struct {
	server   *http.Server
	listener net.Listener
	file     string
	token    string
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
	parent := filepath.Join(dir, "agent")
	if err = os.MkdirAll(parent, 0700); err != nil {
		listener.Close()
		return nil, err
	}
	file, err := createPrivateEndpoint(parent, fmt.Sprintf("endpoint-%d-", os.Getpid()))
	if err != nil {
		listener.Close()
		return nil, err
	}
	fileName := file.Name()
	e := endpoint{Address: listener.Addr().String(), Token: token, PID: os.Getpid()}
	err = json.NewEncoder(file).Encode(e)
	if closeErr := file.Close(); err == nil {
		err = closeErr
	}
	if err != nil {
		listener.Close()
		os.Remove(fileName)
		return nil, err
	}
	b := &Bridge{listener: listener, file: fileName, token: token}
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
		payload, err := json.Marshal(result)
		if err != nil {
			_ = json.NewEncoder(w).Encode(response{Error: "encode response failed"})
			return
		}
		_ = json.NewEncoder(w).Encode(response{Result: payload})
	})}
	go func() { _ = b.server.Serve(listener) }()
	return b, nil
}

func (b *Bridge) Close() error {
	if b == nil {
		return nil
	}
	err := b.server.Close()
	data, readErr := os.ReadFile(b.file)
	var e endpoint
	if readErr == nil && json.Unmarshal(data, &e) == nil && e.Token == b.token {
		_ = os.Remove(b.file)
	}
	return err
}

// Client discovers a live instance and never uses environment HTTP proxies.
type Client struct {
	Dir     string
	PID     int
	Timeout time.Duration
}

func (c Client) Call(ctx context.Context, method string, args any, out any) error {
	entries, err := os.ReadDir(filepath.Join(c.Dir, "agent"))
	if err != nil {
		return errors.New("no running NetFlow agent bridge found")
	}
	var active []endpoint
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasPrefix(entry.Name(), "endpoint-") || !strings.HasSuffix(entry.Name(), ".json") {
			continue
		}
		file := filepath.Join(c.Dir, "agent", entry.Name())
		data, e := os.ReadFile(file)
		if e != nil || len(data) > 4096 {
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
		probeCtx, cancel := context.WithTimeout(ctx, time.Second)
		e = c.call(probeCtx, ep, "ping", nil, nil)
		cancel()
		if e == nil {
			active = append(active, ep)
		}
	}
	if len(active) == 0 {
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
	var result response
	if err = json.NewDecoder(io.LimitReader(res.Body, 4<<20)).Decode(&result); err != nil {
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
