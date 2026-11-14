// Package webdav uploads explicitly selected, unencrypted NetFlow backups.
// Credentials and server responses are never included in returned errors.
package webdav

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

const MaxArchiveBytes = 544 << 20

type Credentials struct {
	URL      string
	User     string
	Password string
}

// Client accepts an optional HTTP client for tests; upload always refuses
// redirects, irrespective of its client's redirect policy.
type Client struct{ HTTP *http.Client }

type countedReader struct {
	r      io.Reader
	n      atomic.Int64
	mu     sync.Mutex
	closed bool
	done   chan struct{}
}

// Validate checks the endpoint and authentication syntax without connecting.
func Validate(c Credentials) error {
	_, _, _, err := validate(c)
	return err
}

func (r *countedReader) Read(p []byte) (int, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed {
		return 0, io.EOF
	}
	n, err := r.r.Read(p)
	r.n.Add(int64(n))
	return n, err
}

func (r *countedReader) Close() error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if !r.closed {
		r.closed = true
		close(r.done)
	}
	return nil
}

func validate(c Credentials) (*url.URL, string, string, error) {
	if len(c.URL) > 8192 || len(c.User) > 1024 || len(c.Password) > 4096 {
		return nil, "", "", errors.New("invalid WebDAV configuration")
	}
	u, err := url.Parse(c.URL)
	if err != nil || u.Scheme != "https" || u.Hostname() == "" || u.Fragment != "" || u.Opaque != "" {
		return nil, "", "", errors.New("WebDAV requires an HTTPS collection URL without a fragment")
	}
	user, password := c.User, c.Password
	if u.User != nil {
		if user != "" || password != "" {
			return nil, "", "", errors.New("choose either URL credentials or separate credentials")
		}
		user = u.User.Username()
		password, _ = u.User.Password()
		u.User = nil
	}
	if strings.ContainsAny(user, "\r\n:") || strings.ContainsAny(password, "\r\n") {
		return nil, "", "", errors.New("invalid WebDAV credentials")
	}
	return u, user, password, nil
}

// Upload writes to a new randomly named resource within the given collection.
// A conforming server will reject an existing resource via If-None-Match.
// Interruption may leave a partial remote resource; it is never deleted here.
func (c Client) Upload(ctx context.Context, credentials Credentials, archive io.Reader, size int64) (string, error) {
	if ctx == nil || archive == nil || size <= 0 || size > MaxArchiveBytes {
		return "", errors.New("invalid backup upload")
	}
	u, user, password, err := validate(credentials)
	if err != nil {
		return "", err
	}
	var nonce [16]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return "", errors.New("could not allocate backup name")
	}
	name := "netflow-" + time.Now().UTC().Format("20060102-150405") + "-" + hex.EncodeToString(nonce[:]) + ".zip"
	escaped := strings.TrimRight(u.EscapedPath(), "/") + "/" + name
	u.Path = strings.TrimRight(u.Path, "/") + "/" + name
	u.RawPath = escaped
	ctx, cancel := context.WithTimeout(ctx, 10*time.Minute)
	defer cancel()
	reader := &countedReader{r: io.LimitReader(archive, size), done: make(chan struct{})}
	req, err := http.NewRequestWithContext(ctx, http.MethodPut, u.String(), reader)
	if err != nil {
		return "", errors.New("invalid WebDAV request")
	}
	req.ContentLength = size
	req.Header.Set("Content-Type", "application/zip")
	req.Header.Set("If-None-Match", "*")
	if user != "" || password != "" {
		req.SetBasicAuth(user, password)
	}
	var client http.Client
	if c.HTTP != nil {
		client = *c.HTTP
	} else {
		transport := &http.Transport{
			Proxy:                 nil,
			DialContext:           (&net.Dialer{Timeout: 15 * time.Second, KeepAlive: 30 * time.Second}).DialContext,
			TLSHandshakeTimeout:   15 * time.Second,
			ResponseHeaderTimeout: 30 * time.Second,
			DisableCompression:    true,
		}
		defer transport.CloseIdleConnections()
		client.Transport = transport
	}
	client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	resp, err := client.Do(req)
	// net/http may close the body asynchronously after Do returns. Ensure
	// archive reads have stopped before the caller seeks or hashes the file.
	<-reader.done
	if err != nil {
		return name, errors.New("WebDAV upload failed")
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusCreated && resp.StatusCode != http.StatusNoContent && resp.StatusCode != http.StatusOK {
		return name, fmt.Errorf("WebDAV upload failed (HTTP %d)", resp.StatusCode)
	}
	if reader.n.Load() != size {
		return name, errors.New("WebDAV server replied before the backup was sent")
	}
	return name, nil
}
