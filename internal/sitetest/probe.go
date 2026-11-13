package sitetest

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"time"
)

// ErrTimeout is a probe that did not answer before the client deadline.
var ErrTimeout = errors.New("检测超时或失败")

// IsTimeout reports a client deadline or a network timeout.
func IsTimeout(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, ErrTimeout) || errors.Is(err, context.DeadlineExceeded) {
		return true
	}
	var ne net.Error
	return errors.As(err, &ne) && ne.Timeout()
}

// ProbeURL measures one GET. client nil uses a 5 second timeout.
// Callers in tests pass an httptest transport so this does not dial the public network.
func ProbeURL(raw string, client *http.Client) (int, error) {
	if raw == "" {
		return 0, fmt.Errorf("empty url")
	}
	if client == nil {
		client = &http.Client{Timeout: 5 * time.Second}
	}
	req, err := http.NewRequest(http.MethodGet, raw, nil)
	if err != nil {
		return 0, err
	}
	start := time.Now()
	resp, err := client.Do(req)
	if err != nil {
		if IsTimeout(err) {
			return 0, ErrTimeout
		}
		return 0, err
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode < 200 || resp.StatusCode >= 400 {
		return 0, fmt.Errorf("status %d", resp.StatusCode)
	}
	ms := int(time.Since(start).Milliseconds())
	if ms < 0 {
		ms = 0
	}
	return ms, nil
}
