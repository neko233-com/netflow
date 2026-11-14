package ui

import (
	"bytes"
	"context"
	"encoding/base64"
	"fmt"
	"image"
	"image/color"
	"image/png"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func testIconPNG(t *testing.T, w, h int) []byte {
	t.Helper()
	img := image.NewRGBA(image.Rect(0, 0, w, h))
	img.Set(0, 0, color.RGBA{R: 255, A: 255})
	var out bytes.Buffer
	if err := png.Encode(&out, img); err != nil {
		t.Fatal(err)
	}
	return out.Bytes()
}
func TestGroupIconRejectsUnsafeOrOversizedContent(t *testing.T) {
	if _, err := decodeGroupIcon(testIconPNG(t, 1, 1)); err != nil {
		t.Fatal(err)
	}
	if _, err := decodeGroupIcon(testIconPNG(t, 513, 1)); err == nil {
		t.Fatal("oversized bitmap accepted")
	}
	valid := []byte(`<?xml version="1.0"?><svg xmlns="http://www.w3.org/2000/svg" width="16" height="16"><circle cx="8" cy="8" r="4" fill="#fff"/></svg>`)
	if _, err := decodeGroupIcon(valid); err != nil {
		t.Fatalf("valid SVG: %v", err)
	}
	for _, svg := range []string{`<svg width="1" height="1"><script/></svg>`, `<svg width="1" height="1"><image href="https://example.test/a"/></svg>`, `<!DOCTYPE svg [<!ENTITY x "bad">]><svg width="1" height="1"/>`, `<svg width="1" height="1"><path fill="url(#ok) url(https://example.test)"/></svg>`} {
		if _, err := decodeGroupIcon([]byte(svg)); err == nil {
			t.Fatalf("unsafe SVG accepted: %s", svg)
		}
	}
}
func TestGroupIconRendersAndDisablingCancelsLoading(t *testing.T) {
	m := DemoModel()
	m.Router.Replace("/proxies")
	m.Prefs.GroupIcon = true
	m.Groups[0].Icon = "data:image/png;base64," + base64.StdEncoding.EncodeToString(testIconPNG(t, 2, 2))
	tt := renderModel(m, WindowWidth, WindowHeight, false)
	deadline := time.Now().Add(3 * time.Second)
	for {
		tt.Frame()
		if _, ok := tt.Find("group-icon-Proxy"); ok {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("group icon did not render")
		}
		time.Sleep(10 * time.Millisecond)
	}
	m.Prefs.GroupIcon = false
	tt.Frame()
	if _, ok := tt.Find("group-icon-Proxy"); ok {
		t.Fatal("disabled group icon remained visible")
	}
	started := make(chan struct{})
	canceled := make(chan struct{})
	m.Prefs.GroupIcon = true
	m.Groups[0].Icon = "https://icons.example.test/a.png"
	m.Hooks.LoadGroupIcon = func(ctx context.Context, raw string) ([]byte, error) {
		if !strings.Contains(raw, "example.test") {
			t.Error("unexpected URL")
		}
		close(started)
		<-ctx.Done()
		close(canceled)
		return nil, ctx.Err()
	}
	tt.Frame()
	select {
	case <-started:
	case <-time.After(time.Second):
		t.Fatal("icon load did not start")
	}
	m.Prefs.GroupIcon = false
	tt.Frame()
	select {
	case <-canceled:
	case <-time.After(time.Second):
		t.Fatal("disabled icon load was not canceled")
	}
}

func TestGroupIconCacheBoundsConcurrentWorkAndEntries(t *testing.T) {
	cache := newGroupIconCache()
	var calls atomic.Int32
	loader := func(ctx context.Context, _ string) ([]byte, error) { calls.Add(1); <-ctx.Done(); return nil, ctx.Err() }
	for i := 0; i < 500; i++ {
		cache.get(fmt.Sprintf("https://icons.example.test/%d.png", i), loader, nil)
	}
	deadline := time.Now().Add(time.Second)
	for calls.Load() < 4 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	cache.mu.Lock()
	entries := len(cache.entries)
	inflight := len(cache.slots)
	cache.mu.Unlock()
	if entries > maxGroupIconEntries || inflight > 4 || calls.Load() > 4 {
		t.Fatalf("unbounded icon work: entries=%d inflight=%d calls=%d", entries, inflight, calls.Load())
	}
	cache.cancelPending()
	deadline = time.Now().Add(time.Second)
	for len(cache.slots) > 0 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if len(cache.slots) != 0 {
		t.Fatal("icon workers did not stop after cancellation")
	}
}
