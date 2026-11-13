package ui

import (
	"os"
	"strings"
	"testing"

	mygoui "github.com/egoist/mygo/ui"
)

func TestProfileQRShareAndCleanup(t *testing.T) {
	m := NewModel(HomeState{})
	raw := "https://example.test/subscribe?token=test-secret"
	m.openProfileQR(raw)
	if !m.QROpen || m.QRImage == nil || m.QRURL != raw {
		t.Fatal("QR dialog did not open")
	}
	var copied string
	m.Hooks.Copy = func(s string) error { copied = s; return nil }
	tt := mygoui.NewTester(m.View, WindowWidth, WindowHeight)
	if !tt.HasText("二维码包含订阅凭据，请只向可信设备分享。") {
		t.Fatal("missing sensitive-data notice")
	}
	if path := os.Getenv("NETFLOW_QR_SCREENSHOT"); path != "" {
		if err := writePNG(path, tt.Image()); err != nil {
			t.Fatal(err)
		}
	}
	if err := tt.Click("qr-copy"); err != nil {
		t.Fatal(err)
	}
	if copied != raw {
		t.Fatal("copied the wrong URL")
	}
	if err := tt.Click("qr-close"); err != nil {
		t.Fatal(err)
	}
	if m.QROpen || m.QRURL != "" || m.QRImage != nil {
		t.Fatal("QR data remained after closing")
	}
	m.openProfileQR("javascript:alert(1)")
	if m.QROpen || m.Notice == "" {
		t.Fatal("unsafe URL accepted")
	}
	m.openProfileQR("https://example.test/" + strings.Repeat("x", 5000))
	if m.QROpen || !strings.Contains(m.Notice, "过长") {
		t.Fatal("oversize QR did not return a clear error")
	}
}
