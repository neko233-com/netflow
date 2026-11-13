package ui

import (
	"strings"

	mygoui "github.com/egoist/mygo/ui"
	qrcode "github.com/skip2/go-qrcode"
)

func (m *Model) openProfileQR(raw string) {
	raw = strings.TrimSpace(raw)
	if !safeProfileHome(raw) {
		m.Notice = "订阅链接无效，无法生成二维码"
		return
	}
	png, err := qrcode.Encode(raw, qrcode.Medium, 512)
	if err != nil {
		m.Notice = "订阅链接过长，无法生成二维码"
		return
	}
	picture, err := mygoui.DecodeImage(png)
	if err != nil {
		m.Notice = "无法生成二维码"
		return
	}
	m.QRImage, m.QRURL, m.QROpen = picture, raw, true
}

func (m *Model) profileQRDialog(c *mygoui.Context, pal Palette) {
	if !m.QROpen {
		return
	}
	mygoui.Modal(c, &m.QROpen, func() {
		mygoui.Column(c).Width(400).Padding(16).Gap(8).Radius(10).Background(pal.Dialog).Children(func() {
			mygoui.Text(c, "订阅二维码").FontSize(18).Bold()
			mygoui.Text(c, "二维码包含订阅凭据，请只向可信设备分享。").FontSize(12).TextColor(pal.Warning)
			if m.QRImage != nil {
				mygoui.Image(c, m.QRImage).Size(320, 320).Label("subscription-qr")
			}
			mygoui.Row(c).Gap(8).Children(func() {
				if filledButton(c, pal, "复制链接", "qr-copy", false) {
					m.copy(m.QRURL)
				}
				if filledButton(c, pal, "关闭", "qr-close", true) {
					m.QROpen = false
				}
			})
		})
	})
	if !m.QROpen {
		m.QRURL = ""
		m.QRImage = nil
	}
}
