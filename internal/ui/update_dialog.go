package ui

import (
	"time"

	mygoui "github.com/egoist/mygo/ui"
	"github.com/neko233-com/netflow/internal/update"
)

func (m *Model) checkUpdate() {
	if m.Busy == "check-update" {
		return
	}
	if m.Hooks.CheckUpdateAsync == nil {
		m.Notice = "更新检查不可用"
		return
	}
	m.Busy = "check-update"
	m.Notice = "正在检查更新…"
	m.Hooks.CheckUpdateAsync(func(result update.Result, err error) {
		m.Busy = ""
		if err != nil {
			m.Notice = "检查更新失败: " + err.Error()
			return
		}
		m.Home.LastCheck = time.Now().Format("2006-01-02 15:04")
		m.UpdateResult = result
		m.UpdateDialog = true
		m.Notice = "更新检查完成"
	})
}

func (m *Model) updateDialog(c *mygoui.Context, pal Palette) {
	if !m.UpdateDialog {
		return
	}
	mygoui.Modal(c, &m.UpdateDialog, func() {
		mygoui.Column(c).Width(400).Padding(16).Gap(10).Radius(10).Background(pal.Dialog).Children(func() {
			mygoui.Text(c, "检查更新").FontSize(18).Bold()
			mygoui.Text(c, "当前版本 "+m.UpdateResult.Current).FontSize(14)
			mygoui.Text(c, "最新版本 "+m.UpdateResult.Latest).FontSize(14)
			message := "当前已是所选更新通道的最新版本。"
			if m.UpdateResult.Available {
				message = "发现新版本，可前往 GitHub 查看并下载安装。"
			}
			mygoui.Text(c, message).FontSize(13).TextColor(pal.TextMuted)
			mygoui.Row(c).Gap(8).Children(func() {
				if filledButton(c, pal, "关闭", "update-close", false) {
					m.UpdateDialog = false
				}
				if m.UpdateResult.Available && filledButton(c, pal, "打开发布页", "update-open", true) {
					c.OpenURL(m.UpdateResult.URL)
				}
			})
		})
	})
}
