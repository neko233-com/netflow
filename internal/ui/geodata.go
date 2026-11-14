package ui

import "fmt"

func (m *Model) updateGeo() {
	if m.Busy == "geo" {
		return
	}
	if m.Hooks.UpdateGeoAsync == nil {
		m.Notice = "GeoData 更新不可用"
		return
	}
	m.Busy = "geo"
	m.Notice = "正在通过当前代理下载并校验 GeoData…"
	m.Hooks.UpdateGeoAsync(func(count int, err error) {
		m.Busy = ""
		if err != nil {
			m.Notice = "GeoData 更新失败: " + err.Error()
			return
		}
		m.Notice = fmt.Sprintf("已下载 %d 个 GeoData 数据库，请退出并重新启动 NetFlow 以应用", count)
	})
}
