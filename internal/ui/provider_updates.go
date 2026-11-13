package ui

import "strings"

func (m *Model) updateProxyProviders(names []string) {
	if m.ProviderBusy {
		return
	}
	if len(names) == 0 {
		m.Notice = "没有可更新的代理集合"
		return
	}
	if m.Hooks.UpdateProxyProviderAsync == nil {
		m.Notice = "代理集合更新不可用"
		return
	}
	m.ProviderBusy = true
	var failures []string
	completed := 0
	var next func(int)
	next = func(i int) {
		if i == len(names) {
			m.ProviderBusy = false
			m.Notice = "已更新 " + itoa(completed) + " 个代理集合"
			if len(failures) > 0 {
				m.Notice += "；失败：" + strings.Join(failures, "；")
			}
			return
		}
		m.Notice = "正在更新代理集合 " + itoa(i+1) + " / " + itoa(len(names))
		m.Hooks.UpdateProxyProviderAsync(names[i], func(err error) {
			if err != nil {
				failures = append(failures, names[i]+": "+err.Error())
			} else {
				completed++
			}
			next(i + 1)
		})
	}
	next(0)
}
