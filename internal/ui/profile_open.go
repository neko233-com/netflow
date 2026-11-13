package ui

func (m *Model) openProfileFile(id string) {
	if m.Hooks.OpenProfileFile == nil {
		m.Notice = "打开订阅文件不可用"
		return
	}
	if err := m.Hooks.OpenProfileFile(id); err != nil {
		m.Notice = err.Error()
		return
	}
	m.Notice = "文件已打开；保存后请重新激活订阅，远程更新会覆盖编辑"
}
