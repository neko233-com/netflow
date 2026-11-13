package ui

func (m *Model) openRuntimeConfig() {
	if m.Hooks.LoadEffectiveConfig == nil {
		m.Notice = "当前配置不可用"
		return
	}
	text, err := m.Hooks.LoadEffectiveConfig()
	if err != nil {
		m.Notice = err.Error()
		return
	}
	m.RuntimeConfig = text
	m.Dialogs.Runtime = true
}
