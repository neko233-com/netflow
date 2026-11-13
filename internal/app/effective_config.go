package app

import (
	"errors"
	"strings"
)

func (a *App) effectiveConfig() (string, error) {
	if a == nil || a.core == nil {
		return "", errors.New("内核不可用")
	}
	data, err := a.core.EffectiveConfig()
	if err != nil {
		return "", err
	}
	const maxView = 256 << 10
	if len(data) > maxView {
		data = data[:maxView]
		return strings.ToValidUTF8(string(data), "�") + "\n# 内容过长，仅显示前 256 KiB\n", nil
	}
	return string(data), nil
}
