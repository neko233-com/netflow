package ui

import (
	"strings"

	mygoui "github.com/egoist/mygo/ui"

	"github.com/neko233-com/netflow/internal/clashlog"
	"github.com/neko233-com/netflow/internal/query"
)

// LogView is the logs page. Level defaults to all. Order defaults to ascending.
type LogView struct {
	Lines  []clashlog.Line
	Level  string
	Query  query.Options
	Paused bool
	Desc   bool
}

func (m *Model) logsPage(c *mygoui.Context, pal Palette) {
	if m.Logs.Level == "" {
		m.Logs.Level = "all"
	}
	lines := clashlog.Filter(m.Logs.Lines, m.Logs.Level, m.Logs.Query, m.Logs.Desc)
	m.page(c, pal, "日志", func() {
		pauseTip := "暂停"
		mark := iconPause
		if m.Logs.Paused {
			pauseTip = "继续"
			mark = iconPlay
		}
		if iconButtonBox(c, pal, mark, pauseTip, "log-pause", "log-pause-icon", iconButtonSmall, iconGlyphSmall, iconButtonSmall/2) {
			m.Logs.Paused = !m.Logs.Paused
			if m.Hooks.SetLogPaused != nil {
				m.Hooks.SetLogPaused(m.Logs.Paused)
			}
		}
		orderTip := "按时间倒序"
		if m.Logs.Desc {
			orderTip = "按时间正序"
		}
		if iconButton(c, pal, iconSort, orderTip, "log-order") {
			m.Logs.Desc = !m.Logs.Desc
		}
		if filledButton(c, pal, "清除", "log-clear", true) {
			m.Logs.Lines = nil
			if m.Hooks.ClearLogs != nil {
				m.Hooks.ClearLogs()
			}
		}
	}, func() {
		mygoui.Row(c).Height(39).Padding(8, 10, 4, 10).Gap(8).AlignItems(mygoui.Center).Children(func() {
			cur := logLevelLabel(m.Logs.Level)
			opts := make([]string, 0, 5)
			for _, lv := range clashlog.Levels() {
				opts = append(opts, lv.Label)
			}
			sel := mygoui.Select(c, &cur, opts).Width(120).Label("log-level")
			if sel.Changed() {
				for _, lv := range clashlog.Levels() {
					if lv.Label == cur {
						m.Logs.Level = lv.Value
					}
				}
			}
			searchBox(c, pal, &m.Logs.Query, "logs")
		})
		if len(lines) == 0 {
			emptyState(c, pal)
			return
		}
		mygoui.Column(c).Children(func() {
			for _, line := range lines {
				m.logRow(c, pal, line)
			}
		})
	})
}

func (m *Model) logRow(c *mygoui.Context, pal Palette, line clashlog.Line) {
	mygoui.Column(c).Padding(8, 12).Gap(2).BorderWidth(0, 0, 1, 0).BorderColor(pal.Divider).Children(func() {
		mygoui.Row(c).Gap(8).AlignItems(mygoui.Center).Children(func() {
			mygoui.Text(c, line.Time.Format("01-02 15:04:05")).FontSize(14).TextColor(pal.TextMuted)
			mygoui.Text(c, strings.ToUpper(line.Level)).FontSize(14).FontWeight(600).TextColor(logLevelColor(pal, line.Level))
		})
		mygoui.Row(c).Gap(0).Children(func() {
			for _, span := range query.Spans(m.Logs.Query, line.Payload) {
				t := mygoui.Text(c, span.Text).FontSize(14)
				if span.Hit {
					bg := mygoui.Hex("#FFEB3B").Alpha(0x90 / 255.0)
					if pal.Dark {
						bg = mygoui.Hex("#FFEB3B").Alpha(0x40 / 255.0)
					}
					t.Background(bg).Radius(2).Padding(0, 2)
				}
			}
		})
	})
}

func logLevelLabel(value string) string {
	for _, lv := range clashlog.Levels() {
		if lv.Value == value {
			return lv.Label
		}
	}
	return "ALL"
}

func logLevelColor(pal Palette, level string) mygoui.Color {
	l := strings.ToLower(level)
	switch {
	case strings.Contains(l, "err"):
		return pal.Error
	case strings.Contains(l, "warn"):
		return pal.Warning
	case strings.Contains(l, "inf"):
		return pal.Info
	default:
		return pal.Text
	}
}
