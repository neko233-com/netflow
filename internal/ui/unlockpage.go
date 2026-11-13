package ui

import (
	"strconv"
	"strings"
	"time"

	"github.com/neko233-com/netflow/internal/sitetest"
	"github.com/neko233-com/netflow/internal/unlock"

	mygoui "github.com/egoist/mygo/ui"
)

// UnlockItem is one card on the unlock page.
// Delay -1 is untested, -2 is in progress, and >=0 is milliseconds.
type UnlockItem struct {
	Name   string
	Status string
	Region string
	Delay  int
}

// DefaultUnlocks is the 13-card Verge grid, all untested.
func DefaultUnlocks() []UnlockItem {
	names := unlock.Names()
	out := make([]UnlockItem, len(names))
	for i, name := range names {
		out[i] = UnlockItem{Name: name, Delay: -1}
	}
	return out
}

func (m *Model) unlockPage(c *mygoui.Context, pal Palette) {
	if m.Unlocks == nil {
		m.Unlocks = DefaultUnlocks()
	}
	busy := m.unlockBusy()
	m.page(c, pal, "解锁测试", func() {
		if m.unlockAllButton(c, pal, busy) && !busy {
			m.unlockAll()
		}
	}, func() {
		if len(m.Unlocks) == 0 {
			mygoui.Text(c, "暂无解锁测试项目").FontSize(14).TextColor(pal.TextMuted).Padding(24)
			return
		}
		mygoui.Grid(c).Columns(3).Gap(8).Padding(16).Children(func() {
			for i := range m.Unlocks {
				m.unlockCard(c, pal, i)
			}
		})
	})
}

func (m *Model) unlockBusy() bool {
	for _, it := range m.Unlocks {
		if it.Delay == -2 {
			return true
		}
	}
	return false
}

// unlockAllButton is the contained 「测试全部」 control. Idle shows
// RefreshRounded. While any card is running it shows a 16px spinner and
// 「测试中...」, and it does not accept a click.
func (m *Model) unlockAllButton(c *mygoui.Context, pal Palette, busy bool) bool {
	label := "测试全部"
	if busy {
		label = "测试中..."
	}
	filled := len(m.Unlocks) > 0
	b := mygoui.ButtonBase(c.Key("unlock-all")).Height(30).Padding(0, 10).Radius(6).Gap(6).Label("unlock-all")
	b.Disabled(busy || !filled)
	fg := pal.Text
	if filled {
		b.Background(pal.Primary).TextColor(pal.OnPrimary)
		fg = pal.OnPrimary
		if busy {
			b.Opacity(0.7)
		}
	} else {
		b.Background(mygoui.Transparent).TextColor(pal.Text).Border(1, pal.Primary)
	}
	b.Children(func() {
		if busy {
			mygoui.Spinner(c).Size(16, 16).TextColor(fg).Shrink(0).Label("unlock-all-spinner")
		} else {
			mygoui.Icon(c, iconRefresh).Size(18, 18).TextColor(fg).Shrink(0).Label("unlock-all-icon")
		}
		mygoui.Text(c, label).FontSize(13).TextColor(fg).Shrink(0)
	})
	return b.Clicked()
}

func (m *Model) unlockCard(c *mygoui.Context, pal Palette, i int) {
	it := m.Unlocks[i]
	col := mygoui.Column(c.Key("unlock-" + it.Name)).MinHeight(100).Radius(8).FillWidth().Background(pal.Card).Label("unlock-" + it.Name)
	col.BorderWidth(0, 0, 0, 4).BorderColor(unlockTone(pal, it))
	col.Children(func() {
		mygoui.Column(c).Padding(10, 10, 6, 10).Gap(8).Grow(1).FillWidth().Children(func() {
			mygoui.Row(c).FillWidth().AlignItems(mygoui.Center).Children(func() {
				mygoui.Text(c, it.Name).FontSize(16).FontWeight(600).SingleLine().Grow(1)
				m.unlockRefresh(c, pal, i)
			})
			mygoui.Row(c).Gap(8).AlignItems(mygoui.Center).Children(func() {
				m.unlockStatusChip(c, pal, it)
				if it.Region != "" {
					unlockRegionChip(c, pal, it.Region)
				}
			})
		})
		line := mygoui.RGBA(0, 0, 0, 0.2)
		if pal.Dark {
			line = mygoui.RGBA(255, 255, 255, 0.2)
		}
		mygoui.Box(c).Height(1).FillWidth().Margin(0, 8).Shrink(0).BorderWidth(0, 0, 1, 0).BorderStyle(mygoui.BorderDashed).BorderColor(line)
		mygoui.Row(c).FillWidth().Padding(2, 12).Justify(mygoui.End).Shrink(0).Children(func() {
			mygoui.Text(c, unlockTime(it)).FontSize(11).TextColor(pal.TextMuted).SingleLine().Shrink(0)
		})
	})
}

func (m *Model) unlockRefresh(c *mygoui.Context, pal Palette, i int) {
	it := m.Unlocks[i]
	id := "unlock-test-" + it.Name
	spinning := it.Delay == -2
	b := mygoui.ButtonBase(c.Key(id)).Size(32, 32).Radius(16).Shrink(0).Label(id).Tooltip("测试")
	b.Background(mygoui.Transparent).TextColor(pal.Primary).Border(1, pal.Primary)
	if spinning {
		b.Disabled(true).Opacity(0.55)
	}
	b.Children(func() {
		icon := mygoui.Icon(c, iconRefresh).Size(18, 18).TextColor(pal.Primary).Shrink(0)
		if spinning {
			icon.Rotate(icon.Loop("unlock-spin", time.Second, mygoui.Linear) * 360)
		}
	})
	if b.Clicked() {
		m.unlockOne(i)
	}
}

func (m *Model) unlockStatusChip(c *mygoui.Context, pal Palette, it UnlockItem) {
	tone := unlockToneName(it)
	fg := pal.Text
	bg := pal.Text.Alpha(0.08)
	weight := 700
	if tone == ToneMuted || it.Delay == -2 {
		weight = 400
	} else {
		fg = pal.Color(tone)
		bg = fg.Alpha(0.12)
	}
	mygoui.Row(c.Key("unlock-chip-"+it.Name)).Padding(2, 8).Radius(12).Gap(4).Shrink(0).Background(bg).AlignItems(mygoui.Center).Label("unlock-chip-" + it.Name).Children(func() {
		mygoui.Icon(c, unlockStatusIcon(it)).Size(16, 16).TextColor(fg).Shrink(0).Label("unlock-status-" + it.Name)
		mygoui.Text(c, unlockChip(it)).FontSize(12).FontWeight(weight).TextColor(fg).SingleLine()
	})
}

func unlockStatusIcon(it UnlockItem) *mygoui.SVG {
	if it.Delay == -2 || it.Status == "" || it.Status == "Pending" {
		return iconPending
	}
	switch it.Status {
	case "Yes":
		return iconCheck
	case "No":
		return iconCancel
	case "Soon":
		return iconTime
	default:
		return iconStatusHelp
	}
}

func unlockRegionChip(c *mygoui.Context, pal Palette, region string) {
	label := flagEmoji(region)
	if label != "" {
		label += " "
	}
	label += region
	mygoui.Row(c).Padding(1, 6).Radius(10).Shrink(0).AlignItems(mygoui.Center).Border(1, pal.Info).Children(func() {
		mygoui.Text(c, label).FontSize(12).TextColor(pal.Info).SingleLine()
	})
}

func (m *Model) unlockOne(i int) {
	if i < 0 || i >= len(m.Unlocks) || m.Unlocks[i].Delay == -2 {
		return
	}
	m.Unlocks[i].Delay = -2
	m.Unlocks[i].Status = "Pending"
	name := m.Unlocks[i].Name
	if m.Hooks.CheckUnlockAsync != nil {
		m.Hooks.CheckUnlockAsync(name, func(status, region string, ms int, err error) { m.finishUnlock(name, status, region, ms, err) })
		return
	}
	var status, region string
	var ms int
	var err error
	if m.Hooks.CheckUnlock != nil {
		status, region, ms, err = m.Hooks.CheckUnlock(m.Unlocks[i].Name)
	}
	m.finishUnlock(name, status, region, ms, err)
}

func (m *Model) finishUnlock(name, status, region string, ms int, err error) {
	i := -1
	for j := range m.Unlocks {
		if m.Unlocks[j].Name == name {
			i = j
			break
		}
	}
	if i < 0 || m.Unlocks[i].Delay != -2 {
		return
	}
	if err != nil {
		m.Unlocks[i].Delay = -1
		m.Unlocks[i].Status = "Failed"
		if sitetest.IsTimeout(err) {
			m.Notice = "检测超时或失败"
			return
		}
		m.Notice = m.Unlocks[i].Name + " 检测失败"
		return
	}
	if status == "" {
		status = "Yes"
	}
	if ms < 0 {
		ms = 0
	}
	m.Unlocks[i].Status = status
	m.Unlocks[i].Region = region
	m.Unlocks[i].Delay = ms
}

func (m *Model) unlockAll() {
	if m.unlockBusy() || len(m.Unlocks) == 0 {
		return
	}
	for i := range m.Unlocks {
		m.unlockOne(i)
	}
}

func unlockChip(it UnlockItem) string {
	if it.Delay == -2 {
		return "测试中..."
	}
	switch it.Status {
	case "Yes":
		return "支持"
	case "No":
		return "不支持"
	case "Risky":
		return "存疑"
	case "Failed":
		return "测试失败"
	case "Soon":
		return "待检测"
	case "Completed":
		return "检测完成"
	default:
		return "待检测"
	}
}

func unlockTime(it UnlockItem) string {
	if it.Delay == -2 {
		return "测试中..."
	}
	if it.Delay >= 0 && it.Status != "" && it.Status != "Pending" {
		return strconv.Itoa(it.Delay) + " ms"
	}
	return "-- --"
}

func unlockToneName(it UnlockItem) Tone {
	if it.Delay == -2 || it.Status == "" || it.Status == "Pending" {
		return ToneMuted
	}
	switch it.Status {
	case "Yes":
		return ToneSuccess
	case "No", "Failed":
		return ToneError
	case "Risky", "Soon":
		return ToneWarning
	case "Completed":
		return ToneInfo
	default:
		return ToneMuted
	}
}

func unlockTone(pal Palette, it UnlockItem) mygoui.Color {
	return pal.Color(unlockToneName(it))
}

func flagEmoji(region string) string {
	region = strings.ToUpper(strings.TrimSpace(region))
	if len(region) != 2 {
		return ""
	}
	r := []rune(region)
	if r[0] < 'A' || r[0] > 'Z' || r[1] < 'A' || r[1] > 'Z' {
		return ""
	}
	return string(rune(r[0]-'A'+0x1F1E6)) + string(rune(r[1]-'A'+0x1F1E6))
}
