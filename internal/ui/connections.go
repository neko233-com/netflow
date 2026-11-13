package ui

import (
	"time"

	mygoui "github.com/egoist/mygo/ui"

	"github.com/neko233-com/netflow/internal/conn"
	"github.com/neko233-com/netflow/internal/query"
)

// ConnView is the connections page. The default layout is the table.
type ConnView struct {
	Active       []conn.Item
	Closed       []conn.Item
	Up           int64
	Down         int64
	Tab          string
	Layout       string
	Order        string
	Query        query.Options
	Detail       *conn.Item
	DetailClosed bool
	SortField    string
	SortDir      int
	ColHidden    map[string]bool
	ColOrder     []string
	ColsOpen     bool
}

type connColumn struct {
	field string
	title string
	width float32
	right bool
}

func connColumns() []connColumn {
	return []connColumn{
		{"host", "主机", 180, false},
		{"download", "下载量", 76, true},
		{"upload", "上传量", 76, true},
		{"dlSpeed", "下载速度", 76, true},
		{"ulSpeed", "上传速度", 76, true},
		{"chains", "链路", 280, false},
		{"rule", "规则", 220, false},
		{"process", "进程", 180, false},
		{"time", "连接时间", 100, true},
		{"source", "源地址", 160, false},
		{"remoteDestination", "目标地址", 160, false},
		{"type", "类型", 120, false},
	}
}

func (m *Model) connectionsPage(c *mygoui.Context, pal Palette) {
	m.normalizeConns()
	items := m.visibleConns()
	m.page(c, pal, "连接", func() {
		mygoui.Text(c, "下载量: "+conn.HeaderTraffic(m.Conns.Down)).FontSize(13).Shrink(0)
		mygoui.Text(c, "上传量: "+conn.HeaderTraffic(m.Conns.Up)).FontSize(13).Shrink(0)
		// Table shows the control that switches to the list, and the list
		// shows the control that switches back to the table.
		mark := iconTableRows
		tip := "列表视图"
		iconID := "conn-layout-rows"
		if m.Conns.Layout == "list" {
			mark = iconTableChart
			tip = "表格视图"
			iconID = "conn-layout-chart"
		}
		if iconButtonBox(c, pal, mark, tip, "conn-layout", iconID, iconButtonSmall, iconGlyphSmall, iconButtonSmall/2) {
			if m.Conns.Layout == "list" {
				m.Conns.Layout = "table"
			} else {
				m.Conns.Layout = "list"
			}
		}
		if filledButton(c, pal, "关闭全部", "close-all", true) {
			m.closeAllConnections()
		}
	}, func() {
		m.connTools(c, pal, len(items) > 0)
		if len(items) == 0 {
			emptyState(c, pal)
			return
		}
		if m.Conns.Layout == "list" {
			m.connList(c, pal, items, c.Now())
			return
		}
		m.connTable(c, pal, items, c.Now())
	})
	m.connOverlays(c, pal, items, c.Now())
}

func (m *Model) normalizeConns() {
	if m.Conns.Layout == "" {
		m.Conns.Layout = "table"
	}
	if m.Conns.Tab == "" {
		m.Conns.Tab = "active"
	}
	if m.Conns.Order == "" {
		m.Conns.Order = "default"
	}
	if m.Conns.ColHidden == nil {
		m.Conns.ColHidden = map[string]bool{}
	}
}

func (m *Model) connTools(c *mygoui.Context, pal Palette, hasRows bool) {
	mygoui.Row(c).Padding(8, 10, 4, 10).MinHeight(36).Gap(8).AlignItems(mygoui.Center).Children(func() {
		if filledButton(c, pal, "活跃 "+itoa(len(m.Conns.Active)), "conn-active", m.Conns.Tab != "closed") {
			m.Conns.Tab = "active"
			m.Conns.Detail = nil
			m.Conns.ColsOpen = false
		}
		if filledButton(c, pal, "已关闭 "+itoa(len(m.Conns.Closed)), "conn-closed", m.Conns.Tab == "closed") {
			m.Conns.Tab = "closed"
			m.Conns.Detail = nil
			m.Conns.ColsOpen = false
		}
		if m.Conns.Layout == "list" {
			cur := connOrderLabel(m.Conns.Order)
			sel := mygoui.Select(c, &cur, []string{"默认", "上传速度", "下载速度"}).Width(120).Label("conn-order")
			if sel.Changed() {
				m.Conns.Order = connOrderValue(cur)
			}
		}
		searchBox(c, pal, &m.Conns.Query, "conn")
		if m.Conns.Layout != "list" && hasRows {
			if iconButton(c, pal, iconCols, "列设置", "conn-columns") {
				m.Conns.ColsOpen = true
			}
		}
	})
}

func (m *Model) visibleConns() []conn.Item {
	m.normalizeConns()
	src := m.Conns.Active
	if m.Conns.Tab == "closed" {
		src = m.Conns.Closed
	}
	items := conn.Filter(src, m.Conns.Query)
	if m.Conns.Layout == "list" || m.Conns.Query.Active() {
		conn.Sort(items, m.Conns.Order)
	}
	if m.Conns.Layout != "list" {
		conn.SortField(items, m.Conns.SortField, m.Conns.SortDir)
	}
	return items
}

func (m *Model) connTable(c *mygoui.Context, pal Palette, items []conn.Item, now time.Time) {
	cols := m.visibleColumns()
	mygoui.ScrollBoth(c).Grow(1).Children(func() {
		mygoui.Column(c).Children(func() {
			mygoui.Row(c).Shrink(0).Background(pal.Paper).Children(func() {
				for _, col := range cols {
					m.connHeaderCell(c, pal, col)
				}
			})
			for _, it := range items {
				m.connTableRow(c, pal, cols, it, now)
			}
		})
	})
}

func (m *Model) connHeaderCell(c *mygoui.Context, pal Palette, col connColumn) {
	b := mygoui.ButtonBase(c.Key("col-"+col.field)).Width(col.width).Height(32).Padding(0, 8).Label("col-" + col.field)
	b.Background(pal.Paper)
	if col.right {
		b.Justify(mygoui.End)
	} else {
		b.Justify(mygoui.Start)
	}
	b.Children(func() {
		mygoui.Text(c, col.title).FontSize(13).FontWeight(600).TextColor(pal.TextMuted)
		if mark := connSortMark(col.field, m.Conns.SortField, m.Conns.SortDir); mark != "" {
			mygoui.Text(c, mark).FontSize(12).TextColor(pal.TextMuted)
		}
	})
	if b.Clicked() {
		m.cycleColumnSort(col.field)
	}
}

func (m *Model) cycleColumnSort(field string) {
	if m.Conns.SortField != field {
		m.Conns.SortField = field
		m.Conns.SortDir = 1
		return
	}
	m.Conns.SortDir = (m.Conns.SortDir + 1) % 3
	if m.Conns.SortDir == 0 {
		m.Conns.SortField = ""
	}
}

func connSortMark(field, cur string, dir int) string {
	if field != cur {
		return ""
	}
	switch dir {
	case 1:
		return "▲"
	case 2:
		return "▼"
	default:
		return ""
	}
}

func (m *Model) connTableRow(c *mygoui.Context, pal Palette, cols []connColumn, it conn.Item, now time.Time) {
	row := mygoui.ButtonBase(c.Key("conn-" + it.ID)).Label("conn-" + it.ID)
	row.Height(40).BorderWidth(0, 0, 1, 0).BorderColor(pal.Divider)
	row.Children(func() {
		for _, col := range cols {
			cell := mygoui.Row(c).Width(col.width).Padding(0, 8).AlignItems(mygoui.Center)
			if col.right {
				cell.Justify(mygoui.End)
			}
			cell.Children(func() {
				mygoui.Text(c, connCell(it, col.field, now)).FontSize(13).SingleLine()
			})
		}
	})
	if row.Clicked() {
		m.openConn(it)
	}
}

func (m *Model) connList(c *mygoui.Context, pal Palette, items []conn.Item, now time.Time) {
	mygoui.Column(c).Children(func() {
		for _, it := range items {
			m.connListRow(c, pal, it, now)
		}
	})
}

func (m *Model) connListRow(c *mygoui.Context, pal Palette, it conn.Item, now time.Time) {
	mygoui.Row(c).MinHeight(56).Padding(6, 12).Gap(8).AlignItems(mygoui.Center).
		BorderWidth(0, 0, 1, 0).BorderColor(pal.Divider).Children(func() {
		body := mygoui.ButtonBase(c.Key("conn-list-" + it.ID)).Grow(1).Label("conn-list-" + it.ID)
		body.AlignItems(mygoui.Start)
		body.Children(func() {
			mygoui.Column(c).FillWidth().Gap(4).Children(func() {
				mygoui.Text(c, conn.HostLabel(it)).FontSize(14).SingleLine()
				mygoui.Row(c).Gap(4).Children(func() {
					for _, tag := range connTags(it, now) {
						mygoui.Text(c, tag).FontSize(10).Padding(0, 4).Radius(4).Border(1, mygoui.RGBA(128, 128, 128, 0.35))
					}
				})
			})
		})
		if body.Clicked() {
			m.openConn(it)
		}
		if m.Conns.Tab != "closed" && textButton(c, pal, "×", "关闭连接", "conn-close-"+it.ID) {
			m.closeOne(it.ID)
		}
	})
}

func connTags(it conn.Item, now time.Time) []string {
	var tags []string
	if it.Network != "" {
		tags = append(tags, it.Network)
	}
	if it.Type != "" {
		tags = append(tags, it.Type)
	}
	if p := conn.ProcessLabel(it); p != "" {
		tags = append(tags, p)
	}
	if ch := conn.ChainsLabel(it); ch != "" {
		tags = append(tags, ch)
	}
	if rel := conn.Relative(now, it.Start); rel != "" {
		tags = append(tags, rel)
	}
	if speed := conn.SpeedTag(it); speed != "" {
		tags = append(tags, speed)
	}
	return tags
}

func (m *Model) openConn(it conn.Item) {
	if m.Conns.Detail != nil {
		return
	}
	cp := it
	m.Conns.Detail = &cp
	m.Conns.DetailClosed = m.Conns.Tab == "closed"
}

func (m *Model) closeOne(id string) {
	if m.Hooks.CloseConnection != nil {
		if err := m.Hooks.CloseConnection(id); err != nil {
			return
		}
	}
	var kept []conn.Item
	for _, it := range m.Conns.Active {
		if it.ID != id {
			kept = append(kept, it)
			continue
		}
		it.Closed = true
		it.UploadSpeed, it.DownloadSpeed = 0, 0
		m.Conns.Closed = append(m.Conns.Closed, it)
	}
	m.Conns.Active = kept
	if m.Conns.Detail != nil && m.Conns.Detail.ID == id {
		m.Conns.Detail = nil
	}
}

func (m *Model) closeAllConnections() {
	if m.Hooks.CloseAllConnections != nil {
		if err := m.Hooks.CloseAllConnections(); err != nil {
			return
		}
	}
	for _, it := range m.Conns.Active {
		it.Closed = true
		it.UploadSpeed, it.DownloadSpeed = 0, 0
		m.Conns.Closed = append(m.Conns.Closed, it)
	}
	m.Conns.Active = nil
	if m.Conns.Detail != nil && !m.Conns.DetailClosed {
		m.Conns.Detail = nil
	}
}

func (m *Model) clearClosed() {
	m.Conns.Closed = nil
	if m.Conns.DetailClosed {
		m.Conns.Detail = nil
	}
	if m.Hooks.ClearClosed != nil {
		m.Hooks.ClearClosed()
	}
}

func (m *Model) connOverlays(c *mygoui.Context, pal Palette, items []conn.Item, now time.Time) {
	showFab := m.Conns.Tab == "closed" && len(items) > 0
	if m.Conns.Detail == nil && !showFab {
		return
	}
	mygoui.Overlay(c, func() {
		if m.Conns.Detail != nil {
			m.connDetail(c, pal, now)
		}
		if showFab {
			bottom := float32(16)
			if m.Conns.Layout != "list" {
				bottom = 70
			}
			b := mygoui.ButtonBase(c.Key("clear-closed")).Absolute().Right(16).Bottom(bottom).Height(36).Padding(0, 12).Radius(18).Label("clear-closed")
			b.Background(pal.Primary).TextColor(pal.OnPrimary)
			b.Children(func() { mygoui.Text(c, "清除").FontSize(13) })
			if b.Clicked() {
				m.clearClosed()
			}
		}
	})
}

func (m *Model) connDetail(c *mygoui.Context, pal Palette, now time.Time) {
	it := *m.Conns.Detail
	box := mygoui.Column(c).Absolute().Right(16).Bottom(16).Width(360).MaxHeight(480).Padding(12).Gap(4).Radius(8).Background(pal.Paper).Label("conn-detail")
	box.Children(func() {
		rows := []struct{ label, value string }{
			{"主机", hostDetail(it)},
			{"下载量", conn.CellTraffic(it.Download)},
			{"上传量", conn.CellTraffic(it.Upload)},
			{"下载速度", conn.Speed(it.DownloadSpeed)},
			{"上传速度", conn.Speed(it.UploadSpeed)},
			{"链路", conn.ChainsLabel(it)},
			{"规则", conn.RuleLabel(it)},
			{"进程", conn.ProcessDetail(it)},
			{"连接时间", conn.Relative(now, it.Start)},
			{"源地址", conn.SourceLabel(it)},
			{"目标地址", conn.DestDetail(it)},
			{"目标端口", it.DestinationPort},
			{"类型", conn.TypeLabel(it)},
		}
		for _, row := range rows {
			mygoui.Row(c).Gap(6).Children(func() {
				mygoui.Text(c, row.label+":").FontSize(13).Bold().TextColor(pal.TextMuted).Shrink(0)
				mygoui.Text(c, row.value).FontSize(13).Grow(1)
			})
		}
		mygoui.Row(c).Justify(mygoui.End).Gap(8).Padding(8, 0, 0, 0).Children(func() {
			if textButton(c, pal, "关闭", "关闭", "detail-away") {
				m.Conns.Detail = nil
			}
			if !m.Conns.DetailClosed && filledButton(c, pal, "关闭连接", "conn-detail-close", true) {
				m.closeOne(it.ID)
			}
		})
	})
}

func hostDetail(it conn.Item) string {
	host := it.Host
	if host == "" {
		host = it.DestinationIP
	}
	if host == "" {
		host = it.RemoteDestination
	}
	if it.DestinationPort == "" {
		return host
	}
	if host == "" {
		return ":" + it.DestinationPort
	}
	return host + ":" + it.DestinationPort
}

func (m *Model) visibleColumns() []connColumn {
	cols := connColumns()
	if len(m.Conns.ColOrder) > 0 {
		by := map[string]connColumn{}
		for _, col := range cols {
			by[col.field] = col
		}
		var ordered []connColumn
		seen := map[string]bool{}
		for _, field := range m.Conns.ColOrder {
			if col, ok := by[field]; ok && !seen[field] {
				ordered = append(ordered, col)
				seen[field] = true
			}
		}
		for _, col := range cols {
			if !seen[col.field] {
				ordered = append(ordered, col)
			}
		}
		cols = ordered
	}
	var vis []connColumn
	for _, col := range cols {
		if !m.Conns.ColHidden[col.field] {
			vis = append(vis, col)
		}
	}
	if len(vis) == 0 && len(cols) > 0 {
		return cols[:1]
	}
	return vis
}

func (m *Model) connColumnDialog(c *mygoui.Context, pal Palette) {
	if !m.Conns.ColsOpen {
		return
	}
	mygoui.Modal(c, &m.Conns.ColsOpen, func() {
		mygoui.Column(c).Width(360).Padding(16).Gap(8).Background(pal.Dialog).Radius(8).Children(func() {
			mygoui.Text(c, "列设置").FontSize(18).Bold()
			visible := 0
			for _, col := range connColumns() {
				if !m.Conns.ColHidden[col.field] {
					visible++
				}
			}
			for _, col := range connColumns() {
				field := col.field
				title := col.title
				on := !m.Conns.ColHidden[field]
				mygoui.Row(c).Padding(4, 8).Radius(4).Border(1, pal.Divider).AlignItems(mygoui.Center).Gap(8).Children(func() {
					box := mygoui.Checkbox(c, &on, title).Label("col-vis-" + field)
					if visible <= 1 && on {
						box.Disabled(true)
					}
					if box.Changed() {
						if m.Conns.ColHidden == nil {
							m.Conns.ColHidden = map[string]bool{}
						}
						if on {
							delete(m.Conns.ColHidden, field)
						} else if visible > 1 {
							m.Conns.ColHidden[field] = true
						}
					}
					mygoui.Spacer(c).Grow(1)
					mygoui.Text(c, "↕").FontSize(14).TextColor(pal.TextMuted).Tooltip("拖拽控件")
				})
			}
			mygoui.Row(c).Gap(8).Justify(mygoui.End).Children(func() {
				if textButton(c, pal, "重置为默认值", "重置为默认值", "cols-reset") {
					m.Conns.ColHidden = map[string]bool{}
					m.Conns.ColOrder = nil
					m.Conns.SortField = ""
					m.Conns.SortDir = 0
				}
				if filledButton(c, pal, "关闭", "cols-close", true) {
					m.Conns.ColsOpen = false
				}
			})
		})
	})
}

func connCell(it conn.Item, field string, now time.Time) string {
	switch field {
	case "host":
		return conn.HostLabel(it)
	case "download":
		return conn.CellTraffic(it.Download)
	case "upload":
		return conn.CellTraffic(it.Upload)
	case "dlSpeed":
		return conn.Speed(it.DownloadSpeed)
	case "ulSpeed":
		return conn.Speed(it.UploadSpeed)
	case "chains":
		return conn.ChainsLabel(it)
	case "rule":
		return conn.RuleLabel(it)
	case "process":
		return conn.ProcessLabel(it)
	case "time":
		return conn.Relative(now, it.Start)
	case "source":
		return conn.SourceLabel(it)
	case "remoteDestination":
		return conn.DestLabel(it)
	case "type":
		return conn.TypeLabel(it)
	default:
		return ""
	}
}

func connOrderLabel(v string) string {
	switch v {
	case "uploadSpeed":
		return "上传速度"
	case "downloadSpeed":
		return "下载速度"
	default:
		return "默认"
	}
}

func connOrderValue(label string) string {
	switch label {
	case "上传速度":
		return "uploadSpeed"
	case "下载速度":
		return "downloadSpeed"
	default:
		return "default"
	}
}
