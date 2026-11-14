package ui

import (
	"time"

	mygoui "github.com/egoist/mygo/ui"
	"github.com/egoist/mygo/ui/chart"
)

const trafficHistoryCapacity = 120
const trafficHistoryWindow = time.Minute

type trafficPoint struct {
	At               time.Time
	Upload, Download int64
}
type trafficHistory struct {
	points               [trafficHistoryCapacity]trafficPoint
	xs, upload, download [trafficHistoryCapacity]float32
	upPath, downPath     mygoui.Path
	next, count          int
}

// RecordTraffic keeps the most recent 60 seconds of measured byte rates in a
// bounded ring. Calls and rendering run on the application event loop.
func (m *Model) RecordTraffic(at time.Time, upload, download int64) {
	if m == nil || at.IsZero() {
		return
	}
	h := &m.traffic
	if h.count > 0 {
		last := h.points[(h.next-1+len(h.points))%len(h.points)]
		if !at.After(last.At) {
			return
		}
	}
	if upload < 0 {
		upload = 0
	}
	if download < 0 {
		download = 0
	}
	h.points[h.next] = trafficPoint{At: at, Upload: upload, Download: download}
	h.next = (h.next + 1) % len(h.points)
	if h.count < len(h.points) {
		h.count++
	}
}

func (h *trafficHistory) series() (xs, up, down []float32, peak int64) {
	if h == nil || h.count == 0 {
		return nil, nil, nil, 0
	}
	end := h.points[(h.next-1+len(h.points))%len(h.points)].At
	start := end.Add(-trafficHistoryWindow)
	for i := 0; i < h.count; i++ {
		point := h.points[(h.next-h.count+i+len(h.points))%len(h.points)]
		if !point.At.Before(start) {
			if point.Upload > peak {
				peak = point.Upload
			}
			if point.Download > peak {
				peak = point.Download
			}
		}
	}
	scale := peak
	if scale < 1024 {
		scale = 1024
	}
	n := 0
	for i := 0; i < h.count; i++ {
		point := h.points[(h.next-h.count+i+len(h.points))%len(h.points)]
		if point.At.Before(start) {
			continue
		}
		h.xs[n] = float32(point.At.Sub(start).Seconds() / trafficHistoryWindow.Seconds())
		h.upload[n] = float32(float64(point.Upload) / float64(scale))
		h.download[n] = float32(float64(point.Download) / float64(scale))
		n++
	}
	return h.xs[:n], h.upload[:n], h.download[:n], peak
}

func (m *Model) trafficGraph(c *mygoui.Context, pal Palette) {
	xs, up, down, peak := m.traffic.series()
	style := "平滑"
	curve := chart.CurveMonotone
	if !m.ChartSmooth {
		style = "线性"
		curve = chart.CurveLinear
	}
	box := mygoui.ButtonBase(c.Key("traffic-chart")).FillWidth().Height(130).Radius(8).Label("traffic-chart")
	box.Border(1, pal.Divider).AlignItems(mygoui.Start).Justify(mygoui.Start)
	box.Draw(func(p *mygoui.Painter, r mygoui.Rect) {
		area := mygoui.Rect{X: r.X + 10, Y: r.Y + 32, W: r.W - 20, H: r.H - 42}
		if area.W <= 0 || area.H <= 0 {
			return
		}
		for i := 0; i <= 4; i++ {
			y := area.Y + area.H*float32(i)/4
			p.Line(area.X, y, area.X+area.W, y, 1, pal.Divider)
		}
		p.Clip(area, 0, func() {
			if len(xs) == 1 {
				p.Fill(mygoui.Rect{X: chart.X(area, xs[0]) - 2, Y: chart.Y(area, up[0]) - 2, W: 4, H: 4}, pal.Secondary, 2)
				p.Fill(mygoui.Rect{X: chart.X(area, xs[0]) - 2, Y: chart.Y(area, down[0]) - 2, W: 4, H: 4}, pal.Primary, 2)
			} else if len(xs) > 1 {
				p.StrokePath(chart.LineInto(&m.traffic.upPath, area, xs, up, curve), 2, pal.Secondary)
				p.StrokePath(chart.LineInto(&m.traffic.downPath, area, xs, down, curve), 2, pal.Primary)
			}
		})
	})
	box.Children(func() {
		mygoui.Row(c).FillWidth().Padding(4, 8).Gap(10).AlignItems(mygoui.Center).Children(func() {
			mygoui.Text(c, "上传").FontSize(12).TextColor(pal.Secondary)
			mygoui.Text(c, "下载").FontSize(12).TextColor(pal.Primary)
			if len(xs) == 0 {
				mygoui.Text(c, "等待数据").FontSize(12).TextColor(pal.TextMuted)
			} else {
				mygoui.Text(c, "峰值 "+FormatSpeed(peak)).FontSize(12).TextColor(pal.TextMuted)
			}
			mygoui.Spacer(c).Grow(1)
			mygoui.Text(c, style).FontSize(12).TextColor(pal.TextMuted)
		})
	})
	if box.Clicked() {
		m.ChartSmooth = !m.ChartSmooth
	}
}
