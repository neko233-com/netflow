package ui

import (
	"image"
	"testing"
	"time"
)

func TestTrafficHistoryIsBoundedAndUsesMeasuredRates(t *testing.T) {
	m := NewModel(demoHome())
	start := time.Unix(1000, 0)
	for i := 0; i < 130; i++ {
		m.RecordTraffic(start.Add(time.Duration(i)*500*time.Millisecond), int64(i*10), int64(i*20))
	}
	m.RecordTraffic(start.Add(-time.Second), 999999, 999999)
	xs, up, down, peak := m.traffic.series()
	if len(xs) != trafficHistoryCapacity || len(up) != len(xs) || len(down) != len(xs) || peak != 2580 || xs[0] <= 0 || xs[len(xs)-1] != 1 {
		t.Fatalf("invalid bounded series: count=%d peak=%d x=%v", len(xs), peak, xs)
	}
	if down[len(down)-1] != 1 || up[len(up)-1] != 0.5 {
		t.Fatalf("measured rates not reflected: %v %v", up[len(up)-1], down[len(down)-1])
	}
}
func chartPixelsDiffer(a, b *image.RGBA, r image.Rectangle) int {
	changed := 0
	for y := r.Min.Y; y < r.Max.Y; y++ {
		for x := r.Min.X; x < r.Max.X; x++ {
			if a.RGBAAt(x, y) != b.RGBAAt(x, y) {
				changed++
			}
		}
	}
	return changed
}
func TestTrafficChartDrawsLiveSeries(t *testing.T) {
	m := DemoModel()
	base := time.Unix(2000, 0)
	for i := 0; i <= 6; i++ {
		m.RecordTraffic(base.Add(time.Duration(i)*10*time.Second), 0, 0)
	}
	tt := renderModel(m, WindowWidth, 1400, false)
	box, ok := tt.Find("traffic-chart")
	if !ok {
		t.Fatal("traffic chart missing")
	}
	old := image.NewRGBA(tt.Image().Bounds())
	copy(old.Pix, tt.Image().Pix)
	for i := 1; i <= 6; i++ {
		rate := int64(i * 2048)
		if i%2 == 0 {
			rate = 0
		}
		m.RecordTraffic(base.Add(time.Duration(60+i*10)*time.Second), rate, rate/2)
	}
	tt.Frame()
	if !tt.HasText("峰值 10.00 KB/s") {
		t.Fatalf("peak does not reflect measured samples: %v", tt.Texts())
	}
	r := image.Rect(int(box.X)+10, int(box.Y)+33, int(box.X+box.W)-10, int(box.Y+box.H)-10).Intersect(old.Bounds())
	if r.Empty() || chartPixelsDiffer(old, tt.Image(), r) < 25 {
		t.Fatal("measured traffic did not change the plotted lines")
	}
	if err := tt.Click("traffic-chart"); err != nil {
		t.Fatal(err)
	}
	if m.ChartSmooth || !tt.HasText("线性") {
		t.Fatal("linear mode did not select the linear curve")
	}
}
