package app

import (
	"testing"
	"time"

	mygoui "github.com/egoist/mygo/ui"
	"github.com/neko233-com/netflow/internal/conn"
	"github.com/neko233-com/netflow/internal/ui"
)

func TestLiveTrafficSnapshotReachesNativeChart(t *testing.T) {
	a := &App{model: ui.DemoModel()}
	a.model.Router.Replace("/home")
	a.updateTraffic(conn.Snapshot{UploadSpeed: 4096, DownloadSpeed: 2048}, time.Unix(1000, 0))
	tester := mygoui.NewTester(a.model.View, ui.WindowWidth, 1400)
	if !tester.HasText("峰值 4.00 KB/s") {
		t.Fatal("live sample did not reach the native chart")
	}
}
