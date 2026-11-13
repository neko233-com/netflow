package conn

import (
	"errors"
	"strconv"
	"testing"
	"time"

	"github.com/neko233-com/netflow/internal/query"
)

func TestTrafficSpacing(t *testing.T) {
	if got := HeaderTraffic(0); got != "0.00B" {
		t.Fatalf("header zero %q", got)
	}
	if got := CellTraffic(0); got != "0.00 B" {
		t.Fatalf("cell zero %q", got)
	}
	if got := Speed(0); got != "0.00 B/s" {
		t.Fatalf("speed zero %q", got)
	}
	v := 12.3 * 1024 * 1024
	n := int64(v)
	num, unit := FormatParts(n)
	if unit != "MB" {
		t.Fatalf("unit %s num %s", unit, num)
	}
	if HeaderTraffic(n) != num+unit {
		t.Fatal("header joined the unit with a space")
	}
	if CellTraffic(n) != num+" "+unit {
		t.Fatalf("cell %q", CellTraffic(n))
	}
	if got := HeaderTraffic(1024); got != "1.00KB" {
		t.Fatalf("1KB header %q", got)
	}
}

func TestFilterIgnoresRuleAndSorts(t *testing.T) {
	base := time.Date(2026, 4, 21, 13, 0, 0, 0, time.UTC)
	items := []Item{
		{ID: "a", Host: "www.google.com", Rule: "MATCH", Process: "Safari", Start: base, DownloadSpeed: 10},
		{ID: "b", Host: "example.com", DestinationIP: "1.1.1.1", Rule: "google", Start: base.Add(time.Second), UploadSpeed: 50},
		{ID: "c", Process: "Google Chrome", Start: base.Add(2 * time.Second), DownloadSpeed: 80},
	}
	got := Filter(items, query.Options{Text: "google"})
	if len(got) != 2 || got[0].ID != "a" || got[1].ID != "c" {
		t.Fatalf("filter %+v", ids(got))
	}
	if len(Filter(items, query.Options{Text: "MATCH"})) != 0 {
		t.Fatal("rule text should not match")
	}
	Sort(items, "default")
	if items[0].ID != "c" || items[2].ID != "a" {
		t.Fatalf("default order %v", ids(items))
	}
	Sort(items, "uploadSpeed")
	if items[0].ID != "b" {
		t.Fatalf("upload order %v", ids(items))
	}
}

func TestLabelsAndTracker(t *testing.T) {
	it := Item{
		Host: "", DestinationIP: "1.1.1.1", DestinationPort: "443",
		Chains: []string{"HK", "Proxy"}, Rule: "Domain", RulePayload: "google.com",
		Type: "HTTPS", Network: "tcp", Process: "Safari", ProcessPath: "/Safari",
		SourceIP: "127.0.0.1", SourcePort: "1",
	}
	if HostLabel(it) != "1.1.1.1:443" || ChainsLabel(it) != "Proxy / HK" {
		t.Fatalf("host %q chains %q", HostLabel(it), ChainsLabel(it))
	}
	if RuleLabel(it) != "Domain(google.com)" || TypeLabel(it) != "HTTPS(tcp)" {
		t.Fatalf("rule %q type %q", RuleLabel(it), TypeLabel(it))
	}
	if ProcessDetail(it) != "Safari(/Safari)" || DestDetail(it) != "1.1.1.1" {
		t.Fatalf("process %q dest %q", ProcessDetail(it), DestDetail(it))
	}
	if SpeedTag(Item{DownloadSpeed: 99}) != "" {
		t.Fatal("slow row showed a speed tag")
	}
	if SpeedTag(Item{DownloadSpeed: 100, UploadSpeed: 0}) == "" {
		t.Fatal("100 B/s should show a tag")
	}

	var tr Tracker
	t0 := time.Date(2026, 4, 21, 0, 0, 0, 0, time.UTC)
	first := tr.Observe([]Item{{ID: "a", Upload: 10, Download: 5}}, 10, 5, t0)
	if first.Active[0].UploadSpeed != 0 || first.Active[0].DownloadSpeed != 0 {
		t.Fatalf("first speed %+v", first.Active[0])
	}
	held := tr.Observe([]Item{{ID: "a", Upload: 99}}, 99, 5, t0.Add(100*time.Millisecond))
	if held.Active[0].Upload != 10 {
		t.Fatalf("sample inside 500ms replaced the snapshot: %+v", held.Active[0])
	}
	second := tr.Observe([]Item{{ID: "a", Upload: 30, Download: 25}}, 30, 25, t0.Add(SampleGap))
	if second.Active[0].UploadSpeed != 20 || second.Active[0].DownloadSpeed != 20 {
		t.Fatalf("delta speed %+v", second.Active[0])
	}
	gone := tr.Observe(nil, 30, 25, t0.Add(2*SampleGap))
	if len(gone.Active) != 0 || len(gone.Closed) != 1 || gone.Closed[0].ID != "a" {
		t.Fatalf("closed %+v", gone)
	}

	var many []Item
	for i := 0; i < ClosedCap+1; i++ {
		many = append(many, Item{ID: "id-" + strconv.Itoa(i)})
	}
	var capTr Tracker
	capTr.Observe(many, 0, 0, t0)
	cleared := capTr.Observe(nil, 0, 0, t0.Add(SampleGap))
	if len(cleared.Closed) != ClosedCap {
		t.Fatalf("cap %d", len(cleared.Closed))
	}

	mem := &Memory{Active: []Item{{ID: "a"}, {ID: "b"}}}
	if err := mem.Close("a"); err != nil || len(mem.Active) != 1 || mem.ClosedIDs[0] != "a" {
		t.Fatalf("close %+v %v", mem, err)
	}
	if err := mem.CloseAll(); err != nil || mem.ClosedAll != 1 || len(mem.Active) != 0 {
		t.Fatalf("close all %+v", mem)
	}
	mem.CloseErr = errors.New("nope")
	if err := mem.CloseAll(); err == nil {
		t.Fatal("expected close error")
	}
}

func TestRelative(t *testing.T) {
	now := time.Date(2026, 4, 21, 12, 0, 0, 0, time.UTC)
	if Relative(now, now.Add(-10*time.Second)) != "几秒前" {
		t.Fatal("seconds")
	}
	if Relative(now, now.Add(-60*time.Second)) != "1 分钟前" {
		t.Fatal("minute")
	}
}

func ids(items []Item) []string {
	out := make([]string, len(items))
	for i, it := range items {
		out[i] = it.ID
	}
	return out
}
