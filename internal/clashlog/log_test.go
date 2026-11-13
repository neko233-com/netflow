package clashlog

import (
	"strings"
	"testing"
	"time"

	"github.com/neko233-com/netflow/internal/query"
)

func TestLevelsAndCaseSensitiveSearch(t *testing.T) {
	levels := Levels()
	if len(levels) != 5 {
		t.Fatalf("levels %d", len(levels))
	}
	for _, lv := range levels {
		if strings.EqualFold(lv.Value, "silent") || strings.EqualFold(lv.Label, "SILENT") {
			t.Fatal("silent is not a log page level")
		}
	}
	when := time.Date(2026, 4, 21, 13, 5, 22, 0, time.UTC)
	line := Line{Time: when, Level: "info", Payload: "Google"}
	if Haystack(line) != "04-21 13:05:22 info Google" {
		t.Fatalf("haystack %q", Haystack(line))
	}
	lines := []Line{
		line,
		{Time: when, Level: "warning", Payload: "slow"},
		{Time: when, Level: "error", Payload: "boom"},
		{Time: when, Level: "debug", Payload: "trace"},
	}
	upper := Filter(lines, "all", query.Options{Text: "Google", MatchCase: true}, false)
	if len(upper) != 1 || upper[0].Payload != "Google" {
		t.Fatalf("uppercase match %+v", upper)
	}
	lower := Filter(lines, "all", query.Options{Text: "google", MatchCase: true}, false)
	if len(lower) != 0 {
		t.Fatal("case-sensitive lowercase matched Google")
	}
	if len(Filter(lines, "all", query.Options{Text: "google"}, false)) != 1 {
		t.Fatal("insensitive search missed Google")
	}
	if got := Filter(lines, "warn", query.Options{}, false); len(got) != 1 || got[0].Level != "warning" {
		t.Fatalf("warn %+v", got)
	}
	if got := Filter(lines, "err", query.Options{}, false); len(got) != 1 || got[0].Level != "error" {
		t.Fatalf("err %+v", got)
	}
	desc := Filter(lines, "all", query.Options{}, true)
	if desc[0].Level != "debug" || desc[len(desc)-1].Level != "info" {
		t.Fatalf("desc %+v", desc)
	}
}

func TestBufferBatchesAndCaps(t *testing.T) {
	b := NewBuffer()
	t0 := time.Date(2026, 4, 21, 13, 5, 22, 0, time.UTC)
	b.Add("info", "A", t0)
	b.Add("info", "B", t0.Add(10*time.Millisecond))
	b.Flush(t0.Add(20 * time.Millisecond))
	if len(b.Lines()) != 0 {
		t.Fatal("flushed before 50ms")
	}
	b.Flush(t0.Add(BatchWindow))
	lines := b.Lines()
	if len(lines) != 2 || !lines[0].Time.Equal(lines[1].Time) || !lines[0].Time.Equal(t0) {
		t.Fatalf("batch %+v", lines)
	}
	b.SetPaused(true)
	b.Add("error", "dropped", t0.Add(time.Second))
	b.Flush(t0.Add(time.Second + BatchWindow))
	if len(b.Lines()) != 2 {
		t.Fatal("paused buffer kept a line")
	}
	b.SetPaused(false)
	b.Clear()
	if len(b.Lines()) != 0 {
		t.Fatal("clear")
	}
	for i := 0; i < MaxLines+5; i++ {
		b.Add("info", "n", t0)
	}
	b.Flush(t0.Add(BatchWindow))
	if len(b.Lines()) != MaxLines {
		t.Fatalf("cap %d", len(b.Lines()))
	}
}
