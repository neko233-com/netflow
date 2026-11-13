// Package clashlog is the logs page buffer. It keeps at most 1000 lines
// and flushes a batch every 50ms. Lines in one batch share the timestamp
// of the first line in that batch.
package clashlog

import (
	"strings"
	"time"

	"github.com/neko233-com/netflow/internal/query"
)

const (
	// MaxLines is the frontend cap. Older lines are dropped.
	MaxLines = 1000
	// BatchWindow is how long a batch waits before it is appended.
	BatchWindow = 50 * time.Millisecond
)

// Level is one entry of the level menu. There are five, and no silent.
type Level struct {
	Value string
	Label string
}

// Levels is the log page menu: all / debug / info / warn / err.
func Levels() []Level {
	return []Level{
		{Value: "all", Label: "ALL"},
		{Value: "debug", Label: "DEBUG"},
		{Value: "info", Label: "INFO"},
		{Value: "warn", Label: "WARN"},
		{Value: "err", Label: "ERROR"},
	}
}

// Line is one log row. Level is the kernel value, such as "warning".
type Line struct {
	Time    time.Time
	Level   string
	Payload string
}

// Haystack is the text the search box matches: time, type, and payload.
// It keeps the original case so a case-sensitive query can match it.
func Haystack(line Line) string {
	return line.Time.Format("01-02 15:04:05") + " " + line.Level + " " + line.Payload
}

// LevelMatch reports whether line passes the menu value.
// "warn" matches "warning" and "err" matches "error".
func LevelMatch(filter, level string) bool {
	if filter == "" || filter == "all" {
		return true
	}
	return strings.Contains(strings.ToLower(level), strings.ToLower(filter))
}

// Filter applies the level menu, the search box, and descending order.
func Filter(lines []Line, level string, q query.Options, desc bool) []Line {
	out := make([]Line, 0, len(lines))
	for _, line := range lines {
		if !LevelMatch(level, line.Level) {
			continue
		}
		if q.Active() && !query.Match(q, Haystack(line)) {
			continue
		}
		out = append(out, line)
	}
	if desc {
		for i, j := 0, len(out)-1; i < j; i, j = i+1, j-1 {
			out[i], out[j] = out[j], out[i]
		}
	}
	return out
}

// Buffer collects kernel logs.
type Buffer struct {
	lines   []Line
	pending []Line
	batchAt time.Time
	paused  bool
}

// NewBuffer returns an empty buffer.
func NewBuffer() *Buffer { return &Buffer{} }

// Add queues one log. Paused buffers drop it. A batch shares batchAt.
func (b *Buffer) Add(level, payload string, now time.Time) {
	if b == nil || b.paused {
		return
	}
	if len(b.pending) == 0 {
		b.batchAt = now
	}
	b.pending = append(b.pending, Line{Time: b.batchAt, Level: level, Payload: payload})
}

// Flush appends the pending batch once BatchWindow has passed.
func (b *Buffer) Flush(now time.Time) {
	if b == nil || len(b.pending) == 0 {
		return
	}
	if now.Sub(b.batchAt) < BatchWindow {
		return
	}
	b.lines = append(b.lines, b.pending...)
	b.pending = nil
	b.batchAt = time.Time{}
	if len(b.lines) > MaxLines {
		b.lines = append([]Line(nil), b.lines[len(b.lines)-MaxLines:]...)
	}
}

// Lines returns a copy of the flushed lines.
func (b *Buffer) Lines() []Line {
	if b == nil {
		return nil
	}
	return append([]Line(nil), b.lines...)
}

// SetPaused stops or resumes collection. Paused logs are discarded.
func (b *Buffer) SetPaused(paused bool) {
	if b == nil {
		return
	}
	b.paused = paused
}

// Paused reports the pause flag.
func (b *Buffer) Paused() bool { return b != nil && b.paused }

// Clear drops flushed and pending lines.
func (b *Buffer) Clear() {
	if b == nil {
		return
	}
	b.lines = nil
	b.pending = nil
	b.batchAt = time.Time{}
}
