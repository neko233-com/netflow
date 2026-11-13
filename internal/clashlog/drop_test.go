package clashlog

import (
	"strconv"
	"testing"
	"time"
)

// TestBufferDropsOldest checks which lines survive the 1000 cap.
// TestBufferBatchesAndCaps only checks the length, and every payload there
// is the same word, so a buffer that dropped the newest lines would still pass.
func TestBufferDropsOldest(t *testing.T) {
	b := NewBuffer()
	t0 := time.Date(2026, 4, 21, 13, 5, 22, 0, time.UTC)
	const extra = 5
	n := MaxLines + extra
	for i := 0; i < n; i++ {
		b.Add("info", strconv.Itoa(i), t0)
	}
	b.Flush(t0.Add(BatchWindow))
	lines := b.Lines()
	if len(lines) != MaxLines {
		t.Fatalf("len %d, want %d", len(lines), MaxLines)
	}
	if lines[0].Payload != strconv.Itoa(extra) {
		t.Fatalf("oldest kept line %q, want %d (the first %d lines should be gone)", lines[0].Payload, extra, extra)
	}
	if lines[len(lines)-1].Payload != strconv.Itoa(n-1) {
		t.Fatalf("newest line %q, want %d", lines[len(lines)-1].Payload, n-1)
	}
}
