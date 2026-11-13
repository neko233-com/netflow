package query

import "testing"

func TestMatchCaseIsNotFoldedFirst(t *testing.T) {
	field := "04-21 13:05:22 info Google"
	upper := Options{Text: "Google", MatchCase: true}
	lower := Options{Text: "google", MatchCase: true}
	folded := Options{Text: "google", MatchCase: false}
	if !Match(upper, field) {
		t.Fatal("uppercase query should match uppercase text")
	}
	if Match(lower, field) {
		t.Fatal("case-sensitive lowercase query matched uppercase text")
	}
	if !Match(folded, field) {
		t.Fatal("case-insensitive query should match")
	}
	if !Match(Options{}, field) {
		t.Fatal("empty query matches")
	}
	if Match(Options{Text: "(", Regex: true}, field) {
		t.Fatal("invalid regex should match nothing")
	}
}

func TestWholeWordAndHighlight(t *testing.T) {
	if Match(Options{Text: "go", Whole: true}, "google") {
		t.Fatal("whole word matched inside google")
	}
	if !Match(Options{Text: "go", Whole: true}, "use go now") {
		t.Fatal("whole word missed a word")
	}
	spans := Spans(Options{Text: "Google", MatchCase: true}, "via Google now")
	if len(spans) != 3 || !spans[1].Hit || spans[1].Text != "Google" {
		t.Fatalf("spans %+v", spans)
	}
}
