package sitetest

import "testing"

func TestSaveLoadRoundTrip(t *testing.T) {
	s := NewStore(t.TempDir())
	got, err := s.Load()
	if err != nil || got != nil {
		t.Fatalf("missing file %+v %v", got, err)
	}
	items := []Item{{UID: "a", Name: "Google", URL: "https://www.google.com", Icon: "G"}}
	if err := s.Save(items); err != nil {
		t.Fatal(err)
	}
	again, err := NewStore(s.dir).Load()
	if err != nil {
		t.Fatal(err)
	}
	if len(again) != 1 || again[0].Name != "Google" || again[0].URL != items[0].URL || again[0].Icon != "G" {
		t.Fatalf("%+v", again)
	}
}
