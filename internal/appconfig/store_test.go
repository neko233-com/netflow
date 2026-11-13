package appconfig

import "testing"

func TestFileStoreRoundTrip(t *testing.T) {
	dir := t.TempDir()
	s := NewFileStore(dir)
	got, err := s.Load()
	if err != nil {
		t.Fatal(err)
	}
	if got != (Settings{}) {
		t.Fatalf("missing file loaded %+v", got)
	}
	want := Settings{SystemProxy: true, TUN: true}
	if err := s.Save(want); err != nil {
		t.Fatal(err)
	}
	got, err = s.Load()
	if err != nil {
		t.Fatal(err)
	}
	if got != want {
		t.Fatalf("loaded %+v, want %+v", got, want)
	}
	if s.Dir() != dir {
		t.Fatalf("dir %q", s.Dir())
	}
}

func TestMemoryStore(t *testing.T) {
	m := NewMemory("/cfg")
	if err := m.Save(Settings{SystemProxy: true}); err != nil {
		t.Fatal(err)
	}
	got, err := m.Load()
	if err != nil {
		t.Fatal(err)
	}
	if !got.SystemProxy || got.TUN {
		t.Fatalf("loaded %+v", got)
	}
	if m.Dir() != "/cfg" {
		t.Fatalf("dir %q", m.Dir())
	}
}
