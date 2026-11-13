package rules

import (
	"errors"
	"strings"
	"testing"

	"github.com/neko233-com/netflow/internal/query"
)

func TestPolicyColorAndSearch(t *testing.T) {
	if PolicyColor("REJECT") != PolicyError || PolicyColor("REJECT-DROP") != PolicyError {
		t.Fatal("reject color")
	}
	if PolicyColor("DIRECT") != PolicyText {
		t.Fatal("direct color")
	}
	// Proxy = 80+114+111+120+121 = 546, 546%5 = 1 → secondary.
	if PolicyColor("Proxy") != PolicySecondary {
		t.Fatalf("Proxy tone %v", PolicyColor("Proxy"))
	}
	items := Number([]Item{
		{Type: "DomainSuffix", Payload: "google.com", Proxy: "Proxy"},
		{Type: "Match", Payload: "", Proxy: "DIRECT"},
		{Type: "Domain", Payload: "ads.google.com", Proxy: "REJECT"},
	})
	got := Search(items, query.Options{Text: "GOOGLE", MatchCase: true})
	if len(got) != 0 {
		t.Fatal("payload search should be case sensitive when asked")
	}
	got = Search(items, query.Options{Text: "google"})
	if len(got) != 2 || got[0].No != 1 || got[1].No != 3 {
		t.Fatalf("numbers %+v", got)
	}
	if Search(items, query.Options{Text: "DIRECT"}) != nil && len(Search(items, query.Options{Text: "DIRECT"})) != 0 {
		t.Fatal("search should ignore the proxy name")
	}
}

func TestUpdateAllReportsFailure(t *testing.T) {
	mem := &Memory{
		Providers: []Provider{{Name: "b"}, {Name: "a"}},
		Fail:      map[string]error{"b": errors.New("boom")},
	}
	err := mem.UpdateAll()
	if err == nil {
		t.Fatal("expected a failure")
	}
	if strings.Contains(err.Error(), "均已更新") {
		t.Fatalf("failure was reported as success: %v", err)
	}
	if !strings.Contains(err.Error(), "b") || !strings.Contains(err.Error(), "boom") {
		t.Fatalf("error %v", err)
	}
	if len(mem.Updated) != 1 || mem.Updated[0] != "a" {
		t.Fatalf("updated %v", mem.Updated)
	}
	if err := UpdateAll(nil, nil); !errors.Is(err, ErrNoProviders) {
		t.Fatalf("empty %v", err)
	}
	if err := UpdateAll([]string{"a"}, func(string) error { return nil }); err != nil {
		t.Fatal(err)
	}
}
