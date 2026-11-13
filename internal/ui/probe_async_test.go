package ui

import "testing"

func TestAsyncSiteResultsFollowIdentityAndIgnoreEditedURL(t *testing.T) {
	m := NewModel(HomeState{})
	m.Sites = []SiteTest{{UID: "one", Name: "A", URL: "https://a.test", Delay: -1}, {UID: "two", Name: "B", URL: "https://b.test", Delay: -1}}
	callbacks := map[string]func(int, error){}
	m.Hooks.ProbeSiteAsync = func(url string, done func(int, error)) { callbacks[url] = done }
	m.probeAll()
	if len(callbacks) != 2 || !m.sitesBusy() {
		t.Fatal("probes did not start asynchronously")
	}
	m.Sites[0], m.Sites[1] = m.Sites[1], m.Sites[0]
	callbacks["https://a.test"](123, nil)
	if m.Sites[1].Delay != 123 || m.Sites[0].Delay != -2 {
		t.Fatalf("result went to wrong site: %+v", m.Sites)
	}
	m.TestForm = TestForm{UID: "two", Name: "B", URL: "https://new.test"}
	m.saveTestForm()
	callbacks["https://b.test"](42, nil)
	if m.Sites[0].Delay != -1 || m.Sites[0].Status != "" {
		t.Fatalf("old result replaced edited site: %+v", m.Sites[0])
	}
}

func TestAsyncUnlockAllPublishesResultsIndividually(t *testing.T) {
	m := NewModel(HomeState{})
	m.Unlocks = []UnlockItem{{Name: "A", Delay: -1}, {Name: "B", Delay: -1}}
	callbacks := map[string]func(string, string, int, error){}
	m.Hooks.CheckUnlockAsync = func(name string, done func(string, string, int, error)) { callbacks[name] = done }
	m.unlockAll()
	if len(callbacks) != 2 || !m.unlockBusy() {
		t.Fatal("unlock checks did not start asynchronously")
	}
	callbacks["B"]("No", "", 20, nil)
	if m.Unlocks[1].Status != "No" || m.Unlocks[0].Delay != -2 {
		t.Fatal("result applied to wrong card")
	}
	callbacks["A"]("Yes", "US", 10, nil)
	if m.unlockBusy() || m.Unlocks[0].Region != "US" {
		t.Fatal("pending state did not clear")
	}
}
