package sitetest

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestProbeURLUsesClient(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			t.Errorf("method %s", r.Method)
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	t.Cleanup(srv.Close)
	ms, err := ProbeURL(srv.URL, srv.Client())
	if err != nil {
		t.Fatal(err)
	}
	if ms < 0 {
		t.Fatalf("delay %d", ms)
	}
	fail := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadGateway)
	}))
	t.Cleanup(fail.Close)
	if _, err := ProbeURL(fail.URL, fail.Client()); err == nil {
		t.Fatal("502 was a success")
	}
}
