package ipinfo

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestFetchValidatesResponseAndRequiresExplicitClient(t *testing.T) {
	if _, err := Fetch(context.Background(), nil, "invalid"); err == nil {
		t.Fatal("implicit direct network access accepted")
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"ip":"203.0.113.8","country":"Example","country_code":"EX","asn":64500,"latitude":1.25,"longitude":2.5,"region":"Region","city":"City"}`))
	}))
	defer srv.Close()
	got, err := Fetch(context.Background(), srv.Client(), srv.URL)
	if err != nil || got.IP != "203.0.113.8" || got.ASN != "AS64500" || got.Location != "Region, City" || got.Lat != "1.25" {
		t.Fatalf("result %+v %v", got, err)
	}
}
