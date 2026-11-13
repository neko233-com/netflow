package update

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestCheckSelectsCorrectReleaseChannel(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`[{"tag_name":"v2.0.0-alpha.1","prerelease":true},{"tag_name":"v1.9.0"},{"tag_name":"v9.0.0","draft":true},{"tag_name":"invalid"}]`))
	}))
	defer srv.Close()
	stable, err := Check(context.Background(), srv.Client(), srv.URL, "1.8.0")
	if err != nil || stable.Latest != "v1.9.0" || !stable.Available {
		t.Fatalf("stable: %+v %v", stable, err)
	}
	preview, err := Check(context.Background(), srv.Client(), srv.URL, "1.8.0-alpha.1")
	if err != nil || preview.Latest != "v2.0.0-alpha.1" || preview.URL != ReleaseBase+"v2.0.0-alpha.1" {
		t.Fatalf("preview: %+v %v", preview, err)
	}
	if _, err = Check(context.Background(), srv.Client(), srv.URL, "bad"); err == nil {
		t.Fatal("invalid current version accepted")
	}
}
