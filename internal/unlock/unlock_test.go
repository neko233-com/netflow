package unlock

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/neko233-com/netflow/internal/sitetest"
)

func TestCheckParsesJSONAndTimeout(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/hang" {
			time.Sleep(200 * time.Millisecond)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"status":"Yes","region":"HK","delay":12}`))
	}))
	t.Cleanup(srv.Close)
	prev := endpoints["Netflix"]
	t.Cleanup(func() { endpoints["Netflix"] = prev })

	endpoints["Netflix"] = endpoint{url: srv.URL + "/ok"}
	got, err := Check("Netflix", srv.Client())
	if err != nil {
		t.Fatal(err)
	}
	if got.Status != "Yes" || got.Region != "HK" || got.Delay != 12 {
		t.Fatalf("%+v", got)
	}

	endpoints["Netflix"] = endpoint{url: srv.URL + "/hang"}
	slow := &http.Client{Timeout: 30 * time.Millisecond}
	if _, err := Check("Netflix", slow); err == nil || !sitetest.IsTimeout(err) {
		t.Fatalf("timeout err %v", err)
	}
}
