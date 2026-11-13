package profile

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"
)

func TestImportHTTPUserAgentAndMethod(t *testing.T) {
	var gotUA, gotMethod string
	item := importOK(t, "proxies: []\n", nil, ImportOption{}, func(w http.ResponseWriter, r *http.Request) {
		gotUA = r.Header.Get("User-Agent")
		gotMethod = r.Method
	})
	if gotMethod != http.MethodGet {
		t.Fatalf("method %s", gotMethod)
	}
	if gotUA != DefaultUserAgent() || !strings.HasPrefix(gotUA, "clash-go/v") || gotUA == "" {
		t.Fatalf("default UA %q", gotUA)
	}
	if item.Type != "remote" {
		t.Fatalf("type %q", item.Type)
	}
	if item.Extra != nil {
		t.Fatalf("unexpected extra %+v", item.Extra)
	}
}

func TestImportHTTPCustomUserAgent(t *testing.T) {
	old := Version
	Version = "should-not-appear"
	t.Cleanup(func() { Version = old })

	ua := "X"
	var got string
	importOK(t, "proxies: []\n", nil, ImportOption{UserAgent: &ua}, func(w http.ResponseWriter, r *http.Request) {
		got = r.Header.Get("User-Agent")
	})
	if got != "X" {
		t.Fatalf("UA %q, want X", got)
	}
}

func TestImportHTTPVersionInUserAgent(t *testing.T) {
	old := Version
	Version = "9.9.9"
	t.Cleanup(func() { Version = old })
	var got string
	importOK(t, "proxies: []\n", nil, ImportOption{}, func(w http.ResponseWriter, r *http.Request) {
		got = r.Header.Get("User-Agent")
	})
	if got != "clash-go/v9.9.9" {
		t.Fatalf("UA %q", got)
	}
}

func TestImportHTTPDefaultTimeout(t *testing.T) {
	var remain time.Duration
	var hasDeadline bool
	dir := t.TempDir()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("proxies: []\n"))
	}))
	t.Cleanup(srv.Close)
	trip := func(k ProxyKind) (http.RoundTripper, error) {
		if k != ProxyNone {
			t.Errorf("trip kind %s", k)
		}
		return roundTripFunc(func(r *http.Request) (*http.Response, error) {
			deadline, ok := r.Context().Deadline()
			hasDeadline = ok
			remain = time.Until(deadline)
			return http.DefaultTransport.RoundTrip(r)
		}), nil
	}
	if _, err := ImportHTTP(context.Background(), srv.URL+"/sub.yaml", ImportOption{}, dir, trip); err != nil {
		t.Fatal(err)
	}
	if !hasDeadline || remain < 15*time.Second || remain > DefaultTimeoutSeconds*time.Second+time.Second {
		t.Fatalf("deadline ok=%v remain %s, want about %ds", hasDeadline, remain, DefaultTimeoutSeconds)
	}
}

func TestImportHTTPTimeoutWritesNothing(t *testing.T) {
	dir := t.TempDir()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		<-r.Context().Done()
	}))
	t.Cleanup(srv.Close)
	one := 1
	_, err := ImportHTTP(context.Background(), srv.URL, ImportOption{TimeoutSeconds: &one}, dir, directTrip(t))
	if err == nil {
		t.Fatal("timeout succeeded")
	}
	msg := strings.ToLower(err.Error())
	if !strings.Contains(msg, "timeout") && !strings.Contains(msg, "deadline") {
		t.Fatalf("error %q, want a timeout", err)
	}
	assertEmptyDir(t, dir)
}

func TestImportHTTPProxyKind(t *testing.T) {
	body := "proxies: []\n"
	cases := []struct {
		name string
		self bool
		with bool
		want ProxyKind
	}{
		{name: "direct", want: ProxyNone},
		{name: "system", with: true, want: ProxySystem},
		{name: "localhost", self: true, want: ProxyLocalhost},
		{name: "self wins", self: true, with: true, want: ProxyLocalhost},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var got ProxyKind
			dir := t.TempDir()
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				_, _ = w.Write([]byte(body))
			}))
			t.Cleanup(srv.Close)
			trip := func(k ProxyKind) (http.RoundTripper, error) {
				got = k
				return http.DefaultTransport, nil
			}
			_, err := ImportHTTP(context.Background(), srv.URL, ImportOption{SelfProxy: tc.self, WithProxy: tc.with}, dir, trip)
			if err != nil {
				t.Fatal(err)
			}
			if got != tc.want {
				t.Fatalf("kind %s, want %s", got, tc.want)
			}
		})
	}
}

func TestImportHTTPStatusAndYAML(t *testing.T) {
	dir := t.TempDir()
	status := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "nope", http.StatusBadGateway)
	}))
	t.Cleanup(status.Close)
	_, err := ImportHTTP(context.Background(), status.URL, ImportOption{}, dir, directTrip(t))
	if err == nil || !strings.Contains(err.Error(), "502") {
		t.Fatalf("status error %v", err)
	}
	assertEmptyDir(t, dir)

	for _, body := range []string{"::: not yaml\n", "- just\n- a\n- list\n", "hello\n", "mode: rule\n"} {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			_, _ = w.Write([]byte(body))
		}))
		_, err := ImportHTTP(context.Background(), srv.URL, ImportOption{}, dir, directTrip(t))
		srv.Close()
		if err == nil || !strings.Contains(err.Error(), "yaml") && !strings.Contains(err.Error(), "proxies") {
			t.Fatalf("body %q error %v", body, err)
		}
	}
	assertEmptyDir(t, dir)

	providers := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("proxy-providers:\n  sub:\n    type: http\n    url: http://example.com\n"))
	}))
	t.Cleanup(providers.Close)
	if _, err := ImportHTTP(context.Background(), providers.URL, ImportOption{}, t.TempDir(), directTrip(t)); err != nil {
		t.Fatal(err)
	}
}

func TestImportHTTPBOM(t *testing.T) {
	const yamlBody = "proxies:\n  - {name: n1, type: direct}\n"
	item := importOK(t, "\uFEFF"+yamlBody, nil, ImportOption{}, nil)
	if strings.HasPrefix(item.Body, "\uFEFF") {
		t.Fatal("stored body still has a BOM")
	}
	if !strings.Contains(item.Body, "name: n1") {
		t.Fatalf("body %q", item.Body)
	}
}

func TestImportHTTPHeadersIntervalAndHome(t *testing.T) {
	manual := 15
	item := importOK(t, "proxies: []\n", func(h http.Header) {
		h.Set("Subscription-Userinfo", "upload=1; download=2; total=3; expire=4")
		h.Set("profile-update-interval", "24")
		h.Set("profile-web-page-url", "https://example.com/account")
	}, ImportOption{UpdateInterval: &manual}, nil)
	if item.Extra == nil || *item.Extra != (Extra{Upload: 1, Download: 2, Total: 3, Expire: 4}) {
		t.Fatalf("extra %+v", item.Extra)
	}
	if item.Option.UpdateInterval == nil || *item.Option.UpdateInterval != 15 {
		t.Fatalf("manual interval %#v", item.Option.UpdateInterval)
	}
	if item.Home != "https://example.com/account" {
		t.Fatalf("home %q", item.Home)
	}

	fromHeader := importOK(t, "proxies: []\n", func(h http.Header) {
		h.Set("profile-update-interval", "24")
		h.Set("profile-web-page-url", "javascript:alert(1)")
	}, ImportOption{}, nil)
	if fromHeader.Option.UpdateInterval == nil || *fromHeader.Option.UpdateInterval != 1440 {
		t.Fatalf("header interval %#v", fromHeader.Option.UpdateInterval)
	}
	if fromHeader.Home != "" {
		t.Fatalf("illegal home %q", fromHeader.Home)
	}

	ignored := importOK(t, "proxies: []\n", func(h http.Header) {
		h.Set("profile-update-interval", "soon")
		h.Set("profile-web-page-url", "http://")
	}, ImportOption{}, nil)
	if ignored.Option.UpdateInterval != nil {
		t.Fatalf("illegal interval %#v", ignored.Option.UpdateInterval)
	}
	if ignored.Home != "" {
		t.Fatalf("hostless home %q", ignored.Home)
	}
}

func TestImportHTTPName(t *testing.T) {
	encoded := importOK(t, "proxies: []\n", func(h http.Header) {
		h.Set("Content-Disposition", "attachment; filename=\"ignored.yaml\"; filename*=UTF-8''%E8%AE%A2%E9%98%85.yaml")
	}, ImportOption{}, nil)
	if encoded.Name != "订阅.yaml" {
		t.Fatalf("filename* name %q", encoded.Name)
	}

	plain := importOK(t, "proxies: []\n", func(h http.Header) {
		h.Set("Content-Disposition", `attachment; filename="sub.yaml"`)
	}, ImportOption{}, nil)
	if plain.Name != "sub.yaml" {
		t.Fatalf("filename name %q", plain.Name)
	}

	explicit := importOK(t, "proxies: []\n", func(h http.Header) {
		h.Set("Content-Disposition", `attachment; filename="sub.yaml"`)
	}, ImportOption{Name: "Given"}, nil)
	if explicit.Name != "Given" {
		t.Fatalf("explicit name %q", explicit.Name)
	}

	// A disposition with neither filename* nor filename falls through to
	// the URL's last segment (importOK requests /sub.yaml).
	plainAttachment := importOK(t, "proxies: []\n", func(h http.Header) {
		h.Set("Content-Disposition", "attachment")
	}, ImportOption{}, nil)
	if plainAttachment.Name != "sub.yaml" {
		t.Fatalf("url fallback name %q", plainAttachment.Name)
	}
}

func TestImportHTTPNameFromURL(t *testing.T) {
	dir := t.TempDir()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("proxies: []\n"))
	}))
	t.Cleanup(srv.Close)

	item, err := ImportHTTP(context.Background(), srv.URL+"/path/My%20File.yaml?token=1", ImportOption{}, dir, directTrip(t))
	if err != nil {
		t.Fatal(err)
	}
	if item.Name != "My File.yaml" {
		t.Fatalf("url name %q", item.Name)
	}

	root, err := ImportHTTP(context.Background(), srv.URL+"/", ImportOption{}, dir, directTrip(t))
	if err != nil {
		t.Fatal(err)
	}
	if root.Name != "Remote File" {
		t.Fatalf("fallback name %q", root.Name)
	}
}

func TestImportHTTPRemoteFile(t *testing.T) {
	const yamlBody = "proxies:\n  - {name: n1, type: direct}\n"
	dir := t.TempDir()
	now := time.Now().Unix()
	var item Item
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Subscription-Userinfo", "upload=1; download=2; total=3; expire=4")
		_, _ = w.Write([]byte(yamlBody))
	}))
	t.Cleanup(srv.Close)
	var err error
	item, err = ImportHTTP(context.Background(), srv.URL+"/sub.yaml", ImportOption{Description: "d"}, dir, directTrip(t))
	if err != nil {
		t.Fatal(err)
	}
	second, err := ImportHTTP(context.Background(), srv.URL+"/sub.yaml", ImportOption{}, dir, directTrip(t))
	if err != nil {
		t.Fatal(err)
	}
	assertUID(t, "R", item.UID)
	if item.File != item.UID+".yaml" || item.Type != "remote" {
		t.Fatalf("file %q type %q", item.File, item.Type)
	}
	if item.UID == second.UID {
		t.Fatalf("uids collided: %s", item.UID)
	}
	if item.Updated < now-5 || item.Updated > now+5 {
		t.Fatalf("updated %d, now %d", item.Updated, now)
	}
	if item.Desc != "d" || item.URL != srv.URL+"/sub.yaml" {
		t.Fatalf("desc %q url %q", item.Desc, item.URL)
	}
	if !item.Option.AllowAutoUpdate {
		t.Fatal("allow auto update")
	}
	assertUID(t, "m", item.Option.Merge)
	assertUID(t, "s", item.Option.Script)
	assertUID(t, "r", item.Option.Rules)
	assertUID(t, "p", item.Option.Proxies)
	assertUID(t, "g", item.Option.Groups)
	seen := map[string]bool{}
	for _, uid := range []string{item.UID, item.Option.Merge, item.Option.Script, item.Option.Rules, item.Option.Proxies, item.Option.Groups} {
		if seen[uid] {
			t.Fatalf("duplicate uid %s", uid)
		}
		seen[uid] = true
	}
	data, err := os.ReadFile(dir + "/" + item.File)
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != yamlBody {
		t.Fatalf("file %q", data)
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 2 {
		t.Fatalf("dir entries %d, want the two remote files", len(entries))
	}
}

func importOK(t *testing.T, body string, set func(http.Header), opt ImportOption, hit func(http.ResponseWriter, *http.Request)) Item {
	t.Helper()
	dir := t.TempDir()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if set != nil {
			set(w.Header())
		}
		if hit != nil {
			hit(w, r)
		}
		_, _ = w.Write([]byte(body))
	}))
	t.Cleanup(srv.Close)
	item, err := ImportHTTP(context.Background(), srv.URL+"/sub.yaml", opt, dir, directTrip(t))
	if err != nil {
		t.Fatal(err)
	}
	return item
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func directTrip(t *testing.T) func(ProxyKind) (http.RoundTripper, error) {
	t.Helper()
	return func(k ProxyKind) (http.RoundTripper, error) {
		if k != ProxyNone {
			t.Errorf("trip kind %s", k)
		}
		return http.DefaultTransport, nil
	}
}

func assertEmptyDir(t *testing.T, dir string) {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 0 {
		t.Fatalf("dir not empty: %v", entries)
	}
}

func assertUID(t *testing.T, prefix, uid string) {
	t.Helper()
	rest := strings.TrimPrefix(uid, prefix)
	if rest == uid || len(rest) != 11 {
		t.Fatalf("uid %q, want prefix %s plus 11 chars", uid, prefix)
	}
	for _, r := range rest {
		if !strings.ContainsRune(uidAlphabet, r) {
			t.Fatalf("uid %q has %q", uid, r)
		}
	}
}
