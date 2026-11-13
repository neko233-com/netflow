package profile

import (
	"net/http"
	"testing"
)

func TestParseSubscriptionUserInfo(t *testing.T) {
	t.Parallel()

	standard := http.Header{}
	standard.Set("Subscription-Userinfo", "upload=1; download=2; total=3; expire=4")
	got, ok := ParseSubscriptionUserInfo(standard)
	if !ok {
		t.Fatal("standard header was ignored")
	}
	if got != (Extra{Upload: 1, Download: 2, Total: 3, Expire: 4}) {
		t.Fatalf("extra %+v", got)
	}

	alias := http.Header{}
	alias.Set("x-amz-meta-subscription-userinfo", "upload=9; total=8")
	got, ok = ParseSubscriptionUserInfo(alias)
	if !ok {
		t.Fatal("x-amz-meta-subscription-userinfo was ignored")
	}
	if got != (Extra{Upload: 9, Total: 8}) {
		t.Fatalf("alias extra %+v", got)
	}

	hyphenPrefix := http.Header{}
	hyphenPrefix.Set("foo-subscription-userinfo", "download=7")
	if _, ok := ParseSubscriptionUserInfo(hyphenPrefix); !ok {
		t.Fatal("hyphen prefix was ignored")
	}

	bare := http.Header{}
	bare["subscription-userinfo"] = []string{"expire=42"}
	got, ok = ParseSubscriptionUserInfo(bare)
	if !ok || got.Expire != 42 {
		t.Fatalf("lowercase header ok=%v extra %+v", ok, got)
	}

	missingField := http.Header{}
	missingField.Set("Subscription-Userinfo", "upload=5")
	got, ok = ParseSubscriptionUserInfo(missingField)
	if !ok || got != (Extra{Upload: 5}) {
		t.Fatalf("missing fields %+v ok=%v", got, ok)
	}

	badNumber := http.Header{}
	badNumber.Set("Subscription-Userinfo", "upload=nope; upload=6")
	got, ok = ParseSubscriptionUserInfo(badNumber)
	if !ok || got.Upload != 6 {
		t.Fatalf("invalid then valid upload %+v", got)
	}

	for _, key := range []string{"notsubscription-userinfo", "subscription-userinfo-extra", "x-unrelated"} {
		h := http.Header{}
		h.Set(key, "upload=1")
		if _, ok := ParseSubscriptionUserInfo(h); ok {
			t.Fatalf("header %q matched", key)
		}
	}

	both := http.Header{}
	both.Set("Subscription-Userinfo", "upload=1")
	both.Set("x-amz-meta-subscription-userinfo", "upload=2")
	got, ok = ParseSubscriptionUserInfo(both)
	if !ok || got.Upload != 1 {
		t.Fatalf("exact header should win, got %+v", got)
	}

	if _, ok := ParseSubscriptionUserInfo(nil); ok {
		t.Fatal("nil header matched")
	}
}

func TestParseUpdateInterval(t *testing.T) {
	t.Parallel()
	minutes, ok := ParseUpdateInterval("24")
	if !ok || minutes != 1440 {
		t.Fatalf("24 hours -> %d ok=%v, want 1440", minutes, ok)
	}
	minutes, ok = ParseUpdateInterval("  1 ")
	if !ok || minutes != 60 {
		t.Fatalf("padded 1 -> %d ok=%v", minutes, ok)
	}
	if _, ok := ParseUpdateInterval("0"); !ok {
		t.Fatal("zero hours should be a real interval")
	}
	for _, raw := range []string{"", "   ", "abc", "24.5", "-1", "24h"} {
		if _, ok := ParseUpdateInterval(raw); ok {
			t.Fatalf("%q parsed", raw)
		}
	}
}
