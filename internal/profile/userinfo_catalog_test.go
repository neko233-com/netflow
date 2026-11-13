package profile

import (
	"math"
	"net/http"
	"testing"
)

func TestApplySubscriptionUserInfoHandlesMissingAndOverflow(t *testing.T) {
	item := CatalogItem{Used: 7, Total: 9}
	ApplySubscriptionUserInfo(&item, nil)
	if item.Used != 7 || item.Total != 9 {
		t.Fatal("missing header cleared previous data")
	}
	h := http.Header{"Subscription-Userinfo": []string{"upload=18446744073709551615; download=9; total=18446744073709551615; expire=18446744073709551615"}}
	ApplySubscriptionUserInfo(&item, h)
	if item.Used != math.MaxInt64 || item.Total != math.MaxInt64 || !item.Expire.IsZero() {
		t.Fatalf("unsafe header handling: %+v", item)
	}
	h.Set("Subscription-Userinfo", "upload=12; download=34; total=100; expire=1900000000")
	ApplySubscriptionUserInfo(&item, h)
	if item.Used != 46 || item.Total != 100 || item.Expire.Unix() != 1900000000 {
		t.Fatalf("metadata not parsed: %+v", item)
	}
}
