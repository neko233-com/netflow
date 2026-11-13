package app

import (
	"testing"
	"time"

	"github.com/neko233-com/netflow/internal/profile"
)

func TestProfileUpdateDue(t *testing.T) {
	now := time.Date(2026, 1, 2, 0, 0, 0, 0, time.UTC)
	item := profile.CatalogItem{Type: "remote", URL: "https://example.test", Updated: now.Add(-24 * time.Hour), Option: profile.CatalogOption{AllowAutoUpdate: true, UpdateInterval: 1440}}
	if !profileUpdateDue(item, now, time.Time{}) {
		t.Fatal("due subscription was skipped")
	}
	if profileUpdateDue(item, now, now.Add(time.Minute)) {
		t.Fatal("retry backoff ignored")
	}
	item.Updated = now.Add(-time.Hour)
	if profileUpdateDue(item, now, time.Time{}) {
		t.Fatal("subscription updated early")
	}
	item.Option.AllowAutoUpdate = false
	item.Updated = time.Time{}
	if profileUpdateDue(item, now, time.Time{}) {
		t.Fatal("disabled auto update ignored")
	}
	item.Option.AllowAutoUpdate = true
	item.Type = "local"
	if profileUpdateDue(item, now, time.Time{}) {
		t.Fatal("local file scheduled as remote")
	}
}
