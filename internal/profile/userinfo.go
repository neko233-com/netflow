package profile

import (
	"math"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"
)

// Extra is the traffic and expiry block carried on a subscription.
// Missing fields are zero. Upload, download, and total are bytes.
// Expire is a unix timestamp.
type Extra struct {
	Upload   uint64
	Download uint64
	Total    uint64
	Expire   uint64
}

// ApplySubscriptionUserInfo keeps existing values when a response omits the
// header and saturates untrusted byte counts to the catalog's signed range.
func ApplySubscriptionUserInfo(item *CatalogItem, h http.Header) {
	if item == nil {
		return
	}
	info, ok := ParseSubscriptionUserInfo(h)
	if !ok {
		return
	}
	used := info.Upload
	if math.MaxUint64-used < info.Download {
		used = math.MaxUint64
	} else {
		used += info.Download
	}
	if used > math.MaxInt64 {
		used = math.MaxInt64
	}
	total := info.Total
	if total > math.MaxInt64 {
		total = math.MaxInt64
	}
	item.Used, item.Total = int64(used), int64(total)
	item.Expire = time.Time{}
	// Dates beyond year 9999 cannot be encoded as JSON by time.Time.
	if info.Expire > 0 && info.Expire <= 253402300799 {
		item.Expire = time.Unix(int64(info.Expire), 0).UTC()
	}
}

// ParseSubscriptionUserInfo reads the subscription-userinfo header.
// The name match is case-insensitive. The header must end in
// "subscription-userinfo", and any prefix must be empty or end with "-"
// so that "x-amz-meta-subscription-userinfo" matches and
// "notsubscription-userinfo" does not. ok is false when no header matches.
// An exact "subscription-userinfo" wins over a prefixed alias.
func ParseSubscriptionUserInfo(h http.Header) (extra Extra, ok bool) {
	if len(h) == 0 {
		return Extra{}, false
	}
	keys := make([]string, 0, 1)
	for key := range h {
		if subscriptionUserInfoKey(key) {
			keys = append(keys, key)
		}
	}
	if len(keys) == 0 {
		return Extra{}, false
	}
	sort.Strings(keys)
	chosen := keys[0]
	for _, key := range keys {
		if strings.EqualFold(key, "subscription-userinfo") {
			chosen = key
			break
		}
	}
	raw := ""
	if vals := h[chosen]; len(vals) > 0 {
		raw = vals[0]
	}
	return parseExtra(raw), true
}

func subscriptionUserInfoKey(key string) bool {
	prefix, ok := strings.CutSuffix(strings.ToLower(key), "subscription-userinfo")
	if !ok {
		return false
	}
	return prefix == "" || strings.HasSuffix(prefix, "-")
}

func parseExtra(raw string) Extra {
	return Extra{
		Upload:   parseInfoField(raw, "upload"),
		Download: parseInfoField(raw, "download"),
		Total:    parseInfoField(raw, "total"),
		Expire:   parseInfoField(raw, "expire"),
	}
}

// parseInfoField reads key=value pairs separated by ';'. The first value
// that parses wins. A missing or invalid value is 0.
func parseInfoField(raw, key string) uint64 {
	for _, part := range strings.Split(raw, ";") {
		name, value, cut := strings.Cut(strings.TrimSpace(part), "=")
		if !cut || strings.TrimSpace(name) != key {
			continue
		}
		n, err := strconv.ParseUint(strings.TrimSpace(value), 10, 64)
		if err != nil {
			continue
		}
		return n
	}
	return 0
}

// ParseUpdateInterval converts a profile-update-interval header from hours
// to minutes. Illegal numbers are ignored and ok is false. Zero hours is
// a real interval of zero minutes.
func ParseUpdateInterval(raw string) (minutes int, ok bool) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return 0, false
	}
	hours, err := strconv.ParseUint(raw, 10, 64)
	if err != nil {
		return 0, false
	}
	if hours > uint64(math.MaxInt)/60 {
		return 0, false
	}
	return int(hours * 60), true
}
