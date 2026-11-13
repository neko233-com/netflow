package ui

import (
	"fmt"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"golang.org/x/text/collate"
	"golang.org/x/text/language"
)

const (
	// DelayTimeout is DEFAULT_DELAY_TIMEOUT.
	DelayTimeout = 10000
	// DelayTesting is the in-progress sentinel (-2).
	DelayTesting = -2
	// FilterDebounce is how long a proxy filter waits before it applies.
	FilterDebounce = 600 * time.Millisecond
	// HoverJumpDelay is the default letter-nav hover delay.
	HoverJumpDelay = 280
	// AutoProxyColumns is the misc value that means "follow the width".
	AutoProxyColumns = 6
)

// DelayKind is how a measured delay is shown on a node row.
// Thresholds are the chip scale (250/400), not the home signal scale.
type DelayKind uint8

const (
	DelayUntested DelayKind = iota
	DelayPending
	DelayError
	DelayTimedOut
	DelayHigh
	DelayMid
	DelayLow
)

// ClassifyDelay maps a millisecond measurement onto the node-row chip.
// timeout is the configured ceiling; values below 1 use DelayTimeout.
func ClassifyDelay(ms, timeout int) DelayKind {
	if timeout <= 0 {
		timeout = DelayTimeout
	}
	switch {
	case ms == DelayTesting:
		return DelayPending
	case ms < 0:
		return DelayUntested
	case ms > 100000:
		return DelayError
	case ms == 0 || ms >= timeout:
		return DelayTimedOut
	case ms >= 400:
		return DelayHigh
	case ms >= 250:
		return DelayMid
	default:
		return DelayLow
	}
}

// DelayText is the chip label. Testing/Error/Timeout keep the source's
// English literals; a real measurement is the millisecond number.
func DelayText(ms, timeout int) string {
	switch ClassifyDelay(ms, timeout) {
	case DelayPending:
		return "testing"
	case DelayError:
		return "Error"
	case DelayTimedOut:
		return "Timeout"
	case DelayUntested:
		return "-"
	default:
		return strconv.Itoa(ms)
	}
}

// DelayTone is the chip color.
func DelayTone(ms, timeout int) Tone {
	switch ClassifyDelay(ms, timeout) {
	case DelayError, DelayTimedOut:
		return ToneError
	case DelayHigh:
		return ToneWarning
	case DelayMid:
		return TonePrimary
	case DelayLow:
		return ToneSuccess
	default:
		return ToneMuted
	}
}

// SignalKind is the home current-node scale (200/300/500/10000).
type SignalKind uint8

const (
	SignalNone SignalKind = iota
	SignalTesting
	SignalUntested
	SignalError
	SignalTimeout
	SignalHigh
	SignalMedium
	SignalGood
	SignalExcellent
)

// ClassifySignal maps a delay onto the home signal tiers.
func ClassifySignal(ms int) SignalKind {
	switch {
	case ms == DelayTesting:
		return SignalTesting
	case ms < 0:
		return SignalUntested
	case ms > 100000:
		return SignalError
	case ms == 0 || ms >= DelayTimeout:
		return SignalTimeout
	case ms >= 500:
		return SignalHigh
	case ms >= 300:
		return SignalMedium
	case ms >= 200:
		return SignalGood
	default:
		return SignalExcellent
	}
}

// SignalLabel is the Chinese status next to the signal mark.
func SignalLabel(ms int) string {
	switch ClassifySignal(ms) {
	case SignalTesting:
		return "测试中"
	case SignalUntested:
		return "未测试"
	case SignalError:
		return "错误"
	case SignalTimeout:
		return "超时"
	case SignalHigh:
		return "延迟较高"
	case SignalMedium:
		return "延迟中等"
	case SignalGood:
		return "延迟良好"
	case SignalExcellent:
		return "延迟极佳"
	default:
		return "无代理节点"
	}
}

// SignalTone colors the signal mark.
func SignalTone(ms int) Tone {
	switch ClassifySignal(ms) {
	case SignalError, SignalTimeout, SignalHigh:
		return ToneError
	case SignalMedium:
		return ToneWarning
	case SignalGood:
		return ToneInfo
	case SignalExcellent:
		return ToneSuccess
	default:
		return ToneMuted
	}
}

// SignalBars is how many of four bars are filled.
func SignalBars(ms int) int {
	switch ClassifySignal(ms) {
	case SignalExcellent:
		return 4
	case SignalGood:
		return 3
	case SignalMedium:
		return 2
	case SignalHigh, SignalError, SignalTimeout:
		return 1
	default:
		return 0
	}
}

// FormatUptime renders H:MM:SS. Hours are not padded; minutes and seconds are.
func FormatUptime(d time.Duration) string {
	if d < 0 {
		d = 0
	}
	d = d.Truncate(time.Second)
	h := int(d / time.Hour)
	m := int(d % time.Hour / time.Minute)
	s := int(d % time.Minute / time.Second)
	return fmt.Sprintf("%d:%02d:%02d", h, m, s)
}

// FormatTraffic renders a byte count as B / KB / MB / GB / TB.
func FormatTraffic(n int64) string {
	if n < 0 {
		n = 0
	}
	units := []string{"B", "KB", "MB", "GB", "TB", "PB"}
	v := float64(n)
	i := 0
	for v >= 1024 && i < len(units)-1 {
		v /= 1024
		i++
	}
	if i == 0 {
		return fmt.Sprintf("%d %s", n, units[0])
	}
	return fmt.Sprintf("%.2f %s", v, units[i])
}

// FormatSpeed appends /s, as the traffic card does.
func FormatSpeed(bytesPerSec int64) string {
	return FormatTraffic(bytesPerSec) + "/s"
}

// WideLayout reports whether home and settings use two columns.
// The breakpoint is the window width, md = 900.
func WideLayout(windowWidth float32) bool { return windowWidth >= BreakpointMD }

// ProxyColumns is the node grid width. configured 1–5 is fixed.
// 6 and anything else follow body width: >1920→5, >1450→4, >1024→3, ≥600→2, else 1.
func ProxyColumns(bodyWidth float32, configured int) int {
	if configured >= 1 && configured <= 5 {
		return configured
	}
	switch {
	case bodyWidth > 1920:
		return 5
	case bodyWidth > 1450:
		return 4
	case bodyWidth > 1024:
		return 3
	case bodyWidth >= 600:
		return 2
	default:
		return 1
	}
}

// ContentWidth estimates the page body inside an expanded 200px sidebar.
func ContentWidth(windowWidth float32) float32 {
	return contentWidth(windowWidth, sidebarExpandedWidth)
}

func contentWidth(windowWidth, sidebar float32) float32 {
	w := windowWidth - sidebar
	if w < 0 {
		return 0
	}
	return w
}

// ProfileColumns is how many subscription cards fit.
// Cards stay between 260 and 480, at most four across.
func ProfileColumns(contentWidth float32) int {
	if contentWidth <= 0 {
		return 1
	}
	n := int(contentWidth / 268)
	if n < 1 {
		n = 1
	}
	if n > 4 {
		n = 4
	}
	for n > 1 && contentWidth/float32(n) > 480 {
		n--
	}
	return n
}

// GroupSelectEnabled is false in global and direct mode.
func GroupSelectEnabled(mode string) bool { return mode == "rule" }

// NodeSelectEnabled is false in direct mode.
func NodeSelectEnabled(mode string) bool { return mode != "direct" }

// DelayTestEnabled is false in direct mode or when no node is selected.
func DelayTestEnabled(mode string, hasNode bool) bool {
	return mode != "direct" && hasNode
}

// SearchOpts are the three search-box switches.
type SearchOpts struct {
	MatchCase bool
	WholeWord bool
	Regex     bool
}

var (
	delayQuery = regexp.MustCompile(`(?i)^delay([=<>])(\d+|timeout|error)$`)
	typeQuery  = regexp.MustCompile(`(?i)^type=(.*)$`)
)

// FilterNodes applies one proxy-group query. An empty query keeps order.
// An invalid regular expression matches nothing.
func FilterNodes(nodes []ProxyNode, query string, opt SearchOpts, timeout int) []ProxyNode {
	query = strings.TrimSpace(query)
	if query == "" {
		return append([]ProxyNode(nil), nodes...)
	}
	if timeout <= 0 {
		timeout = DelayTimeout
	}
	if m := delayQuery.FindStringSubmatch(query); m != nil {
		return filterDelay(nodes, m[1], m[2], timeout)
	}
	if m := typeQuery.FindStringSubmatch(query); m != nil {
		want := strings.ToLower(m[1])
		var out []ProxyNode
		for _, n := range nodes {
			if strings.Contains(strings.ToLower(n.Type), want) {
				out = append(out, n)
			}
		}
		return out
	}
	var re *regexp.Regexp
	if opt.Regex {
		pat := query
		if !opt.MatchCase {
			pat = "(?i)" + pat
		}
		compiled, err := regexp.Compile(pat)
		if err != nil {
			return nil
		}
		re = compiled
	}
	var out []ProxyNode
	for _, n := range nodes {
		if nameMatch(n.Name, query, opt, re) {
			out = append(out, n)
		}
	}
	return out
}

func filterDelay(nodes []ProxyNode, op, raw string, timeout int) []ProxyNode {
	var out []ProxyNode
	for _, n := range nodes {
		if n.Delay < 0 {
			continue
		}
		if delayMatch(n.Delay, op, raw, timeout) {
			out = append(out, n)
		}
	}
	return out
}

func delayMatch(ms int, op, raw string, timeout int) bool {
	raw = strings.ToLower(raw)
	switch raw {
	case "error":
		if op == "=" {
			return ms >= 100000
		}
		return cmpDelay(op, ms, 100000)
	case "timeout":
		if op == "=" {
			return ms < 100000 && ms >= 3000
		}
		return cmpDelay(op, ms, 3000)
	}
	n, err := strconv.Atoi(raw)
	if err != nil {
		return false
	}
	_ = timeout
	return cmpDelay(op, ms, n)
}

// cmpDelay uses the source's inverted inequalities: "<" means <= and ">" means >=.
func cmpDelay(op string, ms, n int) bool {
	switch op {
	case "=":
		return ms == n
	case "<":
		return ms <= n
	case ">":
		return ms >= n
	default:
		return false
	}
}

func nameMatch(name, query string, opt SearchOpts, re *regexp.Regexp) bool {
	if re != nil {
		return re.MatchString(name)
	}
	hay, needle := name, query
	if !opt.MatchCase {
		hay = strings.ToLower(name)
		needle = strings.ToLower(query)
	}
	if needle == "" {
		return true
	}
	if !opt.WholeWord {
		return strings.Contains(hay, needle)
	}
	start := 0
	for {
		i := strings.Index(hay[start:], needle)
		if i < 0 {
			return false
		}
		i += start
		before := i == 0 || !isWord(runeAt(hay, i-1))
		afterAt := i + len(needle)
		after := afterAt >= len(hay) || !isWord(runeAt(hay, afterAt))
		if before && after {
			return true
		}
		start = i + len(needle)
		if start >= len(hay) {
			return false
		}
	}
}

func runeAt(s string, i int) rune {
	if i < 0 || i >= len(s) {
		return 0
	}
	for i > 0 && !utf8.RuneStart(s[i]) {
		i--
	}
	r, _ := utf8.DecodeRuneInString(s[i:])
	return r
}

func isWord(r rune) bool {
	return unicode.IsLetter(r) || unicode.IsDigit(r)
}

// SortNodes returns nodes in order. mode 0 keeps the slice, 1 sorts by
// delay (measured ascending, then timeout, error, testing, untested),
// 2 sorts by name with a Chinese collation.
func SortNodes(nodes []ProxyNode, mode, timeout int) []ProxyNode {
	out := append([]ProxyNode(nil), nodes...)
	if timeout <= 0 {
		timeout = DelayTimeout
	}
	switch mode {
	case 1:
		sortDelay(out, timeout)
	case 2:
		c := collate.New(language.Chinese)
		for i := 1; i < len(out); i++ {
			j := i
			for j > 0 && c.CompareString(out[j].Name, out[j-1].Name) < 0 {
				out[j], out[j-1] = out[j-1], out[j]
				j--
			}
		}
	}
	return out
}

func sortDelay(nodes []ProxyNode, timeout int) {
	rank := func(ms int) (int, int) {
		switch {
		case ms == DelayTesting:
			return 3, 0
		case ms < 0:
			return 4, 0
		case ms > 100000:
			return 2, ms
		case ms == 0 || ms >= timeout:
			return 1, ms
		default:
			return 0, ms
		}
	}
	for i := 1; i < len(nodes); i++ {
		j := i
		for j > 0 {
			aG, aV := rank(nodes[j].Delay)
			bG, bV := rank(nodes[j-1].Delay)
			if aG > bG || (aG == bG && aV >= bV) {
				break
			}
			nodes[j], nodes[j-1] = nodes[j-1], nodes[j]
			j--
		}
	}
}

// NextSort cycles 0 → 1 → 2 → 0.
func NextSort(cur int) int { return (cur + 1) % 3 }

// SortLabel is the tooltip for the current sort state.
func SortLabel(mode int) string {
	switch mode {
	case 1:
		return "按延迟排序"
	case 2:
		return "按名称排序"
	default:
		return "默认排序"
	}
}

// Debounced reports whether wait has elapsed since changed.
func Debounced(now, changed time.Time, wait time.Duration) bool {
	if changed.IsZero() || wait <= 0 {
		return false
	}
	return now.Sub(changed) >= wait
}

// ValidSubscriptionURL requires an http or https URL.
func ValidSubscriptionURL(raw string) bool {
	raw = strings.TrimSpace(raw)
	if !strings.HasPrefix(raw, "http://") && !strings.HasPrefix(raw, "https://") {
		return false
	}
	u, err := url.Parse(raw)
	return err == nil && u.Host != ""
}

// URLHost returns the host, or "local" when the URL is not usable.
func URLHost(raw string) string {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || u.Host == "" {
		return "local"
	}
	return u.Host
}

// FrequentUpdate is true for a positive interval under 1440 minutes.
// The value can still be saved.
func FrequentUpdate(minutes int) bool { return minutes > 0 && minutes < 1440 }

// PortSet is one listener the port dialog edits.
type PortSet struct {
	Mixed      int
	Socks      int
	SocksOn    bool
	HTTP       int
	HTTPOn     bool
	Redir      int
	RedirOn    bool
	TProxy     int
	TProxyOn   bool
	ShowRedir  bool
	ShowTProxy bool
}

// ValidatePorts reports a Chinese error, or "" when the set can be saved.
// Mixed is always on. Only enabled listeners are checked for duplicates.
func ValidatePorts(p PortSet) string {
	type pair struct {
		name string
		port int
		on   bool
	}
	rows := []pair{{"混合", p.Mixed, true}}
	if p.SocksOn {
		rows = append(rows, pair{"SOCKS", p.Socks, true})
	}
	if p.HTTPOn {
		rows = append(rows, pair{"HTTP", p.HTTP, true})
	}
	if p.ShowRedir && p.RedirOn {
		rows = append(rows, pair{"Redir", p.Redir, true})
	}
	if p.ShowTProxy && p.TProxyOn {
		rows = append(rows, pair{"TProxy", p.TProxy, true})
	}
	seen := map[int]string{}
	for _, r := range rows {
		if r.port < 1 || r.port > 65535 {
			return "请输入 1 至 65535 之间的端口号"
		}
		if prev, ok := seen[r.port]; ok {
			_ = prev
			return "已启用的监听端口不能重复"
		}
		seen[r.port] = r.name
	}
	return ""
}

// GroupLetter is the first displayed character of a group name, uppercased
// when it is a letter.
func GroupLetter(name string) string {
	for _, r := range strings.TrimSpace(name) {
		if unicode.IsLetter(r) {
			return string(unicode.ToUpper(r))
		}
		return string(r)
	}
	return ""
}

// SelectableGroup is true for types the row click may switch.
func SelectableGroup(kind string) bool {
	switch strings.ToLower(kind) {
	case "selector", "select", "urltest", "url-test", "fallback":
		return true
	default:
		return false
	}
}

// ChainConnectEnabled matches the chain panel's disable rules.
func ChainConnectEnabled(n int, connecting, connected bool) (bool, string) {
	if connecting {
		return false, ""
	}
	if !connected && n < 2 {
		return false, "链式代理至少需要 2 个节点"
	}
	return true, ""
}

// Move shifts one element from index to index. Out-of-range indexes are ignored.
func Move[T any](s []T, from, to int) []T {
	if from < 0 || to < 0 || from >= len(s) || to >= len(s) || from == to {
		return s
	}
	item := s[from]
	if from < to {
		copy(s[from:to], s[from+1:to+1])
	} else {
		copy(s[to+1:from+1], s[to:from])
	}
	s[to] = item
	return s
}

// UsagePercent is used/total clamped to 0–100. A non-positive total is 0.
func UsagePercent(used, total int64) int {
	if total <= 0 || used <= 0 {
		return 0
	}
	p := int(used * 100 / total)
	if p > 100 {
		return 100
	}
	return p
}

// FinishTest leaves a site in a terminal state. A failure must not stay "testing".
func FinishTest(status string, failed bool) string {
	if failed {
		return "fail"
	}
	if status == "testing" || status == "" {
		return "ok"
	}
	return status
}

// EmptyReason is why the proxy page is not showing groups.
type EmptyReason string

const (
	EmptyNone     EmptyReason = ""
	EmptyDirect   EmptyReason = "direct"
	EmptyLoading  EmptyReason = "loading"
	EmptyNoSubs   EmptyReason = "no-subscriptions"
	EmptyInactive EmptyReason = "inactive-subscription"
	EmptyCore     EmptyReason = "core-unavailable"
	EmptyNoInfo   EmptyReason = "no-proxy-info"
)

// ProxyListInput is the data resolveProxyListState reads.
type ProxyListInput struct {
	Mode            string
	Loading         bool
	SubscriptionCnt int
	HasCurrent      bool
	CoreRunning     bool
	CoreError       bool
	GroupCount      int
}

// ResolveProxyList picks the proxies page branch.
func ResolveProxyList(in ProxyListInput) EmptyReason {
	if in.Mode == "direct" {
		return EmptyDirect
	}
	if in.Loading {
		return EmptyLoading
	}
	if in.SubscriptionCnt == 0 {
		return EmptyNoSubs
	}
	if !in.HasCurrent {
		return EmptyInactive
	}
	if in.GroupCount == 0 && (!in.CoreRunning || in.CoreError) {
		return EmptyCore
	}
	if in.GroupCount == 0 {
		return EmptyNoInfo
	}
	return EmptyNone
}
