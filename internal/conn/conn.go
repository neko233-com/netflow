// Package conn is the connections page data: formatting, filtering,
// sorting, and the active/closed tracker. It does not talk to mihomo.
package conn

import (
	"math"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/neko233-com/netflow/internal/query"
)

const (
	// SampleGap is the minimum time between speed samples.
	SampleGap = 500 * time.Millisecond
	// ClosedCap is how many closed connections the page keeps.
	ClosedCap = 500
	// SpeedLabelMin is the speed at which a list row shows its speed tag.
	SpeedLabelMin int64 = 100
)

// Item is one connection, active or closed.
type Item struct {
	ID                string
	Host              string
	DestinationIP     string
	RemoteDestination string
	DestinationPort   string
	Process           string
	ProcessPath       string
	Rule              string
	RulePayload       string
	Network           string
	Type              string
	SourceIP          string
	SourcePort        string
	Upload            int64
	Download          int64
	UploadSpeed       int64
	DownloadSpeed     int64
	Start             time.Time
	Chains            []string
	Closed            bool
}

// Snapshot is the page's list plus cumulative traffic.
type Snapshot struct {
	Active        []Item
	Closed        []Item
	UploadTotal   int64
	DownloadTotal int64
}

// FormatParts splits n into a number and a 1024-based unit.
// The number uses three significant digits, or no fraction at 1000 and above.
func FormatParts(n int64) (num, unit string) {
	if n < 0 {
		n = 0
	}
	units := []string{"B", "KB", "MB", "GB", "TB", "PB", "EB", "ZB", "YB"}
	v := float64(n)
	i := 0
	for v >= 1024 && i < len(units)-1 {
		v /= 1024
		i++
	}
	if v >= 1000 {
		return strconv.FormatFloat(v, 'f', 0, 64), units[i]
	}
	return toPrecision(v, 3), units[i]
}

// HeaderTraffic joins the number and unit with no space: "0.00B", "12.3MB".
func HeaderTraffic(n int64) string {
	num, unit := FormatParts(n)
	return num + unit
}

// CellTraffic joins them with one space: "0.00 B", "12.3 MB".
func CellTraffic(n int64) string {
	num, unit := FormatParts(n)
	return num + " " + unit
}

// Speed is a table or detail speed: "0.00 B/s".
func Speed(n int64) string { return CellTraffic(n) + "/s" }

func toPrecision(n float64, prec int) string {
	if n == 0 {
		return "0." + strings.Repeat("0", prec-1)
	}
	sign := ""
	if n < 0 {
		sign = "-"
		n = -n
	}
	exp := int(math.Floor(math.Log10(n) + 1e-10))
	decimals := prec - exp - 1
	if decimals < 0 {
		decimals = 0
	}
	return sign + strconv.FormatFloat(n, 'f', decimals, 64)
}

// Filter keeps items whose host, destination IP or process matches.
// Rule, chains and ports are not searched.
func Filter(items []Item, q query.Options) []Item {
	if !q.Active() {
		return append([]Item(nil), items...)
	}
	out := make([]Item, 0, len(items))
	for _, it := range items {
		if query.MatchAny(q, it.Host, it.DestinationIP, it.Process) {
			out = append(out, it)
		}
	}
	return out
}

// Sort orders a list-layout result. default is start time, newest first.
func Sort(items []Item, order string) {
	sort.SliceStable(items, func(i, j int) bool {
		switch order {
		case "uploadSpeed":
			return items[i].UploadSpeed > items[j].UploadSpeed
		case "downloadSpeed":
			return items[i].DownloadSpeed > items[j].DownloadSpeed
		default:
			return items[i].Start.After(items[j].Start)
		}
	})
}

// SortField sorts a table by a column. dir 1 is ascending, 2 is descending.
func SortField(items []Item, field string, dir int) {
	if dir == 0 || field == "" {
		return
	}
	sort.SliceStable(items, func(i, j int) bool {
		cmp := compareField(items[i], items[j], field)
		if dir == 1 {
			return cmp < 0
		}
		return cmp > 0
	})
}

func compareField(a, b Item, field string) int {
	switch field {
	case "download":
		return cmpInt(a.Download, b.Download)
	case "upload":
		return cmpInt(a.Upload, b.Upload)
	case "dlSpeed":
		return cmpInt(a.DownloadSpeed, b.DownloadSpeed)
	case "ulSpeed":
		return cmpInt(a.UploadSpeed, b.UploadSpeed)
	case "time":
		return a.Start.Compare(b.Start)
	case "host":
		return strings.Compare(HostLabel(a), HostLabel(b))
	case "chains":
		return strings.Compare(ChainsLabel(a), ChainsLabel(b))
	case "rule":
		return strings.Compare(RuleLabel(a), RuleLabel(b))
	case "process":
		return strings.Compare(ProcessLabel(a), ProcessLabel(b))
	case "source":
		return strings.Compare(SourceLabel(a), SourceLabel(b))
	case "remoteDestination":
		return strings.Compare(DestLabel(a), DestLabel(b))
	case "type":
		return strings.Compare(TypeLabel(a), TypeLabel(b))
	default:
		return 0
	}
}

func cmpInt(a, b int64) int {
	switch {
	case a < b:
		return -1
	case a > b:
		return 1
	default:
		return 0
	}
}

// HostLabel is host, else destination IP, else remote destination, plus the port.
func HostLabel(it Item) string {
	host := first(it.Host, it.DestinationIP, it.RemoteDestination)
	if it.DestinationPort == "" {
		return host
	}
	if host == "" {
		return ":" + it.DestinationPort
	}
	return host + ":" + it.DestinationPort
}

// ProcessLabel prefers the process name, then the path.
func ProcessLabel(it Item) string { return first(it.Process, it.ProcessPath) }

// ProcessDetail is process(path) when both are set.
func ProcessDetail(it Item) string {
	if it.Process != "" && it.ProcessPath != "" {
		return it.Process + "(" + it.ProcessPath + ")"
	}
	return ProcessLabel(it)
}

// RuleLabel is rule(payload), or just the rule when there is no payload.
func RuleLabel(it Item) string {
	if it.RulePayload == "" {
		return it.Rule
	}
	return it.Rule + "(" + it.RulePayload + ")"
}

// TypeLabel is type(network).
func TypeLabel(it Item) string {
	if it.Type == "" && it.Network == "" {
		return ""
	}
	if it.Network == "" {
		return it.Type
	}
	if it.Type == "" {
		return it.Network
	}
	return it.Type + "(" + it.Network + ")"
}

// ChainsLabel joins chains from the last entry back to the first with " / ".
func ChainsLabel(it Item) string {
	if len(it.Chains) == 0 {
		return ""
	}
	rev := make([]string, len(it.Chains))
	for i := range it.Chains {
		rev[len(it.Chains)-1-i] = it.Chains[i]
	}
	return strings.Join(rev, " / ")
}

// SourceLabel is sourceIP:sourcePort.
func SourceLabel(it Item) string {
	if it.SourceIP == "" && it.SourcePort == "" {
		return ""
	}
	return it.SourceIP + ":" + it.SourcePort
}

// DestLabel is the table destination, including the port.
func DestLabel(it Item) string {
	host := first(it.DestinationIP, it.RemoteDestination)
	if it.DestinationPort == "" {
		return host
	}
	if host == "" {
		return ":" + it.DestinationPort
	}
	return host + ":" + it.DestinationPort
}

// DestDetail is the detail destination, without the port.
func DestDetail(it Item) string { return first(it.DestinationIP, it.RemoteDestination) }

func first(values ...string) string {
	for _, v := range values {
		if v != "" {
			return v
		}
	}
	return ""
}

// Relative is a Chinese dayjs fromNow label.
func Relative(now, start time.Time) string {
	if start.IsZero() {
		return ""
	}
	d := now.Sub(start)
	if d < 0 {
		d = 0
	}
	switch {
	case d < 45*time.Second:
		return "几秒前"
	case d < 90*time.Second:
		return "1 分钟前"
	case d < 45*time.Minute:
		return strconv.Itoa(int(d.Minutes())) + " 分钟前"
	case d < 90*time.Minute:
		return "1 小时前"
	case d < 22*time.Hour:
		return strconv.Itoa(int(d.Hours())) + " 小时前"
	case d < 36*time.Hour:
		return "1 天前"
	default:
		return strconv.Itoa(int(d.Hours()/24)) + " 天前"
	}
}

// SpeedTag is the list-row speed chip. It is empty under 100 B/s.
func SpeedTag(it Item) string {
	if it.UploadSpeed < SpeedLabelMin && it.DownloadSpeed < SpeedLabelMin {
		return ""
	}
	return Speed(it.UploadSpeed) + " / " + Speed(it.DownloadSpeed)
}

// Tracker turns kernel snapshots into active and closed lists.
type Tracker struct {
	active map[string]Item
	prev   map[string][2]int64
	closed []Item
	last   time.Time
	cached Snapshot
	have   bool
}

// Observe samples active connections. Calls closer than SampleGap return
// the previous snapshot. A connection's first sample has speed 0.
func (t *Tracker) Observe(active []Item, up, down int64, now time.Time) Snapshot {
	if t.have && now.Sub(t.last) < SampleGap {
		return t.cached
	}
	seen := make(map[string]Item, len(active))
	out := make([]Item, 0, len(active))
	next := make(map[string][2]int64, len(active))
	for _, it := range active {
		if p, ok := t.prev[it.ID]; ok {
			it.UploadSpeed = nonneg(it.Upload - p[0])
			it.DownloadSpeed = nonneg(it.Download - p[1])
		} else {
			it.UploadSpeed = 0
			it.DownloadSpeed = 0
		}
		next[it.ID] = [2]int64{it.Upload, it.Download}
		seen[it.ID] = it
		out = append(out, it)
	}
	for id, old := range t.active {
		if _, ok := seen[id]; ok || t.hasClosed(id) {
			continue
		}
		old.Closed = true
		old.UploadSpeed = 0
		old.DownloadSpeed = 0
		t.closed = append(t.closed, old)
	}
	if len(t.closed) > ClosedCap {
		t.closed = append([]Item(nil), t.closed[len(t.closed)-ClosedCap:]...)
	}
	t.active = seen
	t.prev = next
	t.last = now
	t.have = true
	t.cached = Snapshot{
		Active:        out,
		Closed:        append([]Item(nil), t.closed...),
		UploadTotal:   up,
		DownloadTotal: down,
	}
	return t.cached
}

// MarkClosed moves one active connection into the closed list.
func (t *Tracker) MarkClosed(id string) {
	if id == "" || t.hasClosed(id) {
		return
	}
	if old, ok := t.active[id]; ok {
		old.Closed = true
		old.UploadSpeed = 0
		old.DownloadSpeed = 0
		t.closed = append(t.closed, old)
		delete(t.active, id)
	}
	t.have = false
}

// ClearClosed drops the closed list. It does not touch the kernel.
func (t *Tracker) ClearClosed() {
	t.closed = nil
	t.have = false
}

func (t *Tracker) hasClosed(id string) bool {
	for _, it := range t.closed {
		if it.ID == id {
			return true
		}
	}
	return false
}

func nonneg(n int64) int64 {
	if n < 0 {
		return 0
	}
	return n
}

// Memory is a fake connection source.
type Memory struct {
	Active    []Item
	Up        int64
	Down      int64
	ClosedIDs []string
	ClosedAll int
	CloseErr  error
}

// List returns the current active connections.
func (m *Memory) List() ([]Item, int64, int64) {
	if m == nil {
		return nil, 0, 0
	}
	return append([]Item(nil), m.Active...), m.Up, m.Down
}

// Close records id and drops that connection.
func (m *Memory) Close(id string) error {
	if m == nil {
		return nil
	}
	if m.CloseErr != nil {
		return m.CloseErr
	}
	m.ClosedIDs = append(m.ClosedIDs, id)
	kept := m.Active[:0]
	for _, it := range m.Active {
		if it.ID != id {
			kept = append(kept, it)
		}
	}
	m.Active = kept
	return nil
}

// CloseAll records one close-all and drops every active connection.
func (m *Memory) CloseAll() error {
	if m == nil {
		return nil
	}
	if m.CloseErr != nil {
		return m.CloseErr
	}
	m.ClosedAll++
	m.Active = nil
	return nil
}
