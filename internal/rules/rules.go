// Package rules is the rules page data: search, policy color, and provider updates.
package rules

import (
	"errors"
	"fmt"
	"sort"
	"strings"

	"github.com/neko233-com/netflow/internal/query"
)

// ErrNoProviders is returned when update-all has nothing to update.
var ErrNoProviders = errors.New("没有可更新的规则集合")

// Item is one kernel rule. The row number is the original index plus one,
// computed before search so filtered rows keep their numbers.
type Item struct {
	Type    string
	Payload string
	Proxy   string
}

// Numbered is a rule with its original 1-based row number.
type Numbered struct {
	No   int
	Item Item
}

// Provider is one rule provider.
type Provider struct {
	Name      string
	Vehicle   string
	Behavior  string
	Count     int
	UpdatedAt string
	Updating  bool
}

// PolicyTone is the color of a rule's proxy name.
type PolicyTone int

const (
	PolicyText PolicyTone = iota
	PolicyError
	PolicyPrimary
	PolicySecondary
	PolicyInfo
	PolicyWarning
	PolicySuccess
)

// PolicyColor matches Verge parseColor: REJECT is error, DIRECT is body
// text, and every other name is the sum of its code points modulo 5.
func PolicyColor(name string) PolicyTone {
	switch name {
	case "REJECT", "REJECT-DROP":
		return PolicyError
	case "DIRECT":
		return PolicyText
	}
	sum := 0
	for _, r := range name {
		sum += int(r)
	}
	switch sum % 5 {
	case 0:
		return PolicyPrimary
	case 1:
		return PolicySecondary
	case 2:
		return PolicyInfo
	case 3:
		return PolicyWarning
	default:
		return PolicySuccess
	}
}

// Number assigns original row numbers before filtering.
func Number(items []Item) []Numbered {
	out := make([]Numbered, len(items))
	for i, it := range items {
		out[i] = Numbered{No: i + 1, Item: it}
	}
	return out
}

// Search keeps rules whose payload matches. Type and proxy are ignored.
func Search(items []Numbered, q query.Options) []Numbered {
	if !q.Active() {
		return append([]Numbered(nil), items...)
	}
	out := make([]Numbered, 0, len(items))
	for _, it := range items {
		if query.Match(q, it.Item.Payload) {
			out = append(out, it)
		}
	}
	return out
}

// SortProviders orders providers by name.
func SortProviders(list []Provider) []Provider {
	out := append([]Provider(nil), list...)
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

// UpdateAll updates each provider in name order. It returns an error when
// any update fails, instead of reporting that every provider succeeded.
func UpdateAll(names []string, update func(name string) error) error {
	if len(names) == 0 {
		return ErrNoProviders
	}
	ordered := append([]string(nil), names...)
	sort.Strings(ordered)
	var failed []string
	for _, name := range ordered {
		if update == nil {
			continue
		}
		if err := update(name); err != nil {
			failed = append(failed, fmt.Sprintf("%s 更新失败: %s", name, err.Error()))
		}
	}
	if len(failed) > 0 {
		return fmt.Errorf("更新失败: %s", strings.Join(failed, "; "))
	}
	return nil
}

// Memory is a fake rule source.
type Memory struct {
	Items     []Item
	Providers []Provider
	Fail      map[string]error
	Updated   []string
}

// Update records a successful update, or the injected failure.
func (m *Memory) Update(name string) error {
	if m == nil {
		return errors.New("rules source is nil")
	}
	if err := m.Fail[name]; err != nil {
		return err
	}
	m.Updated = append(m.Updated, name)
	for i := range m.Providers {
		if m.Providers[i].Name == name {
			m.Providers[i].Updating = false
		}
	}
	return nil
}

// UpdateAll updates every provider and reports a partial failure.
func (m *Memory) UpdateAll() error {
	if m == nil {
		return ErrNoProviders
	}
	names := make([]string, len(m.Providers))
	for i, p := range m.Providers {
		names[i] = p.Name
	}
	return UpdateAll(names, m.Update)
}
