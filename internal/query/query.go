// Package query is the search box shared by connections, rules and logs.
// An empty query matches everything. An invalid regular expression matches
// nothing. Match case compares the original text: it is not folded first.
package query

import (
	"regexp"
	"strings"
)

// Options are the three BaseSearchBox switches plus the text.
type Options struct {
	Text      string
	MatchCase bool
	Whole     bool
	Regex     bool
}

// Active reports whether the box has text to filter on.
func (o Options) Active() bool { return strings.TrimSpace(o.Text) != "" }

// Match reports whether field matches o.
func Match(o Options, field string) bool {
	if !o.Active() {
		return true
	}
	if o.Regex || o.Whole {
		re, err := o.compile()
		if err != nil {
			return false
		}
		return re.MatchString(field)
	}
	if o.MatchCase {
		return strings.Contains(field, o.Text)
	}
	return strings.Contains(strings.ToLower(field), strings.ToLower(o.Text))
}

// MatchAny reports whether any field matches. An empty query matches.
func MatchAny(o Options, fields ...string) bool {
	if !o.Active() {
		return true
	}
	for _, f := range fields {
		if Match(o, f) {
			return true
		}
	}
	return false
}

// Span is a slice of field, highlighted when Hit.
type Span struct {
	Text string
	Hit  bool
}

// Spans splits field into highlighted runs using the same matcher as Match.
func Spans(o Options, field string) []Span {
	if !o.Active() {
		return []Span{{Text: field}}
	}
	re, err := o.compile()
	if err != nil {
		return []Span{{Text: field}}
	}
	idx := re.FindAllStringIndex(field, -1)
	if len(idx) == 0 {
		return []Span{{Text: field}}
	}
	var out []Span
	at := 0
	for _, pair := range idx {
		if pair[0] > at {
			out = append(out, Span{Text: field[at:pair[0]]})
		}
		out = append(out, Span{Text: field[pair[0]:pair[1]], Hit: true})
		at = pair[1]
	}
	if at < len(field) {
		out = append(out, Span{Text: field[at:]})
	}
	return out
}

func (o Options) compile() (*regexp.Regexp, error) {
	pat := o.Text
	if !o.Regex {
		pat = regexp.QuoteMeta(pat)
	}
	if o.Whole {
		pat = `\b(?:` + pat + `)\b`
	}
	if !o.MatchCase {
		pat = `(?i)` + pat
	}
	return regexp.Compile(pat)
}
