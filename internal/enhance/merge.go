package enhance

import "strings"

// Merge deep-merges overlay onto base and returns a new mapping.
// Top-level overlay keys are ASCII-lowercased, matching Verge use_lowercase.
// Nested mappings merge recursively. A sequence or scalar from overlay
// replaces the base value. The top-level "dns" mapping is shallow: each
// overlay key replaces that dns entry and sibling keys stay. The top-level
// "hosts" value is replaced as a whole, even when both sides are mappings.
func Merge(base, overlay map[string]any) map[string]any {
	out := cloneMap(base)
	for key, value := range lowerTopKeys(overlay) {
		switch key {
		case "hosts":
			out[key] = cloneAny(value)
		case "dns":
			out[key] = extendDNS(out[key], value)
		default:
			if existing, ok := out[key]; ok {
				out[key] = deepMerge(existing, value)
			} else {
				out[key] = cloneAny(value)
			}
		}
	}
	return out
}

// PrependAppend inserts overlay sequences around list fields on a copy of
// config. The recognized keys are prepend-rules, append-rules, delete-rules,
// and the same trio for proxies and proxy-groups. Other overlay keys are
// ignored; call Merge for those.
//
// For proxies, names added by prepend or append are also inserted at the
// front of the first select / selector group, and delete removes those
// names from every group's proxies list. That is Verge use_seq.
func PrependAppend(config, overlay map[string]any) map[string]any {
	out := cloneMap(config)
	over := lowerTopKeys(overlay)
	for _, field := range []string{"rules", "proxies", "proxy-groups"} {
		_, hasPre := over["prepend-"+field]
		_, hasApp := over["append-"+field]
		_, hasDel := over["delete-"+field]
		if !hasPre && !hasApp && !hasDel {
			continue
		}
		pre, _ := asAnySlice(over["prepend-"+field])
		app, _ := asAnySlice(over["append-"+field])
		applySeq(out, field, pre, app, asStrings(over["delete-"+field]))
	}
	return out
}

func extendDNS(existing, overlay any) any {
	base, baseOK := existing.(map[string]any)
	add, addOK := overlay.(map[string]any)
	if !baseOK || !addOK {
		return cloneAny(overlay)
	}
	out := cloneMap(base)
	for key, value := range add {
		out[key] = cloneAny(value)
	}
	return out
}

func deepMerge(base, overlay any) any {
	bm, bok := base.(map[string]any)
	om, ook := overlay.(map[string]any)
	if bok && ook {
		out := cloneMap(bm)
		for key, value := range om {
			if existing, ok := out[key]; ok {
				out[key] = deepMerge(existing, value)
			} else {
				out[key] = cloneAny(value)
			}
		}
		return out
	}
	return cloneAny(overlay)
}

func applySeq(config map[string]any, field string, prepend, appendItems []any, delete []string) {
	drop := map[string]struct{}{}
	for _, name := range delete {
		drop[name] = struct{}{}
	}
	var added []string
	if field == "proxies" {
		seen := map[string]bool{}
		for _, item := range prepend {
			addProxyName(item, seen, &added)
		}
		for _, item := range appendItems {
			addProxyName(item, seen, &added)
		}
	}

	next := make([]any, 0, len(prepend)+len(appendItems))
	next = append(next, prepend...)
	if existing, ok := config[field].([]any); ok {
		for _, item := range existing {
			if dropped(item, drop) {
				continue
			}
			next = append(next, item)
		}
	}
	next = append(next, appendItems...)
	config[field] = next

	if field != "proxies" {
		return
	}
	groups, ok := config["proxy-groups"].([]any)
	if !ok {
		return
	}
	appended := false
	for _, group := range groups {
		gm, ok := group.(map[string]any)
		if !ok {
			continue
		}
		names, namesOK := groupProxyList(gm)
		if namesOK {
			kept := make([]any, 0, len(names))
			for _, name := range names {
				if s, isString := name.(string); isString {
					if _, cut := drop[s]; cut {
						continue
					}
				}
				kept = append(kept, name)
			}
			gm["proxies"] = kept
			names = kept
		}
		if appended || len(added) == 0 || !namesOK || !isSelector(gm) {
			continue
		}
		merged := make([]any, 0, len(added)+len(names))
		seen := map[string]bool{}
		for _, name := range added {
			if seen[name] {
				continue
			}
			seen[name] = true
			merged = append(merged, name)
		}
		for _, name := range names {
			if s, isString := name.(string); isString && seen[s] {
				continue
			}
			merged = append(merged, name)
		}
		gm["proxies"] = merged
		appended = true
	}
}

func addProxyName(item any, seen map[string]bool, added *[]string) {
	name, ok := itemName(item)
	if !ok || name == "" || seen[name] {
		return
	}
	seen[name] = true
	*added = append(*added, name)
}

func groupProxyList(group map[string]any) ([]any, bool) {
	value, exists := group["proxies"]
	if !exists {
		return nil, true
	}
	names, ok := value.([]any)
	return names, ok
}

func isSelector(group map[string]any) bool {
	typ, _ := group["type"].(string)
	switch strings.ToLower(typ) {
	case "select", "selector":
		return true
	default:
		return false
	}
}

func dropped(item any, drop map[string]struct{}) bool {
	name, ok := itemName(item)
	if !ok {
		return false
	}
	_, cut := drop[name]
	return cut
}

func itemName(item any) (string, bool) {
	switch v := item.(type) {
	case string:
		return v, true
	case map[string]any:
		name, ok := v["name"].(string)
		return name, ok
	default:
		return "", false
	}
}

func lowerTopKeys(m map[string]any) map[string]any {
	if len(m) == 0 {
		return map[string]any{}
	}
	out := make(map[string]any, len(m))
	for key, value := range m {
		out[strings.ToLower(key)] = cloneAny(value)
	}
	return out
}

func cloneMap(m map[string]any) map[string]any {
	if m == nil {
		return map[string]any{}
	}
	out := make(map[string]any, len(m))
	for key, value := range m {
		out[key] = cloneAny(value)
	}
	return out
}

func cloneAny(v any) any {
	switch t := v.(type) {
	case map[string]any:
		return cloneMap(t)
	case []any:
		out := make([]any, len(t))
		for i := range t {
			out[i] = cloneAny(t[i])
		}
		return out
	default:
		return v
	}
}

func asAnySlice(v any) ([]any, bool) {
	switch s := v.(type) {
	case []any:
		return s, true
	case []string:
		out := make([]any, len(s))
		for i, item := range s {
			out[i] = item
		}
		return out, true
	default:
		return nil, false
	}
}

func asStrings(v any) []string {
	switch s := v.(type) {
	case []string:
		return append([]string(nil), s...)
	case []any:
		out := make([]string, 0, len(s))
		for _, item := range s {
			if str, ok := item.(string); ok {
				out = append(out, str)
			}
		}
		return out
	default:
		return nil
	}
}
