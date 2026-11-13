package enhance

import (
	"reflect"
	"testing"

	"go.yaml.in/yaml/v3"
)

func TestMerge(t *testing.T) {
	t.Parallel()
	base := map[string]any{
		"rules": []any{"aaaaa"},
		"tun": map[string]any{
			"mtu": 1500,
			"stack": map[string]any{
				"x": 1,
			},
		},
		"dns": map[string]any{
			"nameserver": []any{"9.9.9.9"},
			"nameserver-policy": map[string]any{
				"old.example": "8.8.8.8",
			},
			"fallback-filter": map[string]any{
				"geoip":  true,
				"domain": []any{"old.example"},
			},
			"ipv6": true,
		},
		"hosts": map[string]any{
			"old.example": "192.0.2.1",
		},
		"script1": "test",
	}
	overlay := map[string]any{
		"DNS": map[string]any{
			"enable": true,
			"nameserver-policy": map[string]any{
				"new.example": "1.1.1.1",
			},
			"fallback-filter": map[string]any{
				"geoip": false,
			},
		},
		"hosts": map[string]any{
			"new.example": "192.0.2.2",
		},
		"tun": map[string]any{
			"enable": true,
			"stack": map[string]any{
				"y": 2,
			},
		},
		"rules": []any{"replace"},
	}
	got := Merge(base, overlay)

	if !reflect.DeepEqual(got["rules"], []any{"replace"}) {
		t.Fatalf("rules %#v", got["rules"])
	}
	if got["script1"] != "test" {
		t.Fatalf("script1 %#v", got["script1"])
	}
	tun := got["tun"].(map[string]any)
	if tun["mtu"] != 1500 || tun["enable"] != true {
		t.Fatalf("tun %#v", tun)
	}
	stack := tun["stack"].(map[string]any)
	if stack["x"] != 1 || stack["y"] != 2 {
		t.Fatalf("tun.stack %#v", stack)
	}
	dns := got["dns"].(map[string]any)
	if dns["ipv6"] != true || dns["enable"] != true {
		t.Fatalf("dns siblings %#v", dns)
	}
	if !reflect.DeepEqual(dns["nameserver"], []any{"9.9.9.9"}) {
		t.Fatalf("nameserver %#v", dns["nameserver"])
	}
	policy := dns["nameserver-policy"].(map[string]any)
	if _, ok := policy["old.example"]; ok || policy["new.example"] != "1.1.1.1" {
		t.Fatalf("nameserver-policy %#v", policy)
	}
	filter := dns["fallback-filter"].(map[string]any)
	if _, ok := filter["domain"]; ok || filter["geoip"] != false {
		t.Fatalf("fallback-filter %#v", filter)
	}
	hosts := got["hosts"].(map[string]any)
	if _, ok := hosts["old.example"]; ok || hosts["new.example"] != "192.0.2.2" {
		t.Fatalf("hosts %#v", hosts)
	}

	// The caller's maps are left alone.
	if base["rules"].([]any)[0] != "aaaaa" {
		t.Fatal("Merge mutated the base rules")
	}
	if _, ok := base["tun"].(map[string]any)["enable"]; ok {
		t.Fatal("Merge mutated the base tun")
	}
}

func TestMergeFromYAML(t *testing.T) {
	t.Parallel()
	base := mustMap(t, `
rules:
  - aaaaa
tun:
  mtu: 1500
dns:
  nameserver: ["9.9.9.9"]
  nameserver-policy:
    old.example: 8.8.8.8
hosts:
  old.example: 192.0.2.1
`)
	overlay := mustMap(t, `
prepend-rules:
  - prepend
rules:
  - replace
tun:
  enable: true
dns:
  enable: true
  nameserver-policy:
    new.example: 1.1.1.1
hosts:
  new.example: 192.0.2.2
`)
	got := Merge(base, overlay)
	rules, _ := got["rules"].([]any)
	if len(rules) != 1 || rules[0] != "replace" {
		t.Fatalf("rules %#v", got["rules"])
	}
	// prepend-rules is a normal key for Merge. PrependAppend consumes it.
	if _, ok := got["prepend-rules"]; !ok {
		t.Fatal("Merge should keep prepend-rules as a key")
	}
	dns := got["dns"].(map[string]any)
	policy := dns["nameserver-policy"].(map[string]any)
	if _, ok := policy["old.example"]; ok {
		t.Fatalf("yaml nameserver-policy %#v", policy)
	}
	if _, ok := dns["nameserver"]; !ok {
		t.Fatal("yaml merge dropped nameserver")
	}
	hosts := got["hosts"].(map[string]any)
	if _, ok := hosts["old.example"]; ok {
		t.Fatalf("yaml hosts %#v", hosts)
	}
}

func TestPrependAppend(t *testing.T) {
	t.Parallel()
	config := map[string]any{
		"rules": []any{"aaaaa", "DROP"},
		"tun":   map[string]any{"mtu": 1500},
	}
	overlay := map[string]any{
		"Prepend-Rules": []any{"prepend"},
		"append-rules":  []any{"append"},
		"delete-rules":  []any{"DROP"},
		"rules":         []any{"ignored by prepend"},
	}
	got := PrependAppend(config, overlay)
	want := []any{"prepend", "aaaaa", "append"}
	if !reflect.DeepEqual(got["rules"], want) {
		t.Fatalf("rules %#v, want %#v", got["rules"], want)
	}
	if _, ok := got["prepend-rules"]; ok {
		t.Fatal("prepend-rules leaked into the config")
	}
	if got["tun"].(map[string]any)["mtu"] != 1500 {
		t.Fatal("unrelated keys changed")
	}
	if config["rules"].([]any)[1] != "DROP" {
		t.Fatal("PrependAppend mutated the input")
	}
}

func TestPrependAppendProxies(t *testing.T) {
	t.Parallel()
	config := map[string]any{
		"proxies": []any{
			map[string]any{"name": "proxy1", "type": "ss"},
			map[string]any{"name": "proxy2", "type": "vmess"},
		},
		"proxy-groups": []any{
			map[string]any{
				"name":    "group1",
				"type":    "select",
				"proxies": []any{"proxy1", "proxy2"},
			},
			map[string]any{
				"name":    "group2",
				"type":    "Select",
				"proxies": []any{"proxy1"},
			},
		},
	}
	added := PrependAppend(config, map[string]any{
		"prepend-proxies": []any{map[string]any{"name": "proxy3", "type": "ss"}},
		"append-proxies":  []any{map[string]any{"name": "proxy4", "type": "vmess"}},
	})
	groups := added["proxy-groups"].([]any)
	g1 := groups[0].(map[string]any)["proxies"]
	g2 := groups[1].(map[string]any)["proxies"]
	if !reflect.DeepEqual(g1, []any{"proxy3", "proxy4", "proxy1", "proxy2"}) {
		t.Fatalf("first selector %#v", g1)
	}
	if !reflect.DeepEqual(g2, []any{"proxy1"}) {
		t.Fatalf("second selector %#v", g2)
	}

	deleted := PrependAppend(config, map[string]any{
		"delete-proxies": []any{"proxy1"},
	})
	proxies := deleted["proxies"].([]any)
	if len(proxies) != 1 || proxies[0].(map[string]any)["name"] != "proxy2" {
		t.Fatalf("proxies %#v", proxies)
	}
	groups = deleted["proxy-groups"].([]any)
	if !reflect.DeepEqual(groups[0].(map[string]any)["proxies"], []any{"proxy2"}) {
		t.Fatalf("group1 after delete %#v", groups[0])
	}
	if !reflect.DeepEqual(groups[1].(map[string]any)["proxies"], []any{}) {
		t.Fatalf("group2 after delete %#v", groups[1])
	}
}

func mustMap(t *testing.T, text string) map[string]any {
	t.Helper()
	var v any
	if err := yaml.Unmarshal([]byte(text), &v); err != nil {
		t.Fatal(err)
	}
	m, ok := v.(map[string]any)
	if !ok {
		t.Fatalf("yaml type %T", v)
	}
	return m
}
