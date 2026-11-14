package vergescript

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestRunVergeEntryAndPreserveInput(t *testing.T) {
	in := []byte(`{"rules":["MATCH,DIRECT"],"proxies":[{"name":"node"}]}`)
	script := `function main(config, profileName) { console.log("sensitive", config); config.rules.unshift("DOMAIN," + profileName + ",DIRECT"); config.proxies[0].name += "-ok"; return config; }`
	out, err := Run(context.Background(), in, script, "example.test")
	if err != nil {
		t.Fatal(err)
	}
	var result struct {
		Rules   []string `json:"rules"`
		Proxies []struct {
			Name string `json:"name"`
		} `json:"proxies"`
	}
	if json.Unmarshal(out, &result) != nil || len(result.Rules) != 2 || result.Rules[0] != "DOMAIN,example.test,DIRECT" || result.Proxies[0].Name != "node-ok" {
		t.Fatalf("unexpected result: %s", out)
	}
	if string(in) != `{"rules":["MATCH,DIRECT"],"proxies":[{"name":"node"}]}` {
		t.Fatal("modified caller input")
	}
}
func TestRunRejectsInvalidAndRedactsExceptions(t *testing.T) {
	for _, script := range []string{`function nope() {}`, `function main(c) { throw new Error(JSON.stringify(c)) }`, `function main(c) { return [1] }`, `function main(c) { return null }`, `function main(c) { return Promise.resolve(c) }`} {
		out, err := Run(context.Background(), []byte(`{"secret":"synthetic-secret"}`), script, "profile")
		if err == nil || out != nil || strings.Contains(err.Error(), "synthetic-secret") {
			t.Fatalf("invalid output or exposed secret: %q %v", out, err)
		}
	}
	if _, err := Run(context.Background(), []byte(`[]`), `function main(c){return c}`, ""); !errors.Is(err, ErrInput) {
		t.Fatalf("invalid input: %v", err)
	}
}
func TestRunDisablesHostGlobalsAndInterruptsLoops(t *testing.T) {
	script := `function main(c) { return {std:typeof std, os:typeof os, process:typeof process, require:typeof require, timer:typeof setTimeout, bjson:typeof bjson, loadScript:typeof loadScript}; }`
	result, err := Run(context.Background(), []byte(`{}`), script, "")
	if err != nil {
		t.Fatal(err)
	}
	var globals map[string]string
	if json.Unmarshal(result, &globals) != nil {
		t.Fatal("invalid result")
	}
	for key, value := range globals {
		if value != "undefined" {
			t.Fatalf("host global %s is %s", key, value)
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	before := time.Now()
	_, err = Run(ctx, []byte(`{}`), `function main(c){for(;;){} }`, "")
	if !errors.Is(err, context.DeadlineExceeded) || time.Since(before) > 5*time.Second {
		t.Fatalf("loop did not terminate: %v", err)
	}
	if _, err = Run(context.Background(), []byte(`{}`), `function main(c){return c}`, ""); err != nil {
		t.Fatalf("runtime unusable after cancellation: %v", err)
	}
}
func TestRunLimitsGuestMemory(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	_, err := Run(ctx, []byte(`{}`), `function main(c){let a=[]; for(;;) a.push(new Uint8Array(1024*1024));}`, "")
	if err == nil {
		t.Fatal("unbounded memory growth succeeded")
	}
}

func TestRunYAMLUsesVergeProfileNameAndDNSOrder(t *testing.T) {
	input := []byte("dns:\n  nameserver-policy:\n    +.first.example: 1.1.1.1\n    +.second.example: 8.8.8.8\nrules: ['MATCH,DIRECT']\n")
	script := `function main(config, profileName) { config.rules.unshift('DOMAIN,' + profileName + ',DIRECT'); return config; }`
	out, err := RunYAML(context.Background(), input, script, "example.test")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(out), `"rules":["DOMAIN,example.test,DIRECT","MATCH,DIRECT"]`) {
		t.Fatalf("script did not transform YAML: %s", out)
	}
	if strings.Index(string(out), "+.first.example") > strings.Index(string(out), "+.second.example") {
		t.Fatal("DNS policy order changed")
	}
}
func TestRunAcceptsLargeOrdinaryConfiguration(t *testing.T) {
	input := []byte(`{"payload":"` + strings.Repeat("a", 1<<20) + `"}`)
	out, err := Run(context.Background(), input, `function main(c){return c}`, "")
	if err != nil || !bytes.Equal(out, input) {
		t.Fatalf("large configuration failed: size=%d error=%v", len(out), err)
	}
}
func TestRunConcurrentGuests(t *testing.T) {
	var wg sync.WaitGroup
	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			out, err := Run(context.Background(), []byte(`{"n":1}`), `function main(c){c.n++;return c}`, "")
			if err != nil || string(out) != `{"n":2}` {
				t.Errorf("concurrent run: %s %v", out, err)
			}
		}()
	}
	wg.Wait()
}

func TestRunRejectsInvalidUTF8AndNulSource(t *testing.T) {
	tests := []struct {
		input        []byte
		script, name string
	}{
		{[]byte(`{}`), "function main(c){return c}\x00invalid", ""},
		{[]byte(`{}`), string([]byte{0xff}), ""},
		{[]byte{'{', '"', 'x', '"', ':', '"', 0xff, '"', '}'}, "function main(c){return c}", ""},
		{[]byte(`{}`), "function main(c){return c}", string([]byte{0xff})},
	}
	for _, v := range tests {
		if _, err := Run(context.Background(), v.input, v.script, v.name); !errors.Is(err, ErrInput) {
			t.Fatalf("invalid encoding accepted: %v", err)
		}
	}
}

func TestRunInterruptsImportedTimer(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	start := time.Now()
	_, err := Run(ctx, []byte(`{}`), `function main(c) { import("qjs:os").then(m => m.sleep(100000)); return c; }`, "")
	if time.Since(start) > 4*time.Second {
		t.Fatal("imported timer blocked the host")
	}
	if err != nil && !errors.Is(err, context.DeadlineExceeded) && !errors.Is(err, ErrExecution) {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestRunScriptLocalsDoNotCollideWithWrapper(t *testing.T) {
	script := `const raw=1, name=2, result=3, stringify=4, parsed=5, invoke=6; function main(c,profile) { JSON.stringify=()=>"malicious"; c.value=raw+name+result+stringify+parsed+invoke; c.profile=profile; return c; }`
	got, err := Run(context.Background(), []byte(`{}`), script, "name")
	if err != nil || string(got) != `{"value":21,"profile":"name"}` {
		t.Fatalf("wrapper conflicted with script: %s %v", got, err)
	}
}

func TestRunRejectsWrapperEscape(t *testing.T) {
	script := `}); return "{}"; /*`
	if _, err := Run(context.Background(), []byte(`{}`), script, ""); err == nil {
		t.Fatal("source escaped the execution wrapper")
	}
}
