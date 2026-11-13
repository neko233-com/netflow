package coreipc

import (
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestWorkerOverPrivateConnection(t *testing.T) {
	t.Setenv("CI", "1")
	left, right := net.Pipe()
	worker := NewWorker()
	stopped := make(chan error, 1)
	go func() { stopped <- worker.Serve(right) }()
	client, err := NewClient(left)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	source := "mixed-port: 0\nport: 0\nsocks-port: 0\nlog-level: error\nrules: ['MATCH,DIRECT']\n"
	path := filepath.Join(dir, "config.yaml")
	if err = os.WriteFile(path, []byte(source), 0600); err != nil {
		t.Fatal(err)
	}
	client.SetProfileID("profile-1")
	client.SetTransformer(func(data []byte, id string) ([]byte, error) {
		if id != "profile-1" {
			t.Errorf("profile ID = %q", id)
		}
		return append(data, []byte("ipv6: false\n")...), nil
	})
	if err = client.Start(dir); err != nil {
		t.Fatal(err)
	}
	if status := client.Status(); !status.Running || status.TUN {
		t.Fatalf("status %+v", status)
	}
	effective, err := client.EffectiveConfig()
	if err != nil || !strings.Contains(string(effective), "ipv6: false") {
		t.Fatalf("effective %q: %v", effective, err)
	}
	if got, err := os.ReadFile(path); err != nil || string(got) != source {
		t.Fatal("source configuration changed")
	}
	if got := client.Rules(); len(got) != 1 || got[0].Proxy != "DIRECT" {
		t.Fatalf("rules %+v", got)
	}
	if err = client.Reload(); err != nil {
		t.Fatal(err)
	}
	if err = client.Close(); err != nil {
		t.Fatal(err)
	}
	select {
	case err = <-stopped:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("worker did not stop on disconnect")
	}
	if worker.kernel.Status().Running {
		t.Fatal("kernel kept running after disconnect")
	}
}

func TestWorkerRejectsOversizedConfig(t *testing.T) {
	if validConfig(make([]byte, MaxConfigBytes+1)) == nil {
		t.Fatal("oversized config accepted")
	}
	if validConfig(nil) == nil {
		t.Fatal("empty config accepted")
	}
}
