package core

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

func TestIconResolverDuringCoreReload(t *testing.T) {
	dir := t.TempDir()
	config := "mixed-port: 0\nport: 0\nsocks-port: 0\nlog-level: error\ndns: {enable: false}\nhosts: {icons.netflow-test.example: 8.8.8.8}\nrules: ['MATCH,DIRECT']\n"
	if err := os.WriteFile(filepath.Join(dir, "config.yaml"), []byte(config), 0600); err != nil {
		t.Fatal(err)
	}
	c := New()
	if err := c.Start(dir); err != nil {
		t.Fatal(err)
	}
	defer c.Stop()
	done := make(chan error, 1)
	go func() {
		for range 100 {
			ips, err := c.ResolveIconHost(context.Background(), "icons.netflow-test.example")
			if err != nil {
				done <- err
				return
			}
			if len(ips) != 1 || ips[0].String() != "8.8.8.8" {
				done <- os.ErrInvalid
				return
			}
		}
		done <- nil
	}()
	for range 3 {
		if err := c.Reload(); err != nil {
			t.Fatal(err)
		}
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}
