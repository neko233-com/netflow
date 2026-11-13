package core

import (
	"runtime/debug"
	"testing"
)

func TestMihomoVersionFollowsBuildReplacement(t *testing.T) {
	for _, tc := range []struct {
		module *debug.Module
		want   string
	}{
		{&debug.Module{Path: "github.com/metacubex/mihomo", Version: "v1.2.3"}, "1.2.3"},
		{&debug.Module{Path: "github.com/metacubex/mihomo", Version: "v1.2.3", Replace: &debug.Module{Path: "example.com/fork", Version: "v1.2.3-fork.8"}}, "1.2.3-fork.8"},
		{&debug.Module{Path: "github.com/metacubex/mihomo", Replace: &debug.Module{Path: "../local"}}, "local"},
		{&debug.Module{Path: "example.com/other", Version: "v2.0.0"}, "unknown"},
	} {
		if got := mihomoDependencyVersion(&debug.BuildInfo{Deps: []*debug.Module{tc.module}}); got != tc.want {
			t.Errorf("version = %q, want %q", got, tc.want)
		}
	}
}
