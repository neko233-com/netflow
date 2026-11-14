package app

import (
	"fmt"
	"net"
	"strings"
	"sync"
	"testing"

	"github.com/neko233-com/netflow/internal/profile"
)

// TestSelectionRestoresPerProfile is Verge's activateSelected.
// Profile A remembers PROXY=n2 and profile B remembers PROXY=m3.
// Switching back to A shows n2. A fresh Store load plus the startup
// path (loadProfiles, install, loadGroups) still shows n2, and that
// path writes the choice back through the already-running kernel.
// The in-process selector Now() matches the UI at every step.
// The kernel is started once for the whole process. Do not call
// t.Parallel: mihomo is a process-wide singleton.
func TestSelectionRestoresPerProfile(t *testing.T) {
	dir := t.TempDir()
	port := freePort(t)
	store := profile.NewStore(dir)
	itemA, err := store.ImportLocal("a.yaml", []byte(profileYAML(port, "n1", "n2")))
	if err != nil {
		t.Fatal(err)
	}
	itemB, err := store.ImportLocal("b.yaml", []byte(profileYAML(port, "m1", "m2", "m3")))
	if err != nil {
		t.Fatal(err)
	}

	first := bootProfiles(t, dir)
	assertSelector(t, first, "PROXY", "n1")

	if err := first.SelectProxy("PROXY", "n2"); err != nil {
		t.Fatal(err)
	}
	assertSelector(t, first, "PROXY", "n2")

	if err := first.UseProfile(itemB.UID); err != nil {
		t.Fatal(err)
	}
	assertSelector(t, first, "PROXY", "m1")
	if err := first.SelectProxy("PROXY", "m3"); err != nil {
		t.Fatal(err)
	}
	assertSelector(t, first, "PROXY", "m3")

	if err := first.UseProfile(itemA.UID); err != nil {
		t.Fatal(err)
	}
	assertSelector(t, first, "PROXY", "n2")
	assertOneSelection(t, dir, itemA.UID, "PROXY", "n2")
	assertOneSelection(t, dir, itemB.UID, "PROXY", "m3")

	// Restart: a new window and a new profile.Store. The kernel object
	// is the one already started above. A second Start, or Reload here,
	// calls hub.Parse while a finalizer from the previous apply still
	// logs, and -race reports log.SetLevel against log.Debugln. Reset
	// the live selector to the profile default instead, then loadGroups
	// must put n2 back.
	again := newProfileHarness(dir)
	again.core = first.core
	again.loadProfiles()
	if again.Model().CurrentProfile != itemA.UID {
		t.Fatalf("fresh store current %q, want %s", again.Model().CurrentProfile, itemA.UID)
	}
	if err := again.installCurrentProfile(); err != nil {
		t.Fatal(err)
	}
	if err := again.core.Select("PROXY", "n1"); err != nil {
		t.Fatal(err)
	}
	again.loadGroups()
	assertSelector(t, again, "PROXY", "n2")
	assertOneSelection(t, dir, itemA.UID, "PROXY", "n2")
	assertOneSelection(t, dir, itemB.UID, "PROXY", "m3")
}

// TestSavedSelectionSkipsMissingNode keeps the group's default when the
// saved node is not in the profile. The kernel stays stopped.
func TestSavedSelectionSkipsMissingNode(t *testing.T) {
	dir := t.TempDir()
	store := profile.NewStore(dir)
	item, err := store.ImportLocal("a.yaml", []byte(profileYAML(7897, "n1", "n2")))
	if err != nil {
		t.Fatal(err)
	}
	if err := store.RecordSelected(item.UID, "PROXY", "ghost"); err != nil {
		t.Fatal(err)
	}
	if err := store.RecordSelected(item.UID, "OTHER", "n2"); err != nil {
		t.Fatal(err)
	}
	a := newProfileHarness(dir)
	a.loadProfiles()
	if err := a.installCurrentProfile(); err != nil {
		t.Fatal(err)
	}
	a.loadGroups()
	m := a.Model()
	if len(m.Groups) != 1 || m.Groups[0].Now != "n1" || m.Home.Node.Name != "n1" {
		t.Fatalf("missing node was applied: groups %+v home %+v", m.Groups, m.Home.Node)
	}
	cur := m.CurrentItem()
	if cur == nil || len(cur.Selected) != 2 {
		t.Fatalf("selected was not copied into the model: %+v", cur)
	}
}

// processKernel starts mihomo once per test process. Every later call
// returns that same Core. A second Start races the logger finalizer
// under -race, so tests reload this core instead of starting another.
var (
	kernelOnce sync.Once
	kernelCore coreEngine
	kernelErr  error
)

func bootProfiles(t *testing.T, dir string) *App {
	t.Helper()
	a := newProfileHarness(dir)
	a.loadProfiles()
	if err := a.installCurrentProfile(); err != nil {
		t.Fatal(err)
	}
	kernelOnce.Do(func() {
		kernelCore = a.core
		kernelErr = kernelCore.Start(dir)
	})
	if kernelErr != nil {
		t.Fatal(kernelErr)
	}
	a.core = kernelCore
	a.loadGroups()
	return a
}

func assertSelector(t *testing.T, a *App, group, node string) {
	t.Helper()
	m := a.Model()
	if len(m.Groups) != 1 || m.Groups[0].Name != group || m.Groups[0].Now != node {
		t.Fatalf("ui group %+v, want %s=%s", m.Groups, group, node)
	}
	if m.Home.Node.Name != node || m.Home.Node.Group != group {
		t.Fatalf("home node %+v, want %s=%s", m.Home.Node, group, node)
	}
	got, err := a.core.Selected(group)
	if err != nil {
		t.Fatal(err)
	}
	if got != node {
		t.Fatalf("kernel Now() %q, ui %q", got, node)
	}
	m.Router.Replace("/proxies")
	tt := newPageTester(m)
	if !tt.HasText(node) {
		t.Fatalf("proxies page does not show %s, texts %q", node, tt.Texts())
	}
}

func assertOneSelection(t *testing.T, dir, uid, group, node string) {
	t.Helper()
	f, err := profile.NewStore(dir).Load()
	if err != nil {
		t.Fatal(err)
	}
	var found *profile.CatalogItem
	for i := range f.Items {
		if f.Items[i].UID == uid {
			found = &f.Items[i]
			break
		}
	}
	if found == nil {
		t.Fatalf("profile %s missing", uid)
	}
	n := 0
	now := ""
	for _, sel := range found.Selected {
		if sel.Name == group {
			n++
			now = sel.Now
		}
	}
	if n != 1 || now != node {
		t.Fatalf("profile %s selected %+v, want one %s=%s", uid, found.Selected, group, node)
	}
}

func profileYAML(port int, nodes ...string) string {
	var b strings.Builder
	fmt.Fprintf(&b, `mixed-port: %d
socks-port: 0
port: 0
redir-port: 0
tproxy-port: 0
allow-lan: false
mode: rule
log-level: error
ipv6: false
find-process-mode: off
geo-auto-update: false
profile:
  store-selected: true
dns:
  enable: false
proxies:
`, port)
	for _, n := range nodes {
		fmt.Fprintf(&b, "  - {name: %s, type: direct}\n", n)
	}
	b.WriteString("proxy-groups:\n  - {name: PROXY, type: select, proxies: [")
	for i, n := range nodes {
		if i > 0 {
			b.WriteString(", ")
		}
		b.WriteString(n)
	}
	b.WriteString("]}\nrules:\n  - MATCH,PROXY\n")
	return b.String()
}

func freePort(t *testing.T) int {
	t.Helper()
	var last error
	var held []net.PacketConn
	defer func() {
		for _, socket := range held {
			_ = socket.Close()
		}
	}()
	for i := 0; i < 1024; i++ {
		udp, err := net.ListenPacket("udp4", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		port := udp.LocalAddr().(*net.UDPAddr).Port
		tcp, err := net.Listen("tcp4", fmt.Sprintf("127.0.0.1:%d", port))
		if err == nil {
			_ = tcp.Close()
			_ = udp.Close()
			return port
		}
		last = err
		held = append(held, udp)
	}
	t.Fatalf("could not reserve a TCP and UDP port: %v", last)
	return 0
}
