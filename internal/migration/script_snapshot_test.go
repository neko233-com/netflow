package migration

import (
	"bytes"
	"context"
	"crypto/sha256"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/neko233-com/netflow/internal/profile"
	"github.com/neko233-com/netflow/internal/vergescript"
)

func TestImportedVergeScriptsAreReadableWithoutAutomaticExecution(t *testing.T) {
	source := fixture(t)
	indexPath := filepath.Join(source, "profiles.yaml")
	index, err := os.ReadFile(indexPath)
	if err != nil {
		t.Fatal(err)
	}
	index = []byte(strings.Replace(string(index), "script: s1", "merge: m1, script: s1", 1))
	index = append(index, []byte("  - {uid: Script, type: script, file: global.js}\n  - {uid: Merge, type: merge, file: global.yaml}\n  - {uid: m1, type: merge, file: local.yaml}\n")...)
	if err := os.WriteFile(indexPath, index, 0600); err != nil {
		t.Fatal(err)
	}
	global := `function main(c, name) { if (c.marker !== "global") throw Error("global merge order"); c.rules.unshift("DOMAIN,global-" + name + ",DIRECT"); return c; }`
	local := `function main(c, name) { if (c.marker !== "profile") throw Error("profile merge order"); c.rules.unshift("DOMAIN,local-" + name + ",DIRECT"); return c; }`
	if err := os.WriteFile(filepath.Join(source, "profiles", "global.yaml"), []byte("marker: global\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(source, "profiles", "local.yaml"), []byte("marker: profile\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(source, "profiles", "global.js"), []byte(global), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(source, "profiles", "s1.js"), []byte(local), 0600); err != nil {
		t.Fatal(err)
	}
	src, err := ReadVerge(source)
	if err != nil {
		t.Fatal(err)
	}
	target := t.TempDir()
	if _, err := src.ImportVerge(target); err != nil {
		t.Fatal(err)
	}
	catalog, err := profile.NewStore(target).Load()
	if err != nil || len(catalog.Items) != 1 {
		t.Fatal(err)
	}
	item := catalog.Items[0]
	original, err := os.ReadFile(filepath.Join(target, item.File))
	if err != nil {
		t.Fatal(err)
	}
	snapshot, err := ReadArchivedScripts(target, item.Option.VergeArchive, item.Option.VergeUID)
	if err != nil {
		t.Fatal(err)
	}
	if snapshot.Global == nil || snapshot.Profile == nil || string(snapshot.Global.Source) != global || string(snapshot.Profile.Source) != local || snapshot.OriginalProfileName != "Test" {
		t.Fatal("script metadata lost during import")
	}
	if snapshot.Global.SHA256 != sha256.Sum256([]byte(global)) || snapshot.ArchiveSHA256 == ([32]byte{}) {
		t.Fatal("missing script or archive identity")
	}
	// The single archive snapshot keeps both merges and both scripts bound to
	// one hash. Execution here is test-only; import leaves scripts inert.
	snap, extensions, err := ReadArchivedCompositionSnapshot(target, item.Option.VergeArchive, item.Option.VergeUID)
	if err != nil {
		t.Fatal(err)
	}
	if snap.ArchiveSHA256 != snapshot.ArchiveSHA256 {
		t.Fatal("archive identities differ")
	}
	none, err := ComposeArchivedSnapshot(context.Background(), original, snap, extensions, "Test", ScriptSelection{}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(none, []byte("global-Test")) || bytes.Contains(none, []byte("local-Test")) {
		t.Fatal("unselected scripts executed")
	}
	second, err := ComposeArchivedSnapshot(context.Background(), original, snap, extensions, "Test", ScriptSelection{Global: true, Profile: true}, vergescript.RunYAML)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(second, []byte("DOMAIN,global-Test,DIRECT")) || !bytes.Contains(second, []byte("DOMAIN,local-Test,DIRECT")) {
		t.Fatalf("scripts did not transform imported profile: %s", second)
	}
	if _, err := ComposeArchivedSnapshot(context.Background(), original, snap, extensions, "Test", ScriptSelection{Global: true}, nil); err == nil {
		t.Fatal("missing executor accepted")
	}

	after, err := os.ReadFile(filepath.Join(target, item.File))
	if err != nil || !bytes.Equal(original, after) || strings.Contains(string(after), "global-Test") {
		t.Fatal("import or preview mutated subscription", err)
	}
}

func TestArchivedScriptsRejectMissingProfileReference(t *testing.T) {
	source := fixture(t)
	index := filepath.Join(source, "profiles.yaml")
	data, err := os.ReadFile(index)
	if err != nil {
		t.Fatal(err)
	}
	data = []byte(strings.Replace(string(data), "script: s1", "script: missing", 1))
	if err := os.WriteFile(index, data, 0600); err != nil {
		t.Fatal(err)
	}
	src, err := ReadVerge(source)
	if err != nil {
		t.Fatal(err)
	}
	target := t.TempDir()
	if _, err := src.ImportVerge(target); err != nil {
		t.Fatal(err)
	}
	catalog, err := profile.NewStore(target).Load()
	if err != nil {
		t.Fatal(err)
	}
	_, err = ReadArchivedScripts(target, catalog.Items[0].Option.VergeArchive, "p1")
	if err == nil {
		t.Fatal("missing explicit script reference was ignored")
	}
}

func TestRealVergeScriptSnapshots(t *testing.T) {
	source := os.Getenv("NETFLOW_TEST_VERGE_SOURCE")
	if source == "" {
		t.Skip("real Verge source not configured")
	}
	original, err := ReadVerge(source)
	if err != nil {
		t.Fatal("cannot read Verge source")
	}
	target := t.TempDir()
	if _, err := original.ImportVerge(target); err != nil {
		t.Fatal("cannot import Verge source")
	}
	catalog, err := profile.NewStore(target).Load()
	if err != nil || len(catalog.Items) == 0 {
		t.Fatal("empty migrated catalog")
	}
	for _, item := range catalog.Items {
		snapshot, err := ReadArchivedScripts(target, item.Option.VergeArchive, item.Option.VergeUID)
		if err != nil {
			t.Fatal("cannot read migrated script snapshot")
		}
		sourceIndex := original.itemByID[item.Option.VergeUID]
		sourceItem := original.index.Items[sourceIndex]
		expectedGlobal := original.extensionData("Script", "script")
		expectedLocal := original.extensionData(sourceItem.Option.Script, "script")
		if len(expectedGlobal) > 0 && (snapshot.Global == nil || !bytes.Equal(snapshot.Global.Source, expectedGlobal)) {
			t.Fatal("global script changed during migration")
		}
		if len(expectedLocal) > 0 && (snapshot.Profile == nil || !bytes.Equal(snapshot.Profile.Source, expectedLocal)) {
			t.Fatal("profile script changed during migration")
		}
	}
}
