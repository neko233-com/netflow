package scriptpreview

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/neko233-com/netflow/internal/migration"
	"github.com/neko233-com/netflow/internal/profile"
)

func fixture(t *testing.T) (string, profile.CatalogItem, []byte) {
	t.Helper()
	source := t.TempDir()
	if err := os.Mkdir(filepath.Join(source, "profiles"), 0700); err != nil {
		t.Fatal(err)
	}
	files := map[string]string{
		"profiles.yaml":        "current: p1\nitems:\n  - uid: p1\n    type: local\n    name: Example\n    file: p1.yaml\n    option: {merge: m1, script: s1}\n  - {uid: Merge, type: merge, file: global.yaml}\n  - {uid: m1, type: merge, file: local.yaml}\n  - {uid: Script, type: script, file: global.js}\n  - {uid: s1, type: script, file: local.js}\n",
		"profiles/p1.yaml":     "mixed-port: 0\nrules: ['MATCH,DIRECT']\n",
		"profiles/global.yaml": "marker: global\n",
		"profiles/local.yaml":  "marker: profile\n",
		"profiles/global.js":   `function main(c,n){if(c.marker!=="global") throw Error();c.globalClock=Date.now();c.random=Math.random();return c;}`,
		"profiles/local.js":    `function main(c,n){if(c.marker!=="profile") throw Error();c.rules.unshift("DOMAIN,"+n+",DIRECT");return c;}`,
	}
	for name, body := range files {
		if err := os.WriteFile(filepath.Join(source, filepath.FromSlash(name)), []byte(body), 0600); err != nil {
			t.Fatal(err)
		}
	}
	src, err := migration.ReadVerge(source)
	if err != nil {
		t.Fatal(err)
	}
	target := t.TempDir()
	if _, err := src.ImportVerge(target); err != nil {
		t.Fatal(err)
	}
	catalog, err := profile.NewStore(target).Load()
	if err != nil || len(catalog.Items) != 1 {
		t.Fatal("missing imported profile", err)
	}
	item := catalog.Items[0]
	body, err := os.ReadFile(filepath.Join(target, item.File))
	if err != nil {
		t.Fatal(err)
	}
	return target, item, body
}
func TestBuildBindsArchiveSourceAndBothScriptStages(t *testing.T) {
	root, item, base := fixture(t)
	clock := time.Date(2026, 11, 15, 1, 2, 3, 0, time.UTC)
	selection := migration.ScriptSelection{Global: true, Profile: true}
	first, err := Build(context.Background(), root, item.Option.VergeArchive, item.Option.VergeUID, base, item.Name, selection, clock)
	if err != nil {
		t.Fatal(err)
	}
	second, err := Build(context.Background(), root, item.Option.VergeArchive, item.Option.VergeUID, base, item.Name, selection, clock)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(first.Body, second.Body) || first.OutputSHA256 != sha256.Sum256(first.Body) || first.BaseSHA256 != sha256.Sum256(base) || first.ArchiveSHA256 == ([32]byte{}) || len(first.Steps) != 2 || first.Steps[0].Scope != "global" || first.Steps[1].Scope != "profile" {
		t.Fatal("candidate was not stable or fully bound")
	}
	if !bytes.Contains(first.Body, []byte("DOMAIN,Example,DIRECT")) {
		t.Fatal("profile script did not modify rules")
	}
	changed, err := Build(context.Background(), root, item.Option.VergeArchive, item.Option.VergeUID, base, item.Name, selection, clock.Add(time.Second))
	if err != nil {
		t.Fatal(err)
	}
	if first.OutputSHA256 == changed.OutputSHA256 {
		t.Fatal("clock was not bound to output")
	}
	saved, err := os.ReadFile(filepath.Join(root, item.File))
	if err != nil || !bytes.Equal(saved, base) {
		t.Fatal("preview changed the subscription", err)
	}
}
func TestBuildRejectsCancellationAndMissingApprovalClock(t *testing.T) {
	root, item, base := fixture(t)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := Build(ctx, root, item.Option.VergeArchive, item.Option.VergeUID, base, item.Name, migration.ScriptSelection{}, time.Now()); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled preview: %v", err)
	}
	if _, err := Build(context.Background(), root, item.Option.VergeArchive, item.Option.VergeUID, base, item.Name, migration.ScriptSelection{}, time.Time{}); err == nil {
		t.Fatal("missing clock accepted")
	}
}

func TestCandidateCheckCurrentRejectsStaleOrTamperedInputs(t *testing.T) {
	root, item, base := fixture(t)
	clock := time.Date(2026, 11, 15, 1, 2, 3, 0, time.UTC)
	selection := migration.ScriptSelection{Global: true, Profile: true}
	candidate, err := Build(context.Background(), root, item.Option.VergeArchive, item.Option.VergeUID, base, item.Name, selection, clock)
	if err != nil {
		t.Fatal(err)
	}
	check := func(data []byte, name string, s migration.ScriptSelection, when time.Time) error {
		return candidate.CheckCurrent(context.Background(), root, data, name, s, when)
	}
	if err := check(base, item.Name, selection, clock); err != nil {
		t.Fatal(err)
	}
	if err := check(append(append([]byte(nil), base...), '\n'), item.Name, selection, clock); err == nil {
		t.Fatal("changed base accepted")
	}
	if err := check(base, item.Name+"x", selection, clock); err == nil {
		t.Fatal("changed profile name accepted")
	}
	if err := check(base, item.Name, migration.ScriptSelection{Global: true}, clock); err == nil {
		t.Fatal("changed selection accepted")
	}
	if err := check(base, item.Name, selection, clock.Add(time.Second)); err == nil {
		t.Fatal("changed clock accepted")
	}
	candidate.Body[0] ^= 1
	if err := check(base, item.Name, selection, clock); err == nil {
		t.Fatal("changed output accepted")
	}
	candidate.Body[0] ^= 1
	candidate.Steps[0].ScriptSHA256[0] ^= 1
	if err := check(base, item.Name, selection, clock); err == nil {
		t.Fatal("changed script identity accepted")
	}
	candidate.Steps[0].ScriptSHA256[0] ^= 1
	archive := filepath.Join(root, item.Option.VergeArchive)
	data, err := os.ReadFile(archive)
	if err != nil {
		t.Fatal(err)
	}
	data[len(data)-1] ^= 1
	if err := os.WriteFile(archive, data, 0600); err != nil {
		t.Fatal(err)
	}
	if err := check(base, item.Name, selection, clock); err == nil {
		t.Fatal("changed archive accepted")
	}
}

func TestDataOnlyRecoveryRequiresExactBaseAndNoScripts(t *testing.T) {
	root, item, base := fixture(t)
	clock := time.Now().UTC()
	c := Candidate{Body: append([]byte(nil), base...), BaseSHA256: sha256.Sum256(base), ProfileNameSHA256: sha256.Sum256([]byte(item.Name)), OutputSHA256: sha256.Sum256(base), ArchiveRelative: item.Option.VergeArchive, VergeUID: item.Option.VergeUID, Clock: clock, DataOnlyWithoutArchive: true}
	if err := c.CheckCurrent(context.Background(), root, base, item.Name, migration.ScriptSelection{}, clock); err != nil {
		t.Fatal(err)
	}
	c.Body = append(c.Body, '\n')
	c.OutputSHA256 = sha256.Sum256(c.Body)
	if err := c.CheckCurrent(context.Background(), root, base, item.Name, migration.ScriptSelection{}, clock); err == nil {
		t.Fatal("recovery changed raw base")
	}
	c.Body = append([]byte(nil), base...)
	c.OutputSHA256 = sha256.Sum256(base)
	c.Selection.Profile = true
	if err := c.CheckCurrent(context.Background(), root, base, item.Name, c.Selection, clock); err == nil {
		t.Fatal("recovery selected a script")
	}
}
