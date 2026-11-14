package scriptapproval

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/neko233-com/netflow/internal/migration"
	"github.com/neko233-com/netflow/internal/profile"
	"github.com/neko233-com/netflow/internal/scriptpreview"
)

func candidateFixture(t *testing.T) (string, profile.CatalogItem, []byte, scriptpreview.Candidate) {
	t.Helper()
	source := t.TempDir()
	if err := os.Mkdir(filepath.Join(source, "profiles"), 0700); err != nil {
		t.Fatal(err)
	}
	files := map[string]string{
		"profiles.yaml":    "current: p1\nitems:\n  - {uid: p1, type: local, name: Example, file: p1.yaml, option: {script: s1}}\n  - {uid: s1, type: script, file: s1.js}\n",
		"profiles/p1.yaml": "rules: ['MATCH,DIRECT']\n",
		"profiles/s1.js":   `function main(c){c.rules.unshift("DOMAIN,example.test,DIRECT");return c}`,
	}
	for name, data := range files {
		if err := os.WriteFile(filepath.Join(source, filepath.FromSlash(name)), []byte(data), 0600); err != nil {
			t.Fatal(err)
		}
	}
	src, err := migration.ReadVerge(source)
	if err != nil {
		t.Fatal(err)
	}
	root := t.TempDir()
	if _, err := src.ImportVerge(root); err != nil {
		t.Fatal(err)
	}
	catalog, err := profile.NewStore(root).Load()
	if err != nil || len(catalog.Items) != 1 {
		t.Fatal("missing profile", err)
	}
	item := catalog.Items[0]
	base, err := os.ReadFile(filepath.Join(root, item.File))
	if err != nil {
		t.Fatal(err)
	}
	c, err := scriptpreview.Build(context.Background(), root, item.Option.VergeArchive, item.Option.VergeUID, base, item.Name, migration.ScriptSelection{Profile: true}, time.Date(2026, 11, 14, 12, 0, 0, 0, time.UTC))
	if err != nil {
		t.Fatal(err)
	}
	return root, item, base, c
}

func TestStoreAndResolveRejectStaleOrTamperedInputs(t *testing.T) {
	root, item, base, c := candidateFixture(t)
	ctx := context.Background()
	a, err := Store(ctx, root, c, base, item.Name)
	if err != nil {
		t.Fatal(err)
	}
	second, err := Store(ctx, root, c, base, item.Name)
	if err != nil || second != a {
		t.Fatal("idempotent store failed", err)
	}
	body, err := Resolve(ctx, root, a, base, item.Name, item.Option.VergeArchive, item.Option.VergeUID)
	if err != nil || !bytes.Equal(body, c.Body) {
		t.Fatal("approved body mismatch", err)
	}
	checks := []struct {
		base               []byte
		name, archive, uid string
	}{
		{append(append([]byte(nil), base...), '\n'), item.Name, item.Option.VergeArchive, item.Option.VergeUID},
		{base, item.Name + "x", item.Option.VergeArchive, item.Option.VergeUID},
		{base, item.Name, item.Option.VergeArchive + "x", item.Option.VergeUID},
		{base, item.Name, item.Option.VergeArchive, item.Option.VergeUID + "x"},
	}
	for _, check := range checks {
		if _, err := Resolve(ctx, root, a, check.base, check.name, check.archive, check.uid); !errors.Is(err, ErrChanged) {
			t.Fatal("changed input accepted", err)
		}
	}
	rel, err := cachePath(a)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(root, rel)
	if err := os.WriteFile(path, []byte("tampered"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := Resolve(ctx, root, a, base, item.Name, item.Option.VergeArchive, item.Option.VergeUID); !errors.Is(err, ErrChanged) {
		t.Fatal("tampered output accepted", err)
	}
	if _, err := Store(ctx, root, c, base, item.Name); !errors.Is(err, ErrChanged) {
		t.Fatal("tampered cache was overwritten", err)
	}
}

func TestApprovalBindsVergeRuleOrdering(t *testing.T) {
	root, item, base, legacy := candidateFixture(t)
	ctx := context.Background()
	modern, err := scriptpreview.BuildWithRules(ctx, root, item.Option.VergeArchive, item.Option.VergeUID, base, item.Name, legacy.Selection, legacy.Clock, true)
	if err != nil {
		t.Fatal(err)
	}
	oldApproval, err := Store(ctx, root, legacy, base, item.Name)
	if err != nil {
		t.Fatal(err)
	}
	newApproval, err := Store(ctx, root, modern, base, item.Name)
	if err != nil || !newApproval.RulesBeforeScripts {
		t.Fatal("modern approval missing ordering", err)
	}
	oldPath, _ := cachePath(oldApproval)
	newPath, _ := cachePath(newApproval)
	if oldPath == newPath {
		t.Fatal("different ordering shared an approval cache key")
	}
	if _, err := ResolveSnapshot(ctx, root, newApproval, base, item.Name, item.Option.VergeArchive, item.Option.VergeUID); !errors.Is(err, ErrChanged) {
		t.Fatal("new approval accepted as legacy", err)
	}
	if _, err := ResolveSnapshotWithRules(ctx, root, oldApproval, base, item.Name, item.Option.VergeArchive, item.Option.VergeUID, true); !errors.Is(err, ErrChanged) {
		t.Fatal("legacy approval accepted as new ordering", err)
	}
	if _, err := ResolveSnapshotWithRules(ctx, root, newApproval, base, item.Name, item.Option.VergeArchive, item.Option.VergeUID, true); err != nil {
		t.Fatal(err)
	}
}

func TestResolveRejectsArchiveChangesAndInvalidMetadata(t *testing.T) {
	root, item, base, c := candidateFixture(t)
	ctx := context.Background()
	a, err := Store(ctx, root, c, base, item.Name)
	if err != nil {
		t.Fatal(err)
	}
	bad := a
	bad.OutputSHA256 = "../../outside"
	if _, err := Resolve(ctx, root, bad, base, item.Name, item.Option.VergeArchive, item.Option.VergeUID); !errors.Is(err, ErrChanged) {
		t.Fatal("invalid digest accepted", err)
	}
	bad = a
	bad.Clock = bad.Clock.Add(time.Second)
	if _, err := Resolve(ctx, root, bad, base, item.Name, item.Option.VergeArchive, item.Option.VergeUID); !errors.Is(err, ErrChanged) {
		t.Fatal("changed approval time accepted", err)
	}
	path := filepath.Join(root, item.Option.VergeArchive)
	body, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	body[len(body)-1] ^= 1
	if err := os.WriteFile(path, body, 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := Resolve(ctx, root, a, base, item.Name, item.Option.VergeArchive, item.Option.VergeUID); !errors.Is(err, ErrChanged) {
		t.Fatal("changed archive accepted", err)
	}
}

func TestStoreRespectsCancellation(t *testing.T) {
	root, item, base, c := candidateFixture(t)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := Store(ctx, root, c, base, item.Name); !errors.Is(err, context.Canceled) {
		t.Fatal("canceled store accepted", err)
	}
}

func TestCacheLimitKeepsExistingOutputsWithoutDeletingFiles(t *testing.T) {
	root, item, base, c := candidateFixture(t)
	ctx := context.Background()
	if _, err := Store(ctx, root, c, base, item.Name); err != nil {
		t.Fatal(err)
	}
	dir := filepath.Join(root, "verge-script-outputs")
	for i := 0; i < 127; i++ {
		if err := os.WriteFile(filepath.Join(dir, fmt.Sprintf("filler-%03d", i)), nil, 0600); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := Store(ctx, root, c, base, item.Name); err != nil {
		t.Fatal("existing output should remain reusable", err)
	}
	other, err := scriptpreview.Build(ctx, root, item.Option.VergeArchive, item.Option.VergeUID, base, item.Name, migration.ScriptSelection{Profile: true}, c.Clock.Add(time.Second))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Store(ctx, root, other, base, item.Name); !errors.Is(err, ErrCacheFull) {
		t.Fatal("full cache accepted", err)
	}
	if _, err := os.Stat(filepath.Join(dir, "filler-000")); err != nil {
		t.Fatal("existing file removed", err)
	}
}

func TestPruneKeepsReferencesAndUnknownFiles(t *testing.T) {
	root, item, base, c := candidateFixture(t)
	ctx := context.Background()
	keep, err := Store(ctx, root, c, base, item.Name)
	if err != nil {
		t.Fatal(err)
	}
	other, err := scriptpreview.Build(ctx, root, item.Option.VergeArchive, item.Option.VergeUID, base, item.Name, migration.ScriptSelection{Profile: true}, c.Clock.Add(time.Second))
	if err != nil {
		t.Fatal(err)
	}
	drop, err := Store(ctx, root, other, base, item.Name)
	if err != nil {
		t.Fatal(err)
	}
	unknown := filepath.Join(root, "verge-script-outputs", "user-file.txt")
	if err := os.WriteFile(unknown, []byte("user"), 0600); err != nil {
		t.Fatal(err)
	}
	if result, err := Prune(ctx, root, []Approval{keep}, func() error { return errors.New("changed") }); err == nil || result.Removed != 0 {
		t.Fatal("guard failure removed data", err)
	}
	result, err := Prune(ctx, root, []Approval{keep}, func() error { return nil })
	if err != nil || result.Removed != 1 {
		t.Fatal("prune result incorrect", result, err)
	}
	if _, err := Resolve(ctx, root, keep, base, item.Name, item.Option.VergeArchive, item.Option.VergeUID); err != nil {
		t.Fatal("referenced output removed", err)
	}
	if _, err := Resolve(ctx, root, drop, base, item.Name, item.Option.VergeArchive, item.Option.VergeUID); !errors.Is(err, ErrChanged) {
		t.Fatal("unreferenced output not removed", err)
	}
	if data, err := os.ReadFile(unknown); err != nil || string(data) != "user" {
		t.Fatal("unknown file changed", err)
	}
}
