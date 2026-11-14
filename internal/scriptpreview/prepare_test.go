package scriptpreview

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/neko233-com/netflow/internal/migration"
	"github.com/neko233-com/netflow/internal/validation"
)

func prepareFixture(t *testing.T) PrepareInput {
	t.Helper()
	root, item, base := fixture(t)
	return PrepareInput{Root: root, Archive: item.Option.VergeArchive, UID: item.Option.VergeUID, ProfileName: item.Name,
		Base: base, Baseline: base, Selection: migration.ScriptSelection{Global: true, Profile: true}, Clock: time.Date(2026, 11, 15, 1, 2, 3, 0, time.UTC),
		Finalize: func(_ context.Context, b []byte) ([]byte, error) { return b, nil },
		Validate: func(_ context.Context, b []byte) (validation.Result, error) {
			if !strings.Contains(string(b), "DOMAIN,Example,DIRECT") {
				t.Fatal("validator received wrong config")
			}
			return validation.Result{Sources: map[string][32]byte{}, Warnings: []string{"private secret"}}, nil
		},
		Check: func(_ context.Context, c Candidate, v validation.Result) error {
			if len(c.Steps) != 2 || v.Sources == nil {
				t.Fatal("check received incomplete candidate")
			}
			return nil
		},
	}
}

func TestPrepareValidatesEffectiveConfigAndReportsRules(t *testing.T) {
	in := prepareFixture(t)
	p, err := Prepare(context.Background(), in)
	if err != nil {
		t.Fatal(err)
	}
	if len(p.BeforeRules) != 1 || p.BeforeRules[0] != "MATCH,DIRECT" || len(p.AfterRules) != 2 || p.AfterRules[0] != "DOMAIN,Example,DIRECT" {
		t.Fatal("rules not preserved")
	}
	if len(p.Validation.Warnings) != 1 || strings.Contains(p.Validation.Warnings[0], "secret") {
		t.Fatal("warning leaked")
	}
	if len(p.Changes.Fields) == 0 {
		t.Fatal("missing changes")
	}
}

func TestPrepareSanitizesFailuresAndRejectsMutation(t *testing.T) {
	tests := []struct {
		name   string
		change func(*PrepareInput)
		want   error
	}{
		{"finalize", func(in *PrepareInput) {
			in.Finalize = func(context.Context, []byte) ([]byte, error) { return nil, errors.New("secret") }
		}, ErrFinalize},
		{"validator", func(in *PrepareInput) {
			in.Validate = func(context.Context, []byte) (validation.Result, error) {
				return validation.Result{}, errors.New("secret")
			}
		}, ErrValidation},
		{"mutation", func(in *PrepareInput) {
			in.Validate = func(_ context.Context, b []byte) (validation.Result, error) {
				b[0] ^= 1
				return validation.Result{Sources: map[string][32]byte{}}, nil
			}
		}, ErrValidation},
		{"check", func(in *PrepareInput) {
			in.Check = func(context.Context, Candidate, validation.Result) error { return errors.New("secret") }
		}, ErrSourcesChanged},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			in := prepareFixture(t)
			tt.change(&in)
			_, err := Prepare(context.Background(), in)
			if !errors.Is(err, tt.want) || strings.Contains(err.Error(), "secret") {
				t.Fatalf("unexpected error: %v", err)
			}
		})
	}
}

func TestPaginateRulesBoundsAndPreservesItems(t *testing.T) {
	rules := []string{"DOMAIN,例子,DIRECT", "MATCH,DIRECT"}
	page, err := PaginateRules(rules, 0, 1)
	if err != nil || len(page.Rules) != 1 || page.Rules[0] != rules[0] || page.Next == nil || *page.Next != 1 {
		t.Fatal("incorrect first page", err)
	}
	page, err = PaginateRules(rules, *page.Next, 1)
	if err != nil || len(page.Rules) != 1 || page.Rules[0] != rules[1] || page.Next != nil {
		t.Fatal("incorrect last page", err)
	}
	if _, err := PaginateRules(rules, -1, 1); err == nil {
		t.Fatal("negative offset accepted")
	}
	if _, err := PaginateRules(rules, 0, 501); err == nil {
		t.Fatal("large limit accepted")
	}
	if _, err := PaginateRules([]string{strings.Repeat("x", 256<<10)}, 0, 1); err == nil {
		t.Fatal("oversize rule accepted")
	}
}

func TestPrepareRejectsArchiveChangedDuringValidation(t *testing.T) {
	in := prepareFixture(t)
	in.Validate = func(_ context.Context, _ []byte) (validation.Result, error) {
		path := filepath.Join(in.Root, in.Archive)
		body, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		body[len(body)-1] ^= 1
		if err := os.WriteFile(path, body, 0600); err != nil {
			t.Fatal(err)
		}
		return validation.Result{Sources: map[string][32]byte{}}, nil
	}
	if _, err := Prepare(context.Background(), in); !errors.Is(err, ErrSourcesChanged) {
		t.Fatalf("changed archive accepted: %v", err)
	}
}
