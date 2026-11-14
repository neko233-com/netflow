package scriptpreview

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"time"

	"github.com/neko233-com/netflow/internal/migration"
	"github.com/neko233-com/netflow/internal/profile"
	"github.com/neko233-com/netflow/internal/rewrite"
	"github.com/neko233-com/netflow/internal/validation"
	"github.com/neko233-com/netflow/internal/vergescript"
)

var (
	ErrFinalize       = errors.New("script preview configuration could not be composed")
	ErrValidation     = errors.New("script preview configuration did not pass validation")
	ErrSourcesChanged = errors.New("script preview sources changed; preview again")
	ErrCandidate      = errors.New("script preview candidate could not be built")
)

// Prepared contains potentially secret configuration and rules. It must be
// kept private; callers may explicitly expose individual paginated rules.
type Prepared struct {
	Candidate               Candidate
	Baseline                []byte
	Effective               []byte
	EffectiveSHA256         [32]byte
	Changes                 TopLevelChanges
	BeforeRules, AfterRules []string
	Validation              validation.Result
}

type PrepareInput struct {
	Root, Archive, UID, ProfileName string
	Base, Baseline                  []byte
	Selection                       migration.ScriptSelection
	Clock                           time.Time
	// Finalize must apply all NetFlow-owned layers to the script output.
	Finalize func(context.Context, []byte) ([]byte, error)
	// Validate must validate the complete effective configuration offline.
	Validate func(context.Context, []byte) (validation.Result, error)
	// Check must check app state and validation sources against fresh snapshots.
	Check func(context.Context, Candidate, validation.Result) error
}

// Prepare builds a read-only candidate and validates it. The caller must
// recheck all sources and the effective digest immediately before application.
func Prepare(ctx context.Context, in PrepareInput) (Prepared, error) {
	var empty Prepared
	if ctx == nil || in.Finalize == nil || in.Validate == nil || in.Check == nil {
		return empty, errors.New("incomplete script preview")
	}
	if err := ctx.Err(); err != nil {
		return empty, err
	}
	candidate, err := Build(ctx, in.Root, in.Archive, in.UID, in.Base, in.ProfileName, in.Selection, in.Clock)
	if err != nil {
		return empty, cleanError(ctx, ErrCandidate)
	}
	return prepareCandidate(ctx, in, candidate, false)
}

// PrepareCandidate validates a trusted previously reviewed candidate, for
// example a rollback target restored from an immutable approval. The caller
// must establish that candidate.Body corresponds to the intended history.
func PrepareCandidate(ctx context.Context, in PrepareInput, candidate Candidate) (Prepared, error) {
	return prepareCandidate(ctx, in, candidate, true)
}

func prepareCandidate(ctx context.Context, in PrepareInput, candidate Candidate, checkInitial bool) (Prepared, error) {
	var empty Prepared
	if ctx == nil || in.Finalize == nil || in.Validate == nil || in.Check == nil {
		return empty, errors.New("incomplete script preview")
	}
	if candidate.ArchiveRelative != in.Archive || candidate.VergeUID != in.UID || len(candidate.Body) == 0 || len(candidate.Body) > vergescript.MaxJSONBytes {
		return empty, cleanError(ctx, ErrCandidate)
	}
	if checkInitial {
		if err := candidate.CheckCurrent(ctx, in.Root, in.Base, in.ProfileName, in.Selection, in.Clock); err != nil {
			return empty, cleanError(ctx, ErrSourcesChanged)
		}
	}
	effective, err := in.Finalize(ctx, append([]byte(nil), candidate.Body...))
	if err != nil || len(effective) == 0 || len(effective) > vergescript.MaxJSONBytes {
		return empty, cleanError(ctx, ErrFinalize)
	}
	effective = append([]byte(nil), effective...)
	changes, err := Summarize(ctx, in.Baseline, effective)
	if err != nil {
		return empty, cleanError(ctx, ErrFinalize)
	}
	before, err := extractRules(ctx, in.Baseline)
	if err != nil {
		return empty, cleanError(ctx, ErrFinalize)
	}
	after, err := extractRules(ctx, effective)
	if err != nil {
		return empty, cleanError(ctx, ErrFinalize)
	}
	var ruleBytes int
	for _, list := range [][]string{before, after} {
		for _, rule := range list {
			ruleBytes += len(rule) + 16
			if ruleBytes > 64<<20 {
				return empty, cleanError(ctx, ErrFinalize)
			}
		}
	}
	hash := sha256.Sum256(effective)
	validationBody := append([]byte(nil), effective...)
	checked, err := in.Validate(ctx, validationBody)
	if err != nil || checked.Sources == nil || len(checked.Sources) > 5000 || sha256.Sum256(validationBody) != hash {
		return empty, cleanError(ctx, ErrValidation)
	}
	// Warnings may contain configuration-derived secrets. Only expose a fixed
	// message rather than returning arbitrary validator output.
	sources := make(map[string][32]byte, len(checked.Sources))
	for key, value := range checked.Sources {
		sources[key] = value
	}
	checked.Sources = sources
	if len(checked.Warnings) > 0 {
		checked.Warnings = []string{"Some external resources were not fully validated."}
	}
	if err := candidate.CheckCurrent(ctx, in.Root, in.Base, in.ProfileName, in.Selection, in.Clock); err != nil {
		return empty, cleanError(ctx, ErrSourcesChanged)
	}
	if err := in.Check(ctx, candidate, checked); err != nil {
		return empty, cleanError(ctx, ErrSourcesChanged)
	}
	if err := ctx.Err(); err != nil {
		return empty, err
	}
	return Prepared{Candidate: candidate, Baseline: append([]byte(nil), in.Baseline...), Effective: effective, EffectiveSHA256: hash, Changes: changes, BeforeRules: before, AfterRules: after, Validation: checked}, nil
}

func cleanError(ctx context.Context, fallback error) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	return fallback
}

func extractRules(ctx context.Context, body []byte) ([]string, error) {
	normalized, err := profile.VergeScriptJSONContext(ctx, body)
	if err != nil {
		return nil, err
	}
	_, rules, err := rewrite.Compose(normalized, rewrite.State{}, "", time.Time{})
	return rules, err
}

type RulePage struct {
	Rules  []string `json:"rules"`
	Total  int      `json:"total"`
	Offset int      `json:"offset"`
	Next   *int     `json:"next,omitempty"`
}

// PaginateRules bounds both count and encoded size and never splits a rule.
func PaginateRules(rules []string, offset, limit int) (RulePage, error) {
	if offset < 0 || offset > len(rules) || limit < 0 || limit > 500 {
		return RulePage{}, errors.New("invalid rule page")
	}
	if limit == 0 {
		limit = 100
	}
	page := RulePage{Rules: []string{}, Total: len(rules), Offset: offset}
	const maxBytes = 256 << 10
	size := 2
	for i := offset; i < len(rules) && len(page.Rules) < limit; i++ {
		encoded, err := json.Marshal(rules[i])
		if err != nil {
			return RulePage{}, errors.New("invalid rule")
		}
		if size+len(encoded)+1 > maxBytes {
			if len(page.Rules) == 0 {
				return RulePage{}, errors.New("rule is too large to preview")
			}
			break
		}
		page.Rules = append(page.Rules, rules[i])
		size += len(encoded) + 1
	}
	next := offset + len(page.Rules)
	if next < len(rules) {
		page.Next = &next
	}
	return page, nil
}
