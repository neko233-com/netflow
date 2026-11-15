package core

import (
	"errors"
	"time"

	C "github.com/metacubex/mihomo/constant"
)

// expiryRule is installed only for NetFlow's leading connection rules. It
// evaluates the deadline for every new match, independently of app timers,
// IPC, provider downloads, and subsequent kernel reloads.
type expiryRule struct {
	C.RuleWrapper
	deadline time.Time
}

func (r *expiryRule) Match(metadata *C.Metadata, helper C.RuleMatchHelper) (bool, string) {
	if r.expired() {
		return false, ""
	}
	return r.RuleWrapper.Match(metadata, helper)
}

func (r *expiryRule) expired() bool { return !time.Now().Before(r.deadline) }

func applyRuleExpirations(rules []C.Rule, deadlines []time.Time) error {
	if len(deadlines) > len(rules) {
		return errors.New("temporary rule metadata does not match configuration")
	}
	now := time.Now()
	for i, deadline := range deadlines {
		wrapped, ok := rules[i].(C.RuleWrapper)
		if !ok {
			return errors.New("temporary rule cannot be time limited")
		}
		// Anchor the persisted wall-clock deadline to the monotonic clock for
		// this kernel lifetime, so later clock changes cannot extend a rule.
		rules[i] = &expiryRule{RuleWrapper: wrapped, deadline: now.Add(deadline.Sub(now))}
	}
	return nil
}
