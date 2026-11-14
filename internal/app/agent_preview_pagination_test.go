package app

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/neko233-com/netflow/internal/agent"
)

func TestPreviewRulePaginationBoundsAndExpiry(t *testing.T) {
	rules := make([]string, 200)
	for i := range rules {
		rules[i] = strings.Repeat("<", 2000)
	}
	a := &App{agentProposals: map[string]agentProposal{"valid": {before: rules, after: rules, expires: time.Now().Add(time.Minute)}}}
	var collected []string
	for offset := 0; offset < len(rules); {
		page, err := a.agentPreviewRules(agent.PreviewRulesArgs{ProposalID: "valid", Stage: "after", Offset: offset, Limit: 100})
		if err != nil || page.Offset != offset || page.Total != len(rules) || page.NextOffset <= offset {
			t.Fatalf("invalid page: %+v %v", page, err)
		}
		data, err := json.Marshal(page.Rules)
		if err != nil || len(data) > maxPreviewPageBytes {
			t.Fatalf("oversized page: %d %v", len(data), err)
		}
		collected = append(collected, page.Rules...)
		offset = page.NextOffset
	}
	if !reflect.DeepEqual(collected, rules) {
		t.Fatal("pages omitted or reordered rules")
	}
	for _, in := range []agent.PreviewRulesArgs{{ProposalID: "valid", Stage: "bad"}, {ProposalID: "valid", Stage: "after", Offset: -1}, {ProposalID: "valid", Stage: "after", Limit: 501}} {
		if _, err := a.agentPreviewRules(in); err == nil {
			t.Fatalf("invalid page accepted: %+v", in)
		}
	}
	if _, err := previewRulePage([]string{strings.Repeat("<", maxPreviewPageBytes)}, 0, 1); err == nil {
		t.Fatal("oversized single rule accepted")
	}
	exact, err := previewRulePage([]string{strings.Repeat("x", maxPreviewPageBytes-4)}, 0, 1)
	if err != nil || exact.NextOffset != 1 {
		t.Fatalf("exact byte boundary did not advance: %d %v", exact.NextOffset, err)
	}
	large := make([]string, 17000)
	largeRule := strings.Repeat("x", 4000)
	for i := range large {
		large[i] = largeRule
	}
	if _, err := previewRuleFootprint(large); err == nil {
		t.Fatal("oversized retained rules accepted")
	}
	a.agentProposals["expired"] = agentProposal{expires: time.Now().Add(-time.Second), after: rules}
	if _, err := a.agentPreviewRules(agent.PreviewRulesArgs{ProposalID: "expired", Stage: "after"}); err == nil {
		t.Fatal("expired proposal accepted")
	}
	if _, ok := a.agentProposals["expired"]; ok {
		t.Fatal("expired proposal retained")
	}
	a.agentProposals["expired"] = agentProposal{expires: time.Now().Add(-time.Second), after: rules}
	a.pruneExpiredProposals(time.Now())
	if _, ok := a.agentProposals["expired"]; ok {
		t.Fatal("periodic cleanup retained an expired proposal")
	}
	if _, ok := a.agentProposals["valid"]; !ok {
		t.Fatal("periodic cleanup removed an active proposal")
	}
}
