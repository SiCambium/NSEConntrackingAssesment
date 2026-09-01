package ruleset

import (
	"testing"
	"time"

	"conntrackd/internal/risk"
	"conntrackd/internal/store"
)

func fixedScore(bucket risk.Bucket, score int) BucketScorer {
	return func(u store.PortUsage) risk.RiskResult {
		return risk.RiskResult{Score: score, Bucket: bucket, Reasons: nil}
	}
}

func TestGenerate_SkipsApprovedAndLowSampleAndLowRisk(t *testing.T) {
	now := time.Now()
	usage := []store.PortUsage{
		{Protocol: "TCP", DstPort: 443, Application: "amazon_aws", SampleCount: 50, LastSeen: now}, // approved
		{Protocol: "UDP", DstPort: 9999, Application: "", SampleCount: 1, LastSeen: now},           // too few samples
		{Protocol: "TCP", DstPort: 8080, Application: "http_alt", SampleCount: 10, LastSeen: now},  // low risk, excluded by default
		{Protocol: "TCP", DstPort: 23, Application: "telnet", SampleCount: 10, LastSeen: now},      // high risk, included
	}
	approved := map[string]bool{"TCP|443|amazon_aws": true}

	rules := Generate(usage, approved, func(u store.PortUsage) risk.RiskResult {
		if u.DstPort == 23 {
			return risk.RiskResult{Score: 60, Bucket: risk.BucketHigh}
		}
		return risk.RiskResult{Score: 10, Bucket: risk.BucketLow}
	}, Options{})

	if len(rules) != 1 {
		t.Fatalf("expected 1 rule (only the high-risk telnet bucket), got %d: %+v", len(rules), rules)
	}
	if rules[0].DstPort != "23" || rules[0].RuleAction != "deny" {
		t.Fatalf("unexpected rule: %+v", rules[0])
	}
}

func TestGenerate_NeverEmitsAllowOrCatchAllDeny(t *testing.T) {
	usage := []store.PortUsage{
		{Protocol: "TCP", DstPort: 4444, Application: "unknown", SampleCount: 5, LastSeen: time.Now()},
	}
	rules := Generate(usage, map[string]bool{}, fixedScore(risk.BucketHigh, 60), Options{})
	for _, r := range rules {
		if r.RuleAction != "deny" {
			t.Fatalf("expected every generated rule to be a deny rule, got %q", r.RuleAction)
		}
		if r.DstAddr == "" && r.DstType == "all" && r.DstPort == "" {
			t.Fatalf("rule looks like an unscoped catch-all deny, which must never be generated: %+v", r)
		}
	}
}

func TestGenerate_OrdersByRiskThenRecency(t *testing.T) {
	older := time.Now().Add(-time.Hour)
	newer := time.Now()
	usage := []store.PortUsage{
		{Protocol: "TCP", DstPort: 1, Application: "a", SampleCount: 5, LastSeen: older},
		{Protocol: "TCP", DstPort: 2, Application: "b", SampleCount: 5, LastSeen: newer},
		{Protocol: "TCP", DstPort: 3, Application: "c", SampleCount: 5, LastSeen: older},
	}
	rules := Generate(usage, map[string]bool{}, func(u store.PortUsage) risk.RiskResult {
		if u.DstPort == 3 {
			return risk.RiskResult{Score: 90, Bucket: risk.BucketCritical}
		}
		return risk.RiskResult{Score: 30, Bucket: risk.BucketMedium}
	}, Options{})

	if len(rules) != 3 {
		t.Fatalf("expected 3 rules, got %d", len(rules))
	}
	if rules[0].DstPort != "3" {
		t.Fatalf("expected highest-risk bucket (port 3) first, got %+v", rules[0])
	}
	if rules[1].DstPort != "2" {
		t.Fatalf("expected more-recently-seen bucket (port 2) before port 1, got %+v", rules[1])
	}
	// Precedence should increase monotonically down the list.
	if !(rules[0].Precedence < rules[1].Precedence && rules[1].Precedence < rules[2].Precedence) {
		t.Fatalf("expected increasing precedence, got %d, %d, %d", rules[0].Precedence, rules[1].Precedence, rules[2].Precedence)
	}
}

func TestGenerate_FlagsApplicationGroupRulesForManualSetup(t *testing.T) {
	usage := []store.PortUsage{
		{Protocol: "TCP", DstPort: 443, Application: "some_app", SampleCount: 5, LastSeen: time.Now()},
		{Protocol: "TCP", DstPort: 4444, Application: "", SampleCount: 5, LastSeen: time.Now()},
	}
	rules := Generate(usage, map[string]bool{}, fixedScore(risk.BucketHigh, 60), Options{})
	byPort := map[string]Rule{}
	for _, r := range rules {
		byPort[r.DstPort] = r
	}
	if !byPort["443"].RequiresManualGroupSetup || byPort["443"].Notes == "" {
		t.Fatalf("expected the application-tagged rule to require manual group setup with notes: %+v", byPort["443"])
	}
	if byPort["4444"].RequiresManualGroupSetup {
		t.Fatalf("expected the plain port-only rule to not require manual group setup: %+v", byPort["4444"])
	}
}

func TestGenerate_IncludeLowRiskOptIn(t *testing.T) {
	usage := []store.PortUsage{
		{Protocol: "TCP", DstPort: 8080, Application: "http_alt", SampleCount: 10, LastSeen: time.Now()},
	}
	rules := Generate(usage, map[string]bool{}, fixedScore(risk.BucketLow, 5), Options{IncludeLowRisk: true})
	if len(rules) != 1 {
		t.Fatalf("expected low-risk bucket included when IncludeLowRisk=true, got %d rules", len(rules))
	}
}
