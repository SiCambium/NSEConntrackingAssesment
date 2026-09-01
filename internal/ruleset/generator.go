// Package ruleset generates a deny-rule preview from observed port usage
// that isn't on the approved list. It is deliberately deny-only and
// manual-review-only:
//
//   - NSELocalSSH's own firewall config code marks the device's "allow"
//     filter-rule action as unconfirmed over CLI — only "deny" has a
//     verified working syntax. So this generator never emits or assumes an
//     allow rule, and never emits a catch-all "deny everything else" rule
//     either, since that would implicitly depend on approved traffic being
//     allowed back in by an unconfirmed primitive. It only emits named
//     deny rules for specific unapproved (protocol, port/application)
//     combinations, relying on the device's own default policy for
//     everything else.
//   - Output fields match NSELocalSSH's outbound-filter-rule model
//     one-to-one (see internal/nse/config_handlers_firewall.go upstream)
//     so a row can be transcribed straight into that app's Firewall
//     screen — this tool never pushes config over SSH itself.
package ruleset

import (
	"fmt"
	"time"

	"conntrackd/internal/risk"
	"conntrackd/internal/store"
)

// Rule mirrors NSELocalSSH's outbound filter rule fields (Name, RuleType,
// RuleAction, Protocol, Src*/Dst*, Precedence) so a row can be copied
// straight into that app's Firewall config screen.
type Rule struct {
	Name       string `json:"name"`
	RuleType   string `json:"rule_type"`   // always "ip" here — see RequiresManualGroupSetup
	RuleAction string `json:"rule_action"` // always "deny" — see package doc
	Protocol   string `json:"protocol"`
	SrcType    string `json:"src_type"`
	SrcAddr    string `json:"src_addr"`
	SrcMask    string `json:"src_mask"`
	DstType    string `json:"dst_type"`
	DstAddr    string `json:"dst_addr"`
	DstMask    string `json:"dst_mask"`
	DstPort    string `json:"dst_port"`
	Precedence int    `json:"precedence"`

	Reason                   string `json:"reason"`
	RiskBucket               string `json:"risk_bucket"`
	RequiresManualGroupSetup bool   `json:"requires_manual_group_setup"`
	Notes                    string `json:"notes,omitempty"`
}

// Options tunes what gets included.
type Options struct {
	MinSampleCount  int // skip buckets seen fewer times than this (default 3)
	IncludeLowRisk  bool
	PrecedenceStart int // default 100
	PrecedenceStep  int // default 10
}

func (o Options) withDefaults() Options {
	if o.MinSampleCount <= 0 {
		o.MinSampleCount = 3
	}
	if o.PrecedenceStart <= 0 {
		o.PrecedenceStart = 100
	}
	if o.PrecedenceStep <= 0 {
		o.PrecedenceStep = 10
	}
	return o
}

// BucketScorer computes a risk result for one port_usage row, so the
// generator can attach a risk bucket/reason without importing the web
// handler's reputation-lookup wiring directly.
type BucketScorer func(u store.PortUsage) risk.RiskResult

// Generate returns one deny Rule per port_usage bucket for firewallID that
// is not present in approved (keyed the same way store.ApprovedSet keys
// its map: "protocol|dst_port|application"), ordered by descending risk
// score then by last-seen. Buckets below opts.MinSampleCount are skipped
// as noise, and low-risk buckets are skipped unless IncludeLowRisk is set.
func Generate(usage []store.PortUsage, approved map[string]bool, score BucketScorer, opts Options) []Rule {
	opts = opts.withDefaults()

	type scored struct {
		u store.PortUsage
		r risk.RiskResult
	}
	var candidates []scored
	for _, u := range usage {
		key := fmt.Sprintf("%s|%d|%s", u.Protocol, u.DstPort, u.Application)
		if approved[key] {
			continue
		}
		if u.SampleCount < opts.MinSampleCount {
			continue
		}
		rr := score(u)
		if rr.Bucket == risk.BucketLow && !opts.IncludeLowRisk {
			continue
		}
		candidates = append(candidates, scored{u, rr})
	}

	// Higher risk first, then most-recently-seen first, for a stable and
	// useful review order.
	for i := 1; i < len(candidates); i++ {
		for j := i; j > 0 && less(candidates[j], candidates[j-1]); j-- {
			candidates[j], candidates[j-1] = candidates[j-1], candidates[j]
		}
	}

	rules := make([]Rule, 0, len(candidates))
	precedence := opts.PrecedenceStart
	for _, c := range candidates {
		name := ruleName(c.u)
		app := c.u.Application
		requiresGroup := app != ""

		rule := Rule{
			Name: name, RuleType: "ip", RuleAction: "deny", Protocol: c.u.Protocol,
			SrcType: "all", SrcAddr: "", SrcMask: "",
			DstType: "all", DstAddr: "any", DstMask: "",
			DstPort:    portString(c.u.DstPort),
			Precedence: precedence,
			Reason: fmt.Sprintf("seen %dx, %d distinct destination(s), last seen %s, risk=%s",
				c.u.SampleCount, c.u.DistinctDstIPs, c.u.LastSeen.Format(time.RFC3339), c.r.Bucket),
			RiskBucket:               string(c.r.Bucket),
			RequiresManualGroupSetup: requiresGroup,
		}
		if requiresGroup {
			rule.Notes = fmt.Sprintf(
				"Device DPI tags this traffic as %q. To deny by application rather than raw port, "+
					"create/verify an Application Group for %q on the device first — this preview only "+
					"names the port-based deny rule, since application-group membership isn't something "+
					"this tool can confirm exists.", app, app)
		}
		rules = append(rules, rule)
		precedence += opts.PrecedenceStep
	}
	return rules
}

func less(a, b struct {
	u store.PortUsage
	r risk.RiskResult
}) bool {
	if a.r.Score != b.r.Score {
		return a.r.Score > b.r.Score
	}
	return a.u.LastSeen.After(b.u.LastSeen)
}

func ruleName(u store.PortUsage) string {
	if u.Application != "" {
		return fmt.Sprintf("deny-%s-%s-%d", u.Application, u.Protocol, u.DstPort)
	}
	return fmt.Sprintf("deny-%s-%d", u.Protocol, u.DstPort)
}

func portString(p int) string {
	if p == 0 {
		return ""
	}
	return fmt.Sprintf("%d", p)
}
