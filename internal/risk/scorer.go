// Package risk scores connections and port-usage buckets against a small,
// additive heuristic model combining local signals (protocol/port
// legacy-ness, traffic volume, sample confidence) with cached threat-intel
// verdicts. Scores are meant to be computed on read, not persisted — see
// PLAN.md — since the inputs (fresh reputation lookups, updated usage
// stats) change independently of the underlying flow data, and a stored
// score would just go stale.
package risk

import "time"

type RiskReason struct {
	Code        string `json:"code"`
	Description string `json:"description"`
	Points      int    `json:"points"`
}

type Bucket string

const (
	BucketLow      Bucket = "low"
	BucketMedium   Bucket = "medium"
	BucketHigh     Bucket = "high"
	BucketCritical Bucket = "critical"
)

type RiskResult struct {
	Score   int          `json:"score"`
	Bucket  Bucket       `json:"bucket"`
	Reasons []RiskReason `json:"reasons"`
}

func bucketFor(score int) Bucket {
	switch {
	case score >= 80:
		return BucketCritical
	case score >= 55:
		return BucketHigh
	case score >= 25:
		return BucketMedium
	default:
		return BucketLow
	}
}

// ReputationInfo is the subset of a cached threat-intel verdict the scorer
// needs, decoupled from any specific provider's response shape.
type ReputationInfo struct {
	Classification string // "malicious" | "benign" | "unknown" | ""
	IsNoise        bool
	IsRIOT         bool
	Resolved       bool // true if a cache lookup actually returned a verdict
}

// ConnectionInput is what ScoreConnection needs about one flow.
type ConnectionInput struct {
	Protocol     string
	DstPort      int
	Application  string
	Direction    string // "LAN TO WAN" | "LAN TO LAN" | "WAN TO LAN" | "" | ...
	IsDstPrivate bool
	Bytes        int64 // tx+rx
	FirstSeen    time.Time
	Reputation   *ReputationInfo // nil if never looked up (e.g. private dst)
	// BucketSampleCount is how many times this connection's (protocol,
	// dst_port, application) bucket has been observed overall — feeds
	// LOW_CONFIDENCE_SAMPLE, since a single flow's own sample count isn't
	// meaningful (every open connection has been "sampled" every poll).
	BucketSampleCount int
	// BucketIsFirstContactForDst is true if this dst IP is new to the
	// bucket's port_usage_dst_ips set as of this poll.
	BucketIsFirstContactForDst bool
	Now                        time.Time
}

func ScoreConnection(in ConnectionInput) RiskResult {
	var reasons []RiskReason
	add := func(code, desc string, points int) { reasons = append(reasons, RiskReason{code, desc, points}) }

	if in.Reputation != nil && in.Reputation.Resolved {
		switch in.Reputation.Classification {
		case "malicious":
			add("GREYNOISE_MALICIOUS", "Destination IP is classified malicious by threat intel", 60)
		}
		if in.Reputation.IsNoise && in.Reputation.Classification != "malicious" && in.Reputation.Classification != "benign" {
			add("GREYNOISE_NOISE_UNKNOWN", "Destination IP is a known internet scanner with unconfirmed intent", 15)
		}
		if in.Reputation.IsRIOT {
			add("GREYNOISE_BENIGN_RIOT", "Destination is a known-good CDN/cloud service (RIOT)", -10)
		}
	} else if !in.IsDstPrivate && in.Now.Sub(in.FirstSeen) >= time.Duration(LongLivedThresholdSeconds)*time.Second {
		add("LONG_LIVED_UNVERIFIED", "Long-lived connection to a public destination with no reputation data yet", 10)
	}

	if legacyAdminPorts[in.DstPort] {
		add("LEGACY_ADMIN_PORT", "Destination port is a legacy remote-admin protocol (telnet/rexec/rlogin/rsh/rpcbind)", 30)
	}
	if cleartextPorts[in.DstPort] {
		add("CLEARTEXT_PROTOCOL", "Destination port is a plaintext protocol that can leak credentials/content", 25)
	} else if in.DstPort == cleartextHTTPPort {
		add("CLEARTEXT_PROTOCOL", "Plain HTTP — unencrypted", 10)
	}
	if in.Application == "" && !wellKnownPorts[in.DstPort] {
		add("UNRECOGNIZED_APP_ON_UNUSUAL_PORT", "No DPI application match on an uncommon port", 20)
	}
	if in.Bytes >= HighVolumeThresholdBytes && in.BucketIsFirstContactForDst {
		add("HIGH_VOLUME_FIRST_CONTACT", "High transfer volume to a destination not seen before on this port/app", 15)
	}
	if in.BucketSampleCount > 0 && in.BucketSampleCount < LowConfidenceSampleCount {
		add("LOW_CONFIDENCE_SAMPLE", "This port/application has only been observed a handful of times", 5)
	}
	if in.Direction == "LAN TO LAN" {
		add("INTERNAL_TRAFFIC", "Traffic stays inside the LAN", -5)
	}

	return finalize(reasons)
}

// PortUsageInput is what ScorePortUsage needs about one port_usage bucket.
type PortUsageInput struct {
	Protocol       string
	DstPort        int
	Application    string
	SampleCount    int
	TotalBytes     int64
	DistinctDstIPs int
	FirstSeen      time.Time
	Now            time.Time
	// Reputations holds a cached verdict for each distinct destination IP
	// in this bucket that has one; a bucket can have more DistinctDstIPs
	// than entries here if some are still queued for lookup.
	Reputations []ReputationInfo
}

// ScorePortUsage scores an aggregated port/application bucket rather than
// a single connection: it takes the worst-case view across every
// destination IP seen on that port (one malicious IP is enough to flag the
// whole bucket), plus the same protocol/port/confidence heuristics
// ScoreConnection uses.
func ScorePortUsage(in PortUsageInput) RiskResult {
	var reasons []RiskReason
	add := func(code, desc string, points int) { reasons = append(reasons, RiskReason{code, desc, points}) }

	anyMalicious, anyNoiseUnknown, anyRIOT := false, false, false
	for _, r := range in.Reputations {
		if !r.Resolved {
			continue
		}
		if r.Classification == "malicious" {
			anyMalicious = true
		}
		if r.IsNoise && r.Classification != "malicious" && r.Classification != "benign" {
			anyNoiseUnknown = true
		}
		if r.IsRIOT {
			anyRIOT = true
		}
	}
	if anyMalicious {
		add("GREYNOISE_MALICIOUS", "At least one destination IP on this port/app is classified malicious", 50)
	}
	if anyNoiseUnknown {
		add("GREYNOISE_NOISE_UNKNOWN", "At least one destination IP is a known scanner with unconfirmed intent", 15)
	}
	if anyRIOT && !anyMalicious {
		add("GREYNOISE_BENIGN_RIOT", "Traffic includes a known-good CDN/cloud service (RIOT)", -10)
	}
	if len(in.Reputations) == 0 && in.DistinctDstIPs > 0 && in.Now.Sub(in.FirstSeen) >= time.Duration(LongLivedThresholdSeconds)*time.Second {
		add("LONG_LIVED_UNVERIFIED", "Long-established port usage with no reputation data yet for any destination", 10)
	}

	if legacyAdminPorts[in.DstPort] {
		add("LEGACY_ADMIN_PORT", "Destination port is a legacy remote-admin protocol (telnet/rexec/rlogin/rsh/rpcbind)", 30)
	}
	if cleartextPorts[in.DstPort] {
		add("CLEARTEXT_PROTOCOL", "Destination port is a plaintext protocol that can leak credentials/content", 25)
	} else if in.DstPort == cleartextHTTPPort {
		add("CLEARTEXT_PROTOCOL", "Plain HTTP — unencrypted", 10)
	}
	if in.Application == "" && !wellKnownPorts[in.DstPort] {
		add("UNRECOGNIZED_APP_ON_UNUSUAL_PORT", "No DPI application match on an uncommon port", 20)
	}
	if in.TotalBytes >= HighVolumeThresholdBytes && in.DistinctDstIPs <= 1 {
		add("HIGH_VOLUME_FIRST_CONTACT", "High cumulative transfer volume concentrated on a single destination", 15)
	}
	if in.SampleCount > 0 && in.SampleCount < LowConfidenceSampleCount {
		add("LOW_CONFIDENCE_SAMPLE", "This port/application has only been observed a handful of times", 5)
	}

	return finalize(reasons)
}

func finalize(reasons []RiskReason) RiskResult {
	score := 0
	for _, r := range reasons {
		score += r.Points
	}
	if score < 0 {
		score = 0
	}
	if score > 100 {
		score = 100
	}
	return RiskResult{Score: score, Bucket: bucketFor(score), Reasons: reasons}
}
