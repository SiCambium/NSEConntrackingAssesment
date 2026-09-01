package risk

import (
	"testing"
	"time"
)

func hasReason(rr RiskResult, code string) bool {
	for _, r := range rr.Reasons {
		if r.Code == code {
			return true
		}
	}
	return false
}

func TestScoreConnection_TelnetIsHighRisk(t *testing.T) {
	now := time.Now()
	rr := ScoreConnection(ConnectionInput{
		Protocol: "TCP", DstPort: 23, Application: "telnet", Direction: "LAN TO WAN",
		FirstSeen: now, Now: now,
	})
	if !hasReason(rr, "LEGACY_ADMIN_PORT") || !hasReason(rr, "CLEARTEXT_PROTOCOL") {
		t.Fatalf("expected telnet to trigger legacy-admin and cleartext reasons, got %+v", rr)
	}
	if rr.Bucket != BucketHigh && rr.Bucket != BucketCritical {
		t.Fatalf("expected telnet to bucket high/critical, got %s (score %d)", rr.Bucket, rr.Score)
	}
}

func TestScoreConnection_KnownHTTPSAmazonIsLow(t *testing.T) {
	now := time.Now()
	rr := ScoreConnection(ConnectionInput{
		Protocol: "TCP", DstPort: 443, Application: "amazon_aws", Direction: "LAN TO WAN",
		FirstSeen: now, Now: now, BucketSampleCount: 50,
		Reputation: &ReputationInfo{Resolved: true, Classification: "benign", IsRIOT: true},
	})
	if rr.Bucket != BucketLow {
		t.Fatalf("expected well-known HTTPS to CDN to bucket low, got %s (score %d) reasons=%+v", rr.Bucket, rr.Score, rr.Reasons)
	}
}

func TestScoreConnection_MaliciousReputationDominates(t *testing.T) {
	now := time.Now()
	rr := ScoreConnection(ConnectionInput{
		Protocol: "TCP", DstPort: 443, Application: "unknown_app", Direction: "LAN TO WAN",
		FirstSeen: now, Now: now,
		Reputation: &ReputationInfo{Resolved: true, Classification: "malicious"},
	})
	if !hasReason(rr, "GREYNOISE_MALICIOUS") {
		t.Fatalf("expected malicious reputation to be flagged, got %+v", rr)
	}
	if rr.Bucket != BucketCritical && rr.Bucket != BucketHigh {
		t.Fatalf("expected malicious dst to bucket high/critical, got %s", rr.Bucket)
	}
}

func TestScoreConnection_InternalTrafficGetsDiscount(t *testing.T) {
	now := time.Now()
	rr := ScoreConnection(ConnectionInput{
		Protocol: "UDP", DstPort: 53, Application: "dns", Direction: "LAN TO LAN",
		FirstSeen: now, Now: now, BucketSampleCount: 50,
	})
	if !hasReason(rr, "INTERNAL_TRAFFIC") {
		t.Fatalf("expected internal traffic discount, got %+v", rr)
	}
	if rr.Score != 0 {
		t.Fatalf("expected score to clamp at 0 for internal DNS, got %d", rr.Score)
	}
}

func TestScoreConnection_UnverifiedLongLivedPublicConnection(t *testing.T) {
	old := time.Now().Add(-3 * time.Hour)
	rr := ScoreConnection(ConnectionInput{
		Protocol: "TCP", DstPort: 443, Application: "amazon_aws",
		FirstSeen: old, Now: time.Now(), IsDstPrivate: false, Reputation: nil,
	})
	if !hasReason(rr, "LONG_LIVED_UNVERIFIED") {
		t.Fatalf("expected long-lived-unverified reason, got %+v", rr)
	}
}

func TestScorePortUsage_AnyMaliciousDestinationFlagsWholeBucket(t *testing.T) {
	now := time.Now()
	rr := ScorePortUsage(PortUsageInput{
		Protocol: "TCP", DstPort: 8080, Application: "custom_app",
		SampleCount: 20, TotalBytes: 1000, DistinctDstIPs: 3, FirstSeen: now, Now: now,
		Reputations: []ReputationInfo{
			{Resolved: true, Classification: "benign"},
			{Resolved: true, Classification: "malicious"},
			{Resolved: false},
		},
	})
	if !hasReason(rr, "GREYNOISE_MALICIOUS") {
		t.Fatalf("expected malicious reputation among bucket destinations to flag the bucket, got %+v", rr)
	}
}

func TestScorePortUsage_LowSampleCountFlagged(t *testing.T) {
	now := time.Now()
	rr := ScorePortUsage(PortUsageInput{
		Protocol: "TCP", DstPort: 9999, Application: "", // no DPI classification
		SampleCount: 1, TotalBytes: 10, DistinctDstIPs: 1, FirstSeen: now, Now: now,
	})
	if !hasReason(rr, "LOW_CONFIDENCE_SAMPLE") {
		t.Fatalf("expected low-confidence-sample reason for a single-sample bucket, got %+v", rr)
	}
	if !hasReason(rr, "UNRECOGNIZED_APP_ON_UNUSUAL_PORT") {
		t.Fatalf("expected unrecognized-app reason on an uncommon port with no DPI match")
	}
}

func TestScoreClampsToZeroAndHundred(t *testing.T) {
	now := time.Now()
	// All-discount scenario shouldn't go negative.
	rr := ScoreConnection(ConnectionInput{
		Protocol: "UDP", DstPort: 53, Application: "dns", Direction: "LAN TO LAN",
		FirstSeen: now, Now: now,
		Reputation: &ReputationInfo{Resolved: true, Classification: "benign", IsRIOT: true},
	})
	if rr.Score < 0 {
		t.Fatalf("score should never go negative, got %d", rr.Score)
	}
}
