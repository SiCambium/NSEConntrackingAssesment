// Package threatintel looks up external reputation data for public
// destination IPs and caches it in the store, respecting each provider's
// rate limit via a durable queue (see Manager). Only GreyNoise Community
// is implemented; Provider is deliberately narrow so a second provider
// (AbuseIPDB, or a bulk-list matcher for Spamhaus DROP/FireHOL/URLhaus —
// see PLAN.md) is an additive implementation, not a rework.
package threatintel

import (
	"context"
	"time"
)

// Verdict is one provider's opinion about an IP, normalized to the fields
// risk.ReputationInfo needs plus enough extra context for the UI/cache.
type Verdict struct {
	Classification string // "malicious" | "benign" | "unknown" | ""
	IsNoise        bool
	IsRIOT         bool
	Name           string
	Link           string
	Message        string
	RawJSON        string
}

// Provider looks up one IP's reputation.
type Provider interface {
	Name() string
	Lookup(ctx context.Context, ip string) (Verdict, error)
}

// RateLimitError signals the provider's own rate limit was hit (e.g. HTTP
// 429) — the caller should treat today's local budget as exhausted
// regardless of its own count, since the server is authoritative.
type RateLimitError struct{ Err error }

func (e *RateLimitError) Error() string { return e.Err.Error() }
func (e *RateLimitError) Unwrap() error { return e.Err }

// DefaultTimeout bounds a single provider HTTP call.
const DefaultTimeout = 10 * time.Second
