package threatintel

import (
	"context"
	"errors"
	"log"
	"time"

	"conntrackd/internal/risk"
	"conntrackd/internal/store"
)

// Manager wires a Provider to the store's cache/queue/rate-limit tables:
// Enqueue is safe to call for every newly-seen public IP (it no-ops if
// already cached or already queued), and a single drip-feed worker goroutine
// pops one queued IP at a time, spaced out across the day so a scarce
// per-day budget (GreyNoise Community: 10/day, unauthenticated) survives
// the whole day instead of being spent in the first few minutes.
type Manager struct {
	store       *store.Store
	provider    Provider
	dailyBudget int
	cacheTTL    time.Duration
	negativeTTL time.Duration
}

func NewManager(st *store.Store, provider Provider, dailyBudget int, cacheTTL, negativeTTL time.Duration) *Manager {
	if dailyBudget <= 0 {
		dailyBudget = 10
	}
	return &Manager{store: st, provider: provider, dailyBudget: dailyBudget, cacheTTL: cacheTTL, negativeTTL: negativeTTL}
}

// Enqueue requests a lookup for ip if it isn't already cached (fresh) or
// already queued. Matches poller.EnqueueReputation's signature.
func (m *Manager) Enqueue(firewallID, ip string, priority int) {
	if _, ok, err := m.store.GetReputation(m.provider.Name(), ip); err == nil && ok {
		return
	}
	if err := m.store.EnqueueReputationLookup(m.provider.Name(), ip, firewallID, priority); err != nil {
		log.Printf("threatintel: enqueue %s: %v", ip, err)
	}
}

// RunDripWorker pops and looks up one queued IP at a time until ctx is
// cancelled, waking roughly every 24h/dailyBudget so the day's budget is
// spread out rather than burst. It still respects RateLimitStatus each
// wake, so a shortened wake interval (or a provider 429) never overspends.
func (m *Manager) RunDripWorker(ctx context.Context) {
	interval := 24 * time.Hour / time.Duration(m.dailyBudget)
	if interval < time.Minute {
		interval = time.Minute
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	m.tick(ctx)
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			m.tick(ctx)
		}
	}
}

func (m *Manager) tick(ctx context.Context) {
	used, budget, err := m.store.RateLimitStatus(m.provider.Name(), m.dailyBudget)
	if err != nil {
		log.Printf("threatintel: rate limit status: %v", err)
		return
	}
	if used >= budget {
		return
	}
	item, ok, err := m.store.PopNextReputationLookup(m.provider.Name())
	if err != nil {
		log.Printf("threatintel: pop queue: %v", err)
		return
	}
	if !ok {
		return
	}

	lookupCtx, cancel := context.WithTimeout(ctx, DefaultTimeout)
	verdict, err := m.provider.Lookup(lookupCtx, item.IP)
	cancel()

	now := time.Now().UTC()
	if err != nil {
		var rl *RateLimitError
		if errors.As(err, &rl) {
			if incErr := m.store.IncrementRateLimit(m.provider.Name(), true); incErr != nil {
				log.Printf("threatintel: recording rate-limit exhaustion: %v", incErr)
			}
			// Put it back at the front of the queue for tomorrow.
			if reErr := m.store.EnqueueReputationLookup(m.provider.Name(), item.IP, item.FirewallID, item.Priority+1); reErr != nil {
				log.Printf("threatintel: re-queueing after rate limit: %v", reErr)
			}
			return
		}
		log.Printf("threatintel: lookup %s failed: %v", item.IP, err)
		_ = m.store.PutReputation(store.ReputationEntry{
			Provider: m.provider.Name(), IP: item.IP, LookupError: err.Error(),
			CheckedAt: now, ExpiresAt: now.Add(m.negativeTTL),
		})
		_ = m.store.IncrementRateLimit(m.provider.Name(), false)
		return
	}

	ttl := m.cacheTTL
	if verdict.Classification == "" || verdict.Classification == "unknown" {
		ttl = m.negativeTTL
	}
	if err := m.store.PutReputation(store.ReputationEntry{
		Provider: m.provider.Name(), IP: item.IP, Classification: verdict.Classification,
		IsNoise: verdict.IsNoise, IsRIOT: verdict.IsRIOT, Name: verdict.Name, Link: verdict.Link,
		Message: verdict.Message, RawJSON: verdict.RawJSON, CheckedAt: now, ExpiresAt: now.Add(ttl),
	}); err != nil {
		log.Printf("threatintel: caching verdict for %s: %v", item.IP, err)
	}
	if err := m.store.IncrementRateLimit(m.provider.Name(), false); err != nil {
		log.Printf("threatintel: incrementing rate limit: %v", err)
	}
}

// CachedReputation returns a risk.ReputationInfo for ip if a non-expired
// cache entry exists — used by the risk scorer, which never triggers a
// lookup itself (only the poller's Enqueue does).
func (m *Manager) CachedReputation(ip string) (risk.ReputationInfo, bool) {
	entry, ok, err := m.store.GetReputation(m.provider.Name(), ip)
	if err != nil || !ok || entry.LookupError != "" {
		return risk.ReputationInfo{}, false
	}
	return risk.ReputationInfo{
		Classification: entry.Classification,
		IsNoise:        entry.IsNoise,
		IsRIOT:         entry.IsRIOT,
		Resolved:       true,
	}, true
}

// Status reports today's usage for the web dashboard's transparency view.
type Status struct {
	Provider   string
	Used       int
	Budget     int
	QueueDepth int
	NextLookup time.Time
}

func (m *Manager) GetStatus() (Status, error) {
	used, budget, err := m.store.RateLimitStatus(m.provider.Name(), m.dailyBudget)
	if err != nil {
		return Status{}, err
	}
	depth, err := m.store.QueueDepth(m.provider.Name())
	if err != nil {
		return Status{}, err
	}
	return Status{Provider: m.provider.Name(), Used: used, Budget: budget, QueueDepth: depth}, nil
}
