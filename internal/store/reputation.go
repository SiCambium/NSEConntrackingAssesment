package store

import (
	"database/sql"
	"errors"
	"time"
)

// GetReputation returns a cached, non-expired verdict for (provider, ip),
// or ok=false if there's no usable cache entry.
func (s *Store) GetReputation(provider, ip string) (ReputationEntry, bool, error) {
	var r ReputationEntry
	var checkedAt, expiresAt int64
	var classification, name, link, message, rawJSON, lookupErr sql.NullString
	err := s.readDB.QueryRow(`
		SELECT provider, ip, classification, is_noise, is_riot, name, link, message, raw_json,
		       checked_at, expires_at, lookup_error
		FROM ip_reputation_cache WHERE provider = ? AND ip = ?
	`, provider, ip).Scan(&r.Provider, &r.IP, &classification, &r.IsNoise, &r.IsRIOT, &name, &link, &message,
		&rawJSON, &checkedAt, &expiresAt, &lookupErr)
	if errors.Is(err, sql.ErrNoRows) {
		return ReputationEntry{}, false, nil
	}
	if err != nil {
		return ReputationEntry{}, false, err
	}
	r.Classification = classification.String
	r.Name = name.String
	r.Link = link.String
	r.Message = message.String
	r.RawJSON = rawJSON.String
	r.LookupError = lookupErr.String
	r.CheckedAt = time.Unix(checkedAt, 0).UTC()
	r.ExpiresAt = time.Unix(expiresAt, 0).UTC()
	if time.Now().After(r.ExpiresAt) {
		return r, false, nil
	}
	return r, true, nil
}

// PutReputation upserts a verdict into the cache.
func (s *Store) PutReputation(r ReputationEntry) error {
	_, err := s.writeDB.Exec(`
		INSERT INTO ip_reputation_cache (provider, ip, classification, is_noise, is_riot, name, link, message,
			raw_json, checked_at, expires_at, lookup_error)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(provider, ip) DO UPDATE SET
			classification = excluded.classification, is_noise = excluded.is_noise, is_riot = excluded.is_riot,
			name = excluded.name, link = excluded.link, message = excluded.message, raw_json = excluded.raw_json,
			checked_at = excluded.checked_at, expires_at = excluded.expires_at, lookup_error = excluded.lookup_error
	`, r.Provider, r.IP, r.Classification, boolToInt(r.IsNoise), boolToInt(r.IsRIOT), r.Name, r.Link, r.Message,
		r.RawJSON, r.CheckedAt.Unix(), r.ExpiresAt.Unix(), r.LookupError)
	return err
}

// EnqueueReputationLookup adds an IP to the durable lookup queue if it
// isn't already queued for this provider (INSERT OR IGNORE on the
// (provider, ip) unique key).
func (s *Store) EnqueueReputationLookup(provider, ip, firewallID string, priority int) error {
	_, err := s.writeDB.Exec(`
		INSERT OR IGNORE INTO reputation_queue (provider, ip, firewall_id, enqueued_at, priority)
		VALUES (?, ?, ?, ?, ?)
	`, provider, ip, firewallID, time.Now().Unix(), priority)
	return err
}

// PopNextReputationLookup removes and returns the highest-priority,
// oldest-enqueued pending lookup for a provider, or ok=false if the queue
// is empty.
func (s *Store) PopNextReputationLookup(provider string) (ReputationQueueItem, bool, error) {
	tx, err := s.writeDB.Begin()
	if err != nil {
		return ReputationQueueItem{}, false, err
	}
	defer tx.Rollback()

	var item ReputationQueueItem
	var enqueuedAt int64
	err = tx.QueryRow(`
		SELECT id, provider, ip, firewall_id, enqueued_at, priority FROM reputation_queue
		WHERE provider = ? ORDER BY priority DESC, enqueued_at ASC LIMIT 1
	`, provider).Scan(&item.ID, &item.Provider, &item.IP, &item.FirewallID, &enqueuedAt, &item.Priority)
	if errors.Is(err, sql.ErrNoRows) {
		return ReputationQueueItem{}, false, nil
	}
	if err != nil {
		return ReputationQueueItem{}, false, err
	}
	item.EnqueuedAt = time.Unix(enqueuedAt, 0).UTC()
	if _, err := tx.Exec(`DELETE FROM reputation_queue WHERE id = ?`, item.ID); err != nil {
		return ReputationQueueItem{}, false, err
	}
	if err := tx.Commit(); err != nil {
		return ReputationQueueItem{}, false, err
	}
	return item, true, nil
}

// QueueDepth returns how many lookups are currently pending for a provider.
func (s *Store) QueueDepth(provider string) (int, error) {
	var n int
	err := s.readDB.QueryRow(`SELECT COUNT(*) FROM reputation_queue WHERE provider = ?`, provider).Scan(&n)
	return n, err
}

// RateLimitStatus returns today's (UTC) used_count and the configured
// daily_budget for a provider, creating the row with used_count=0 if this
// is the first check today.
func (s *Store) RateLimitStatus(provider string, dailyBudget int) (used, budget int, err error) {
	today := time.Now().UTC().Format("2006-01-02")
	var windowDate string
	err = s.writeDB.QueryRow(`
		SELECT window_date, used_count, daily_budget FROM provider_rate_limit WHERE provider = ?
	`, provider).Scan(&windowDate, &used, &budget)
	if errors.Is(err, sql.ErrNoRows) {
		_, insErr := s.writeDB.Exec(`
			INSERT INTO provider_rate_limit (provider, window_date, used_count, daily_budget, updated_at)
			VALUES (?, ?, 0, ?, ?)
		`, provider, today, dailyBudget, time.Now().Unix())
		return 0, dailyBudget, insErr
	}
	if err != nil {
		return 0, 0, err
	}
	if windowDate != today {
		if _, resetErr := s.writeDB.Exec(`
			UPDATE provider_rate_limit SET window_date = ?, used_count = 0, daily_budget = ?, updated_at = ?
			WHERE provider = ?
		`, today, dailyBudget, time.Now().Unix(), provider); resetErr != nil {
			return 0, 0, resetErr
		}
		return 0, dailyBudget, nil
	}
	return used, budget, nil
}

// IncrementRateLimit records one more used lookup for today, or — if
// exhausted is true (e.g. the provider returned HTTP 429) — pins
// used_count to daily_budget regardless of the local count, treating the
// server as authoritative over local tracking.
func (s *Store) IncrementRateLimit(provider string, exhausted bool) error {
	if exhausted {
		_, err := s.writeDB.Exec(`
			UPDATE provider_rate_limit SET used_count = daily_budget, updated_at = ? WHERE provider = ?
		`, time.Now().Unix(), provider)
		return err
	}
	_, err := s.writeDB.Exec(`
		UPDATE provider_rate_limit SET used_count = used_count + 1, updated_at = ? WHERE provider = ?
	`, time.Now().Unix(), provider)
	return err
}
