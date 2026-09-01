package store

import "os"

// ClearAllHistory deletes every row of connection history, port-usage
// rollups, approved-ports decisions, and threat-intel cache/queue state —
// everything except the firewalls table itself (so configured firewalls
// stay configured; only what's been learned about their traffic resets).
// Callers running live pollers must also reset each poller's in-memory
// open-session tracking afterward (see poller.Manager.RestartAll) — the
// DB and a running poller's idea of "what's currently open" would
// otherwise disagree.
func (s *Store) ClearAllHistory() error {
	tx, err := s.writeDB.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()

	tables := []string{
		"flow_samples", "flow_sessions", "port_usage_dst_ips", "port_usage",
		"approved_ports", "ip_reputation_cache", "provider_rate_limit", "reputation_queue",
	}
	for _, t := range tables {
		if _, err := tx.Exec("DELETE FROM " + t); err != nil {
			return err
		}
	}
	// Firewalls keep existing, but their cached summary counters (from
	// the last `service show conntrack`) are now stale relative to a
	// freshly-cleared history — the next poll overwrites them anyway.
	if _, err := tx.Exec(`UPDATE firewalls SET conntrack_usage = NULL, nat_usage = NULL, summary_updated_at = NULL`); err != nil {
		return err
	}
	return tx.Commit()
}

// SizeBytes returns the on-disk size of the database file plus its
// WAL/SHM siblings (present under WAL mode) — the whole footprint, not
// just the main file, since a busy WAL can be a meaningful fraction of it.
func (s *Store) SizeBytes() (int64, error) {
	var total int64
	for _, suffix := range []string{"", "-wal", "-shm"} {
		info, err := os.Stat(s.Path + suffix)
		if err != nil {
			if os.IsNotExist(err) {
				continue
			}
			return 0, err
		}
		total += info.Size()
	}
	return total, nil
}
