package store

import "time"

// PruneOlderThan deletes closed sessions (and their sample history) whose
// closed_at predates the cutoff. Open sessions are never touched.
// port_usage, port_usage_dst_ips, approved_ports, and ip_reputation_cache
// are permanent and never pruned by this — see PLAN.md. Batched to avoid
// one long write-lock on a large backlog.
func (s *Store) PruneOlderThan(cutoff time.Time) (sessionsDeleted, samplesDeleted int64, err error) {
	const batch = 5000
	cut := cutoff.Unix()

	for {
		res, execErr := s.writeDB.Exec(`
			DELETE FROM flow_samples WHERE session_id IN (
				SELECT id FROM flow_sessions WHERE closed_at IS NOT NULL AND closed_at < ? LIMIT ?
			)
		`, cut, batch)
		if execErr != nil {
			return sessionsDeleted, samplesDeleted, execErr
		}
		n, _ := res.RowsAffected()
		samplesDeleted += n

		res2, execErr := s.writeDB.Exec(`
			DELETE FROM flow_sessions WHERE id IN (
				SELECT id FROM flow_sessions WHERE closed_at IS NOT NULL AND closed_at < ? LIMIT ?
			)
		`, cut, batch)
		if execErr != nil {
			return sessionsDeleted, samplesDeleted, execErr
		}
		n2, _ := res2.RowsAffected()
		sessionsDeleted += n2

		if n2 < batch {
			break
		}
	}
	return sessionsDeleted, samplesDeleted, nil
}
