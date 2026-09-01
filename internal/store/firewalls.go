package store

import (
	"database/sql"
	"time"
)

// SyncFirewall ensures a row exists in `firewalls` for this ID (from
// config), creating it on first sight and updating name/host/port if
// they changed in config since. Never touches poll-status columns.
func (s *Store) SyncFirewall(id, name, host string, port int) error {
	_, err := s.writeDB.Exec(`
		INSERT INTO firewalls (id, name, host, port, created_at)
		VALUES (?, ?, ?, ?, ?)
		ON CONFLICT(id) DO UPDATE SET name = excluded.name, host = excluded.host, port = excluded.port
	`, id, name, host, port, time.Now().Unix())
	return err
}

// RecordPollSuccess updates a firewall's last-poll status and the summary
// counters from `service show conntrack` after a successful poll cycle.
func (s *Store) RecordPollSuccess(firewallID string, limit, usage, nat int) error {
	now := time.Now().Unix()
	_, err := s.writeDB.Exec(`
		UPDATE firewalls SET
			last_polled_at = ?, last_poll_ok = 1, last_poll_error = NULL,
			conntrack_limit = ?, conntrack_usage = ?, nat_usage = ?, summary_updated_at = ?
		WHERE id = ?
	`, now, limit, usage, nat, now, firewallID)
	return err
}

// RecordPollFailure marks a firewall's most recent poll as failed, keeping
// the last successful summary counters in place.
func (s *Store) RecordPollFailure(firewallID string, pollErr error) error {
	now := time.Now().Unix()
	_, err := s.writeDB.Exec(`
		UPDATE firewalls SET last_polled_at = ?, last_poll_ok = 0, last_poll_error = ?
		WHERE id = ?
	`, now, pollErr.Error(), firewallID)
	return err
}

func (s *Store) ListFirewalls() ([]Firewall, error) {
	rows, err := s.readDB.Query(`
		SELECT id, name, host, port, created_at, last_polled_at, last_poll_ok, last_poll_error,
		       conntrack_limit, conntrack_usage, nat_usage, summary_updated_at
		FROM firewalls ORDER BY name
	`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []Firewall
	for rows.Next() {
		var f Firewall
		var createdAt int64
		var lastPolledAt, summaryUpdatedAt sql.NullInt64
		var lastPollErr sql.NullString
		var limit, usage, nat sql.NullInt64
		if err := rows.Scan(&f.ID, &f.Name, &f.Host, &f.Port, &createdAt, &lastPolledAt, &f.LastPollOK,
			&lastPollErr, &limit, &usage, &nat, &summaryUpdatedAt); err != nil {
			return nil, err
		}
		f.CreatedAt = time.Unix(createdAt, 0).UTC()
		f.LastPolledAt = timePtrFromUnix(lastPolledAt)
		f.SummaryUpdatedAt = timePtrFromUnix(summaryUpdatedAt)
		f.LastPollError = lastPollErr.String
		f.ConntrackLimit = int(limit.Int64)
		f.ConntrackUsage = int(usage.Int64)
		f.NATUsage = int(nat.Int64)
		out = append(out, f)
	}
	return out, rows.Err()
}

func (s *Store) GetFirewall(id string) (Firewall, bool, error) {
	all, err := s.ListFirewalls()
	if err != nil {
		return Firewall{}, false, err
	}
	for _, f := range all {
		if f.ID == id {
			return f, true, nil
		}
	}
	return Firewall{}, false, nil
}
