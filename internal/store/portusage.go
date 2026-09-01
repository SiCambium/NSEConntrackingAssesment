package store

import "time"

// BumpPortUsage incrementally updates the permanent port_usage rollup for
// (firewallID, protocol, dstPort, application). byteDelta should be the
// change in tx+rx bytes since this session's last poll (not the session's
// cumulative total) so totals stay correct even after old raw history is
// pruned. dstIP is recorded into port_usage_dst_ips (a no-op if already
// present) so distinct_dst_ips stays exact forever without depending on
// prunable flow_samples history.
func (s *Store) BumpPortUsage(firewallID, protocol string, dstPort int, application, dstIP string, seenAt time.Time, byteDelta int64, isNewSession bool) error {
	tx, err := s.writeDB.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()

	now := seenAt.Unix()
	sampleDelta := 0
	if isNewSession {
		sampleDelta = 1
	}
	if _, err := tx.Exec(`
		INSERT INTO port_usage (firewall_id, protocol, dst_port, application, first_seen, last_seen, sample_count, total_bytes, distinct_dst_ips, updated_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, 0, ?)
		ON CONFLICT(firewall_id, protocol, dst_port, application) DO UPDATE SET
			last_seen = excluded.last_seen,
			sample_count = port_usage.sample_count + ?,
			total_bytes = port_usage.total_bytes + ?,
			updated_at = excluded.updated_at
	`, firewallID, protocol, dstPort, application, now, now, sampleDelta, byteDelta, now, sampleDelta, byteDelta); err != nil {
		return err
	}

	res, err := tx.Exec(`
		INSERT OR IGNORE INTO port_usage_dst_ips (firewall_id, protocol, dst_port, application, dst_ip, first_seen)
		VALUES (?, ?, ?, ?, ?, ?)
	`, firewallID, protocol, dstPort, application, dstIP, now)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n > 0 {
		if _, err := tx.Exec(`
			UPDATE port_usage SET distinct_dst_ips = distinct_dst_ips + 1
			WHERE firewall_id = ? AND protocol = ? AND dst_port = ? AND application = ?
		`, firewallID, protocol, dstPort, application); err != nil {
			return err
		}
	}
	return tx.Commit()
}

// ListPortUsage returns every port_usage bucket for a firewall, most
// recently seen first.
func (s *Store) ListPortUsage(firewallID string) ([]PortUsage, error) {
	rows, err := s.readDB.Query(`
		SELECT id, firewall_id, protocol, dst_port, application, first_seen, last_seen,
		       sample_count, total_bytes, distinct_dst_ips, updated_at
		FROM port_usage WHERE firewall_id = ? ORDER BY last_seen DESC
	`, firewallID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []PortUsage
	for rows.Next() {
		var u PortUsage
		var firstSeen, lastSeen, updatedAt int64
		if err := rows.Scan(&u.ID, &u.FirewallID, &u.Protocol, &u.DstPort, &u.Application,
			&firstSeen, &lastSeen, &u.SampleCount, &u.TotalBytes, &u.DistinctDstIPs, &updatedAt); err != nil {
			return nil, err
		}
		u.FirstSeen = time.Unix(firstSeen, 0).UTC()
		u.LastSeen = time.Unix(lastSeen, 0).UTC()
		u.UpdatedAt = time.Unix(updatedAt, 0).UTC()
		out = append(out, u)
	}
	return out, rows.Err()
}

// DistinctDstIPsForBucket lists the destination IPs recorded for one
// port_usage bucket, used to gather threat-intel reputation across the
// bucket for port-level risk scoring.
func (s *Store) DistinctDstIPsForBucket(firewallID, protocol string, dstPort int, application string) ([]string, error) {
	rows, err := s.readDB.Query(`
		SELECT dst_ip FROM port_usage_dst_ips
		WHERE firewall_id = ? AND protocol = ? AND dst_port = ? AND application = ?
	`, firewallID, protocol, dstPort, application)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var ip string
		if err := rows.Scan(&ip); err != nil {
			return nil, err
		}
		out = append(out, ip)
	}
	return out, rows.Err()
}

// SessionsForBucket returns the individual flow_sessions (open and
// closed) that make up one port_usage bucket — same grouping key
// (firewall, protocol, dst_port, application) — most recently seen
// first, along with the total match count so the caller can show
// "N of M" if the list was capped. Used by the Ports & Risk detail view
// to answer "which src/dst IPs actually make up this aggregated bucket."
func (s *Store) SessionsForBucket(firewallID, protocol string, dstPort int, application string, limit int) ([]FlowSession, int, error) {
	if limit <= 0 || limit > 500 {
		limit = 200
	}
	var total int
	if err := s.readDB.QueryRow(`
		SELECT COUNT(*) FROM flow_sessions WHERE firewall_id = ? AND protocol = ? AND dst_port = ? AND application = ?
	`, firewallID, protocol, dstPort, application).Scan(&total); err != nil {
		return nil, 0, err
	}

	rows, err := s.readDB.Query(`
		SELECT id, firewall_id, session_key, protocol, origin_src, origin_dst, src_port, dst_port,
		       nated_ip, nated_port, tcp_state, direction, application, host_name, ttl_last,
		       tx_packets, tx_bytes, rx_packets, rx_bytes, is_dst_private,
		       first_seen, last_seen, sample_count, closed_at
		FROM flow_sessions WHERE firewall_id = ? AND protocol = ? AND dst_port = ? AND application = ?
		ORDER BY last_seen DESC LIMIT ?
	`, firewallID, protocol, dstPort, application, limit)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()

	var out []FlowSession
	for rows.Next() {
		fs, err := scanFlowSession(rows)
		if err != nil {
			return nil, 0, err
		}
		out = append(out, fs)
	}
	return out, total, rows.Err()
}
