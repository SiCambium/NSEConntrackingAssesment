package store

import (
	"database/sql"
	"time"
)

// flowSessionColumns is the column list scanFlowSession expects, in
// order. Every query that feeds scanFlowSession must select exactly
// this — shared as one constant after the column list and the scan
// order drifted apart twice across different queries.
const flowSessionColumns = `id, firewall_id, session_key, protocol, origin_src, origin_dst, src_port, dst_port,
	nated_ip, nated_port, tcp_state, direction, application, host_name, ttl_last,
	tx_packets, tx_bytes, rx_packets, rx_bytes, is_src_private, is_dst_private,
	first_seen, last_seen, sample_count, closed_at`

// OpenSessions returns every currently-open session for a firewall, keyed
// by session_key, so the poller can rebuild its in-memory tracking map on
// startup instead of treating every flow as brand new after a restart.
func (s *Store) OpenSessions(firewallID string) (map[string]FlowSession, error) {
	rows, err := s.readDB.Query(`
		SELECT `+flowSessionColumns+`
		FROM flow_sessions WHERE firewall_id = ? AND closed_at IS NULL
	`, firewallID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	out := map[string]FlowSession{}
	for rows.Next() {
		fs, err := scanFlowSession(rows)
		if err != nil {
			return nil, err
		}
		out[fs.SessionKey] = fs
	}
	return out, rows.Err()
}

type rowScanner interface {
	Scan(dest ...any) error
}

func scanFlowSession(row rowScanner) (FlowSession, error) {
	var fs FlowSession
	var srcPort, dstPort, natedPort, ttlLast sql.NullInt64
	var natedIP, tcpState, direction, hostName sql.NullString
	var firstSeen, lastSeen int64
	var closedAt sql.NullInt64
	var isSrcPrivate, isDstPrivate int
	if err := row.Scan(&fs.ID, &fs.FirewallID, &fs.SessionKey, &fs.Protocol, &fs.OriginSrc, &fs.OriginDst,
		&srcPort, &dstPort, &natedIP, &natedPort, &tcpState, &direction, &fs.Application, &hostName, &ttlLast,
		&fs.TxPackets, &fs.TxBytes, &fs.RxPackets, &fs.RxBytes, &isSrcPrivate, &isDstPrivate,
		&firstSeen, &lastSeen, &fs.SampleCount, &closedAt); err != nil {
		return FlowSession{}, err
	}
	fs.SrcPort = int(srcPort.Int64)
	fs.DstPort = int(dstPort.Int64)
	fs.NatedIP = natedIP.String
	fs.NatedPort = int(natedPort.Int64)
	fs.TCPState = tcpState.String
	fs.Direction = direction.String
	fs.HostName = hostName.String
	fs.TTLLast = int(ttlLast.Int64)
	fs.IsSrcPrivate = isSrcPrivate != 0
	fs.IsDstPrivate = isDstPrivate != 0
	fs.FirstSeen = time.Unix(firstSeen, 0).UTC()
	fs.LastSeen = time.Unix(lastSeen, 0).UTC()
	fs.ClosedAt = timePtrFromUnix(closedAt)
	return fs, nil
}

// InsertSession creates a new open session row and returns its id.
func (s *Store) InsertSession(fs FlowSession) (int64, error) {
	res, err := s.writeDB.Exec(`
		INSERT INTO flow_sessions (
			firewall_id, session_key, protocol, origin_src, origin_dst, src_port, dst_port,
			nated_ip, nated_port, tcp_state, direction, application, host_name, ttl_last,
			tx_packets, tx_bytes, rx_packets, rx_bytes, is_src_private, is_dst_private,
			first_seen, last_seen, sample_count, closed_at
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, NULL)
	`, fs.FirewallID, fs.SessionKey, fs.Protocol, fs.OriginSrc, fs.OriginDst, fs.SrcPort, fs.DstPort,
		fs.NatedIP, fs.NatedPort, fs.TCPState, fs.Direction, fs.Application, fs.HostName, fs.TTLLast,
		fs.TxPackets, fs.TxBytes, fs.RxPackets, fs.RxBytes, boolToInt(fs.IsSrcPrivate), boolToInt(fs.IsDstPrivate),
		fs.FirstSeen.Unix(), fs.LastSeen.Unix(), fs.SampleCount)
	if err != nil {
		return 0, err
	}
	return res.LastInsertId()
}

// UpdateSession refreshes an existing open session's mutable fields
// (counters, state, last_seen) in place and increments sample_count by
// one server-side — callers never need to know the session's previous
// count.
func (s *Store) UpdateSession(id int64, fs FlowSession) error {
	_, err := s.writeDB.Exec(`
		UPDATE flow_sessions SET
			tcp_state = ?, direction = ?, application = ?, host_name = ?, ttl_last = ?,
			tx_packets = ?, tx_bytes = ?, rx_packets = ?, rx_bytes = ?,
			last_seen = ?, sample_count = sample_count + 1
		WHERE id = ?
	`, fs.TCPState, fs.Direction, fs.Application, fs.HostName, fs.TTLLast,
		fs.TxPackets, fs.TxBytes, fs.RxPackets, fs.RxBytes,
		fs.LastSeen.Unix(), id)
	return err
}

// CloseSession marks a session no longer present in the latest poll.
func (s *Store) CloseSession(id int64, closedAt time.Time) error {
	_, err := s.writeDB.Exec(`UPDATE flow_sessions SET closed_at = ? WHERE id = ?`, closedAt.Unix(), id)
	return err
}

// InsertSample appends one event row to the flow_samples history log.
func (s *Store) InsertSample(sample FlowSample) error {
	_, err := s.writeDB.Exec(`
		INSERT INTO flow_samples (
			session_id, firewall_id, event_type, seen_at, protocol, origin_src, origin_dst,
			src_port, dst_port, nated_ip, nated_port, tcp_state, direction, application, host_name, ttl,
			tx_packets, tx_bytes, rx_packets, rx_bytes
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
	`, sample.SessionID, sample.FirewallID, sample.EventType, sample.SeenAt.Unix(), sample.Protocol,
		sample.OriginSrc, sample.OriginDst, sample.SrcPort, sample.DstPort, sample.NatedIP, sample.NatedPort,
		sample.TCPState, sample.Direction, sample.Application, sample.HostName, sample.TTL,
		sample.TxPackets, sample.TxBytes, sample.RxPackets, sample.RxBytes)
	return err
}

func boolToInt(b bool) int {
	if b {
		return 1
	}
	return 0
}
