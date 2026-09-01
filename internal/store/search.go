package store

import (
	"database/sql"
	"strings"
	"time"
)

// FlowSearchFilter is the set of fields the web dashboard's search view can
// filter on. Every field is optional except FirewallID — results are
// always scoped to exactly one firewall, never merged across firewalls.
type FlowSearchFilter struct {
	FirewallID  string
	Protocol    string
	OriginSrc   string // substring match
	OriginDst   string // substring match
	SrcPort     int
	DstPort     int
	Direction   string
	Application string
	TCPState    string
	HostName    string // substring match
	OpenOnly    bool
	Since       *time.Time // last_seen >= Since
	Until       *time.Time // last_seen <= Until
	MinBytes    int64
	Limit       int
	Offset      int
}

// SearchSessions returns flow_sessions rows matching filter, newest
// last_seen first, plus the total match count (ignoring Limit/Offset) for
// pagination.
func (s *Store) SearchSessions(f FlowSearchFilter) ([]FlowSession, int, error) {
	var where []string
	var args []any

	where = append(where, "firewall_id = ?")
	args = append(args, f.FirewallID)

	if f.Protocol != "" {
		where = append(where, "protocol = ?")
		args = append(args, strings.ToUpper(f.Protocol))
	}
	if f.OriginSrc != "" {
		where = append(where, "origin_src LIKE ?")
		args = append(args, "%"+f.OriginSrc+"%")
	}
	if f.OriginDst != "" {
		where = append(where, "origin_dst LIKE ?")
		args = append(args, "%"+f.OriginDst+"%")
	}
	if f.SrcPort != 0 {
		where = append(where, "src_port = ?")
		args = append(args, f.SrcPort)
	}
	if f.DstPort != 0 {
		where = append(where, "dst_port = ?")
		args = append(args, f.DstPort)
	}
	if f.Direction != "" {
		where = append(where, "direction = ?")
		args = append(args, f.Direction)
	}
	if f.Application != "" {
		where = append(where, "application = ?")
		args = append(args, f.Application)
	}
	if f.TCPState != "" {
		where = append(where, "tcp_state = ?")
		args = append(args, f.TCPState)
	}
	if f.HostName != "" {
		where = append(where, "host_name LIKE ?")
		args = append(args, "%"+f.HostName+"%")
	}
	if f.OpenOnly {
		where = append(where, "closed_at IS NULL")
	}
	if f.Since != nil {
		where = append(where, "last_seen >= ?")
		args = append(args, f.Since.Unix())
	}
	if f.Until != nil {
		where = append(where, "last_seen <= ?")
		args = append(args, f.Until.Unix())
	}
	if f.MinBytes > 0 {
		where = append(where, "(tx_bytes + rx_bytes) >= ?")
		args = append(args, f.MinBytes)
	}

	whereSQL := strings.Join(where, " AND ")

	var total int
	if err := s.readDB.QueryRow(`SELECT COUNT(*) FROM flow_sessions WHERE `+whereSQL, args...).Scan(&total); err != nil {
		return nil, 0, err
	}

	limit := f.Limit
	if limit <= 0 || limit > 1000 {
		limit = 200
	}
	query := `
		SELECT id, firewall_id, session_key, protocol, origin_src, origin_dst, src_port, dst_port,
		       nated_ip, nated_port, tcp_state, direction, application, host_name, ttl_last,
		       tx_packets, tx_bytes, rx_packets, rx_bytes, is_dst_private,
		       first_seen, last_seen, sample_count, closed_at
		FROM flow_sessions WHERE ` + whereSQL + `
		ORDER BY last_seen DESC LIMIT ? OFFSET ?`
	rows, err := s.readDB.Query(query, append(args, limit, f.Offset)...)
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

// SessionSamples returns the event timeline for one session, oldest first.
func (s *Store) SessionSamples(sessionID int64) ([]FlowSample, error) {
	rows, err := s.readDB.Query(`
		SELECT id, session_id, firewall_id, event_type, seen_at, protocol, origin_src, origin_dst,
		       src_port, dst_port, nated_ip, nated_port, tcp_state, direction, application, host_name, ttl,
		       tx_packets, tx_bytes, rx_packets, rx_bytes
		FROM flow_samples WHERE session_id = ? ORDER BY seen_at ASC
	`, sessionID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []FlowSample
	for rows.Next() {
		var sm FlowSample
		var seenAt int64
		var srcPort, dstPort, natedPort, ttl sql.NullInt64
		var natedIP, tcpState, direction, hostName sql.NullString
		if err := rows.Scan(&sm.ID, &sm.SessionID, &sm.FirewallID, &sm.EventType, &seenAt, &sm.Protocol,
			&sm.OriginSrc, &sm.OriginDst, &srcPort, &dstPort, &natedIP, &natedPort, &tcpState, &direction,
			&sm.Application, &hostName, &ttl, &sm.TxPackets, &sm.TxBytes, &sm.RxPackets, &sm.RxBytes); err != nil {
			return nil, err
		}
		sm.SeenAt = time.Unix(seenAt, 0).UTC()
		sm.SrcPort = int(srcPort.Int64)
		sm.DstPort = int(dstPort.Int64)
		sm.NatedIP = natedIP.String
		sm.NatedPort = int(natedPort.Int64)
		sm.TCPState = tcpState.String
		sm.Direction = direction.String
		sm.HostName = hostName.String
		sm.TTL = int(ttl.Int64)
		out = append(out, sm)
	}
	return out, rows.Err()
}
