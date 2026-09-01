package store

import (
	"strconv"
	"time"
)

// ApprovePort promotes a (protocol, dst_port, application) bucket into the
// "leave this open" list. approvedBy is a free-text label (this tool has
// no user-auth system — see PLAN.md — so it's just a note, not an identity).
func (s *Store) ApprovePort(firewallID, protocol string, dstPort int, application, label, approvedBy string) error {
	_, err := s.writeDB.Exec(`
		INSERT INTO approved_ports (firewall_id, protocol, dst_port, application, label, approved_by, approved_at)
		VALUES (?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(firewall_id, protocol, dst_port, application) DO UPDATE SET
			label = excluded.label, approved_by = excluded.approved_by, approved_at = excluded.approved_at
	`, firewallID, protocol, dstPort, application, label, approvedBy, time.Now().Unix())
	return err
}

func (s *Store) UnapprovePort(firewallID, protocol string, dstPort int, application string) error {
	_, err := s.writeDB.Exec(`
		DELETE FROM approved_ports WHERE firewall_id = ? AND protocol = ? AND dst_port = ? AND application = ?
	`, firewallID, protocol, dstPort, application)
	return err
}

func (s *Store) ListApprovedPorts(firewallID string) ([]ApprovedPort, error) {
	rows, err := s.readDB.Query(`
		SELECT id, firewall_id, protocol, dst_port, application, label, approved_by, approved_at
		FROM approved_ports WHERE firewall_id = ? ORDER BY approved_at DESC
	`, firewallID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []ApprovedPort
	for rows.Next() {
		var a ApprovedPort
		var approvedAt int64
		if err := rows.Scan(&a.ID, &a.FirewallID, &a.Protocol, &a.DstPort, &a.Application, &a.Label, &a.ApprovedBy, &approvedAt); err != nil {
			return nil, err
		}
		a.ApprovedAt = time.Unix(approvedAt, 0).UTC()
		out = append(out, a)
	}
	return out, rows.Err()
}

// ApprovedSet returns the currently-approved buckets for a firewall as a
// set keyed by "protocol|dst_port|application", for quick membership
// checks (used by the rule generator).
func (s *Store) ApprovedSet(firewallID string) (map[string]bool, error) {
	list, err := s.ListApprovedPorts(firewallID)
	if err != nil {
		return nil, err
	}
	out := make(map[string]bool, len(list))
	for _, a := range list {
		out[approvedKey(a.Protocol, a.DstPort, a.Application)] = true
	}
	return out, nil
}

func approvedKey(protocol string, dstPort int, application string) string {
	return protocol + "|" + strconv.Itoa(dstPort) + "|" + application
}
