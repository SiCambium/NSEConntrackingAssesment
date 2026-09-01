package web

import (
	"encoding/json"
	"net/http"
	"strconv"
	"time"

	"conntrackd/internal/risk"
	"conntrackd/internal/ruleset"
	"conntrackd/internal/store"
)

func (s *Server) handleListFirewalls(w http.ResponseWriter, r *http.Request) {
	list, err := s.store.ListFirewalls()
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, list)
}

// flowRow's added fields are deliberately untagged, matching
// store.FlowSession's default (PascalCase) JSON casing — the embedded
// struct isn't tagged, so these stay consistent with it rather than
// mixing snake_case into one response.
type flowRow struct {
	store.FlowSession
	RiskScore   int
	RiskBucket  string
	RiskReasons []risk.RiskReason
	Approved    bool
}

func (s *Server) handleFlows(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	q := r.URL.Query()

	filter := store.FlowSearchFilter{
		FirewallID:  id,
		Protocol:    q.Get("protocol"),
		OriginSrc:   q.Get("src"),
		OriginDst:   q.Get("dst"),
		Direction:   q.Get("direction"),
		Application: q.Get("application"),
		TCPState:    q.Get("tcp_state"),
		HostName:    q.Get("host_name"),
		OpenOnly:    q.Get("open_only") == "1",
		SrcPort:     atoiOrZero(q.Get("src_port")),
		DstPort:     atoiOrZero(q.Get("dst_port")),
		MinBytes:    int64(atoiOrZero(q.Get("min_bytes"))),
		Limit:       atoiOrZero(q.Get("limit")),
		Offset:      atoiOrZero(q.Get("offset")),
	}
	if since := q.Get("since"); since != "" {
		if t, err := time.Parse(time.RFC3339, since); err == nil {
			filter.Since = &t
		}
	}
	if until := q.Get("until"); until != "" {
		if t, err := time.Parse(time.RFC3339, until); err == nil {
			filter.Until = &t
		}
	}

	sessions, total, err := s.store.SearchSessions(filter)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}

	usage, err := s.store.ListPortUsage(id)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	bucketByKey := make(map[string]store.PortUsage, len(usage))
	for _, u := range usage {
		bucketByKey[bucketKey(u.Protocol, u.DstPort, u.Application)] = u
	}
	approved, err := s.store.ApprovedSet(id)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}

	rows := make([]flowRow, 0, len(sessions))
	for _, fs := range sessions {
		rr := s.scoreSession(fs, bucketByKey)
		rows = append(rows, flowRow{
			FlowSession: fs, RiskScore: rr.Score, RiskBucket: string(rr.Bucket), RiskReasons: rr.Reasons,
			Approved: approved[bucketKey(fs.Protocol, fs.DstPort, fs.Application)],
		})
	}

	writeJSON(w, http.StatusOK, map[string]any{"total": total, "flows": rows})
}

func (s *Server) handleSessionSamples(w http.ResponseWriter, r *http.Request) {
	sessionID, err := strconv.ParseInt(r.PathValue("sessionId"), 10, 64)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid session id")
		return
	}
	samples, err := s.store.SessionSamples(sessionID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, samples)
}

// portRow's added fields are deliberately untagged — see flowRow.
type portRow struct {
	store.PortUsage
	RiskScore   int
	RiskBucket  string
	RiskReasons []risk.RiskReason
	Approved    bool
}

func (s *Server) handlePorts(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	usage, err := s.store.ListPortUsage(id)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	approved, err := s.store.ApprovedSet(id)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}

	rows := make([]portRow, 0, len(usage))
	for _, u := range usage {
		rr := s.scoreBucket(u)
		rows = append(rows, portRow{
			PortUsage: u, RiskScore: rr.Score, RiskBucket: string(rr.Bucket), RiskReasons: rr.Reasons,
			Approved: approved[bucketKey(u.Protocol, u.DstPort, u.Application)],
		})
	}
	writeJSON(w, http.StatusOK, rows)
}

// handlePortConnections lists the individual connections behind one
// aggregated port_usage bucket — answers "which src/dst IPs actually make
// up this?" for the Ports & Risk detail view.
func (s *Server) handlePortConnections(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	q := r.URL.Query()
	protocol := q.Get("protocol")
	application := q.Get("application")
	dstPort := atoiOrZero(q.Get("dst_port"))
	if protocol == "" {
		writeError(w, http.StatusBadRequest, "protocol is required")
		return
	}
	sessions, total, err := s.store.SessionsForBucket(id, protocol, dstPort, application, 200)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"total": total, "sessions": sessions})
}

type approveRequest struct {
	Protocol    string `json:"protocol"`
	DstPort     int    `json:"dst_port"`
	Application string `json:"application"`
	Label       string `json:"label"`
	ApprovedBy  string `json:"approved_by"`
}

func (s *Server) handleApprovePort(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	var req approveRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON")
		return
	}
	if req.Protocol == "" {
		writeError(w, http.StatusBadRequest, "protocol is required")
		return
	}
	if err := s.store.ApprovePort(id, req.Protocol, req.DstPort, req.Application, req.Label, req.ApprovedBy); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

func (s *Server) handleUnapprovePort(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	var req approveRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON")
		return
	}
	if err := s.store.UnapprovePort(id, req.Protocol, req.DstPort, req.Application); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

func (s *Server) handleListApproved(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	list, err := s.store.ListApprovedPorts(id)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, list)
}

func (s *Server) handleRulesPreview(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	usage, err := s.store.ListPortUsage(id)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	approved, err := s.store.ApprovedSet(id)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	q := r.URL.Query()
	opts := ruleset.Options{
		MinSampleCount: atoiOrZero(q.Get("min_sample_count")),
		IncludeLowRisk: q.Get("include_low_risk") == "1",
	}
	rules := ruleset.Generate(usage, approved, s.scoreBucket, opts)
	writeJSON(w, http.StatusOK, map[string]any{
		"caveat": "Deny-only, manual-review preview. This device's outbound-filter 'allow' action is " +
			"unconfirmed over CLI (only 'deny' is proven), so no allow rules or catch-all deny-all are " +
			"generated here — only named deny rules for specific unapproved ports/applications. Transcribe " +
			"rows into NSELocalSSH's Firewall screen; nothing is pushed to the device from here.",
		"rules": rules,
	})
}

func (s *Server) handleReputationStatus(w http.ResponseWriter, r *http.Request) {
	if s.reputation == nil {
		writeJSON(w, http.StatusOK, map[string]any{"enabled": false})
		return
	}
	status, err := s.reputation.GetStatus()
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"enabled": true, "status": status})
}

func atoiOrZero(s string) int {
	n, _ := strconv.Atoi(s)
	return n
}
