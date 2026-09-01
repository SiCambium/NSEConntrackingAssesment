// Package web serves conntrackd's dashboard: a small JSON API plus a
// vanilla HTML/JS/CSS frontend (no build step), matching NSELocalSSH's own
// approach of one Go binary embedding and serving its own static UI.
package web

import (
	"embed"
	"encoding/json"
	"io/fs"
	"log"
	"net/http"

	"conntrackd/internal/config"
	"conntrackd/internal/poller"
	"conntrackd/internal/store"
	"conntrackd/internal/threatintel"
)

//go:embed static/*
var staticFS embed.FS

type Server struct {
	store       *store.Store
	reputation  *threatintel.Manager
	configStore *config.Store
	pollers     *poller.Manager
	mux         *http.ServeMux
}

// New builds the dashboard's HTTP handler. configStore and pollers are
// optional (nil is fine) — when absent, the Settings tab's read endpoint
// still works against whatever configStore.Get() would have returned, but
// write endpoints (add/edit/remove a firewall) return 501, since there's
// nothing to persist to or reload. cmd/conntrackd and cmd/conntrack-app
// both pass real ones; a future read-only/embedded use could omit them.
func New(st *store.Store, reputation *threatintel.Manager, configStore *config.Store, pollers *poller.Manager) *Server {
	s := &Server{store: st, reputation: reputation, configStore: configStore, pollers: pollers, mux: http.NewServeMux()}
	s.routes()
	return s
}

func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	s.mux.ServeHTTP(w, r)
}

func (s *Server) routes() {
	staticSub, err := fs.Sub(staticFS, "static")
	if err != nil {
		log.Fatalf("web: embedding static assets: %v", err)
	}
	fileServer := http.FileServer(http.FS(staticSub))
	s.mux.Handle("/", fileServer)

	s.mux.HandleFunc("GET /api/meta", s.handleMeta)
	s.mux.HandleFunc("GET /api/firewalls", s.handleListFirewalls)
	s.mux.HandleFunc("GET /api/settings/firewalls", s.handleListSettingsFirewalls)
	s.mux.HandleFunc("POST /api/settings/firewalls", s.handleAddFirewall)
	s.mux.HandleFunc("PUT /api/settings/firewalls/{id}", s.handleEditFirewall)
	s.mux.HandleFunc("DELETE /api/settings/firewalls/{id}", s.handleRemoveFirewall)
	s.mux.HandleFunc("GET /api/firewalls/{id}/flows", s.handleFlows)
	s.mux.HandleFunc("GET /api/firewalls/{id}/flows/{sessionId}/samples", s.handleSessionSamples)
	s.mux.HandleFunc("GET /api/firewalls/{id}/ports", s.handlePorts)
	s.mux.HandleFunc("POST /api/firewalls/{id}/ports/approve", s.handleApprovePort)
	s.mux.HandleFunc("POST /api/firewalls/{id}/ports/unapprove", s.handleUnapprovePort)
	s.mux.HandleFunc("GET /api/firewalls/{id}/approved", s.handleListApproved)
	s.mux.HandleFunc("GET /api/firewalls/{id}/rules/preview", s.handleRulesPreview)
	s.mux.HandleFunc("GET /api/firewalls/{id}/reputation/status", s.handleReputationStatus)
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(v); err != nil {
		log.Printf("web: encoding response: %v", err)
	}
}

func writeError(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]string{"error": msg})
}
