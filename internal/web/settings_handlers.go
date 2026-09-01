package web

import (
	"encoding/json"
	"net/http"
	"regexp"
	"strings"

	"conntrackd/internal/config"
)

func (s *Server) handleMeta(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{
		"poll_intervals_seconds": config.AllowedPollIntervalsSeconds,
	})
}

// settingsFirewall is what the Settings UI sees: never includes the
// password, only whether one is set (so the edit form can show "leave
// blank to keep the current password" instead of round-tripping it).
type settingsFirewall struct {
	ID                  string `json:"id"`
	Name                string `json:"name"`
	Host                string `json:"host"`
	Port                int    `json:"port"`
	User                string `json:"user"`
	HasPassword         bool   `json:"has_password"`
	PollIntervalSeconds int    `json:"poll_interval_seconds"`
	Running             bool   `json:"running"`
}

func (s *Server) toSettingsFirewalls(firewalls []config.Firewall) []settingsFirewall {
	running := map[string]bool{}
	if s.pollers != nil {
		for _, id := range s.pollers.RunningIDs() {
			running[id] = true
		}
	}
	out := make([]settingsFirewall, 0, len(firewalls))
	for _, fw := range firewalls {
		out = append(out, settingsFirewall{
			ID: fw.ID, Name: fw.Name, Host: fw.Host, Port: fw.Port, User: fw.User,
			HasPassword: fw.Password != "", PollIntervalSeconds: fw.PollInterval(), Running: running[fw.ID],
		})
	}
	return out
}

func (s *Server) handleListSettingsFirewalls(w http.ResponseWriter, r *http.Request) {
	writable := s.configStore != nil && s.pollers != nil
	firewalls := []settingsFirewall{}
	if writable {
		firewalls = s.toSettingsFirewalls(s.configStore.Get().Firewalls)
	}
	writeJSON(w, http.StatusOK, map[string]any{"writable": writable, "firewalls": firewalls})
}

type firewallWriteRequest struct {
	ID                  string `json:"id"`
	Name                string `json:"name"`
	Host                string `json:"host"`
	Port                int    `json:"port"`
	User                string `json:"user"`
	Password            string `json:"password"`
	PollIntervalSeconds int    `json:"poll_interval_seconds"`
}

var slugSanitizer = regexp.MustCompile(`[^a-z0-9-]+`)

func slugify(name string) string {
	s := slugSanitizer.ReplaceAllString(strings.ToLower(strings.TrimSpace(name)), "-")
	return strings.Trim(s, "-")
}

func (s *Server) handleAddFirewall(w http.ResponseWriter, r *http.Request) {
	if s.configStore == nil || s.pollers == nil {
		writeError(w, http.StatusNotImplemented, "settings are not writable in this mode")
		return
	}
	var req firewallWriteRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON")
		return
	}
	if req.Host == "" || req.User == "" {
		writeError(w, http.StatusBadRequest, "host and user are required")
		return
	}
	if req.Password == "" {
		writeError(w, http.StatusBadRequest, "password is required for a new firewall")
		return
	}
	id := slugify(req.ID)
	if id == "" {
		id = slugify(req.Name)
	}
	if id == "" {
		writeError(w, http.StatusBadRequest, "name or id is required")
		return
	}
	if req.Port == 0 {
		req.Port = 22
	}
	if req.PollIntervalSeconds == 0 {
		req.PollIntervalSeconds = 30
	}
	if !config.ValidPollInterval(req.PollIntervalSeconds) {
		writeError(w, http.StatusBadRequest, "invalid poll interval")
		return
	}

	newCfg, err := s.configStore.Update(func(cfg *config.Config) error {
		for _, fw := range cfg.Firewalls {
			if fw.ID == id {
				return errFirewallExists
			}
		}
		cfg.Firewalls = append(cfg.Firewalls, config.Firewall{
			ID: id, Name: req.Name, Host: req.Host, Port: req.Port, User: req.User,
			Password: req.Password, PollIntervalSeconds: req.PollIntervalSeconds,
		})
		return nil
	})
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	s.pollers.Reload(newCfg.Firewalls)
	writeJSON(w, http.StatusOK, map[string]any{"writable": true, "firewalls": s.toSettingsFirewalls(newCfg.Firewalls)})
}

func (s *Server) handleEditFirewall(w http.ResponseWriter, r *http.Request) {
	if s.configStore == nil || s.pollers == nil {
		writeError(w, http.StatusNotImplemented, "settings are not writable in this mode")
		return
	}
	id := r.PathValue("id")
	var req firewallWriteRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON")
		return
	}
	if req.PollIntervalSeconds != 0 && !config.ValidPollInterval(req.PollIntervalSeconds) {
		writeError(w, http.StatusBadRequest, "invalid poll interval")
		return
	}

	newCfg, err := s.configStore.Update(func(cfg *config.Config) error {
		for i, fw := range cfg.Firewalls {
			if fw.ID != id {
				continue
			}
			if req.Name != "" {
				fw.Name = req.Name
			}
			if req.Host != "" {
				fw.Host = req.Host
			}
			if req.Port != 0 {
				fw.Port = req.Port
			}
			if req.User != "" {
				fw.User = req.User
			}
			if req.Password != "" { // blank means "keep the existing password"
				fw.Password = req.Password
			}
			if req.PollIntervalSeconds != 0 {
				fw.PollIntervalSeconds = req.PollIntervalSeconds
			}
			cfg.Firewalls[i] = fw
			return nil
		}
		return errFirewallNotFound
	})
	if err != nil {
		status := http.StatusBadRequest
		if err == errFirewallNotFound {
			status = http.StatusNotFound
		}
		writeError(w, status, err.Error())
		return
	}
	s.pollers.Reload(newCfg.Firewalls)
	writeJSON(w, http.StatusOK, map[string]any{"writable": true, "firewalls": s.toSettingsFirewalls(newCfg.Firewalls)})
}

// handleRemoveFirewall stops polling and drops the firewall from
// config.yaml, but deliberately leaves its stored history (sessions,
// port_usage, approved_ports, reputation cache) in place — removing a
// firewall from the list you're actively polling isn't the same decision
// as discarding what you've already learned about it, and the latter
// isn't something a single click should do silently.
func (s *Server) handleRemoveFirewall(w http.ResponseWriter, r *http.Request) {
	if s.configStore == nil || s.pollers == nil {
		writeError(w, http.StatusNotImplemented, "settings are not writable in this mode")
		return
	}
	id := r.PathValue("id")
	newCfg, err := s.configStore.Update(func(cfg *config.Config) error {
		kept := cfg.Firewalls[:0]
		found := false
		for _, fw := range cfg.Firewalls {
			if fw.ID == id {
				found = true
				continue
			}
			kept = append(kept, fw)
		}
		if !found {
			return errFirewallNotFound
		}
		cfg.Firewalls = kept
		return nil
	})
	if err != nil {
		writeError(w, http.StatusNotFound, err.Error())
		return
	}
	s.pollers.Reload(newCfg.Firewalls)
	writeJSON(w, http.StatusOK, map[string]any{"writable": true, "firewalls": s.toSettingsFirewalls(newCfg.Firewalls)})
}

type settingsError string

func (e settingsError) Error() string { return string(e) }

const (
	errFirewallExists   = settingsError("a firewall with that id already exists")
	errFirewallNotFound = settingsError("no firewall with that id")
)
