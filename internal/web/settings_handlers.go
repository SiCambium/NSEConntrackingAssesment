package web

import (
	"encoding/json"
	"net/http"
	"regexp"
	"slices"
	"strings"
	"sync"

	"conntrackd/internal/config"
	"conntrackd/internal/enrich"
	"conntrackd/internal/version"
)

func (s *Server) handleMeta(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{
		"version":                version.Version,
		"poll_intervals_seconds": config.AllowedPollIntervalsSeconds,
	})
}

// sourceInfo is one enrich.Source as the Settings UI sees it: its
// registered health status plus whether it's currently enabled — enabled
// is a config concern (per-firewall-independent, global to the app),
// status is the registry's own concern (does it actually work).
type sourceInfo struct {
	enrich.Status
	Enabled bool `json:"enabled"`
}

func (s *Server) sourcesSnapshot() []sourceInfo {
	cfg := config.Config{}
	if s.configStore != nil {
		cfg = s.configStore.Get()
	}
	statuses := s.enrichment.Status()
	out := make([]sourceInfo, 0, len(statuses))
	for _, st := range statuses {
		out = append(out, sourceInfo{Status: st, Enabled: cfg.SourceEnabled(st.Key)})
	}
	return out
}

func (s *Server) handleListSources(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{
		"writable": s.configStore != nil,
		"sources":  s.sourcesSnapshot(),
	})
}

func (s *Server) handleSetSourceEnabled(w http.ResponseWriter, r *http.Request) {
	if s.configStore == nil {
		writeError(w, http.StatusNotImplemented, "settings are not writable in this mode")
		return
	}
	key := r.PathValue("key")
	if !slices.Contains(s.enrichment.Keys(), key) {
		writeError(w, http.StatusNotFound, "unknown source: "+key)
		return
	}
	var req struct {
		Enabled bool `json:"enabled"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON")
		return
	}
	if _, err := s.configStore.Update(func(cfg *config.Config) error {
		if cfg.EnabledSources == nil {
			cfg.EnabledSources = map[string]bool{}
		}
		cfg.EnabledSources[key] = req.Enabled
		return nil
	}); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	// Turning a source on runs one test lookup immediately (against a
	// stable, well-known public IP) so its Settings row shows real health
	// right away instead of sitting at "not checked yet" until you
	// happen to click a destination IP in the Flows tab later.
	if req.Enabled {
		s.enrichment.Lookup(r.Context(), key, testLookupIP)
	}
	writeJSON(w, http.StatusOK, map[string]any{"writable": true, "sources": s.sourcesSnapshot()})
}

// testLookupIP is Cloudflare's public resolver — stable, well-known,
// always resolvable — used only to health-check a newly-enabled source.
const testLookupIP = "1.1.1.1"

// handleLookup runs every currently-enabled enrich source against one IP
// and returns all their results together (plus any per-source errors),
// so the UI can show a combined "who/what is this" answer from one click
// instead of one request per source. Sources that are off are skipped
// entirely — never queried, never counted against their own status.
func (s *Server) handleLookup(w http.ResponseWriter, r *http.Request) {
	ip := strings.TrimSpace(r.URL.Query().Get("ip"))
	if ip == "" {
		writeError(w, http.StatusBadRequest, "ip is required")
		return
	}
	cfg := config.Config{}
	if s.configStore != nil {
		cfg = s.configStore.Get()
	}

	type lookupResult struct {
		Source string `json:"source"`
		Name   string `json:"name"`
		enrich.Result
		Error string `json:"error,omitempty"`
	}

	var (
		mu      sync.Mutex
		results []lookupResult
		wg      sync.WaitGroup
	)
	for _, key := range s.enrichment.Keys() {
		if !cfg.SourceEnabled(key) {
			continue
		}
		key := key
		wg.Add(1)
		go func() {
			defer wg.Done()
			res, err := s.enrichment.Lookup(r.Context(), key, ip)
			lr := lookupResult{Source: key, Result: res}
			if err != nil {
				lr.Error = err.Error()
			}
			mu.Lock()
			results = append(results, lr)
			mu.Unlock()
		}()
	}
	wg.Wait()

	if len(results) == 0 {
		writeJSON(w, http.StatusOK, map[string]any{"ip": ip, "results": []lookupResult{}, "note": "no lookup sources are enabled — turn some on in Settings"})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ip": ip, "results": results})
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

func (s *Server) handleDatabaseInfo(w http.ResponseWriter, r *http.Request) {
	size, err := s.store.SizeBytes()
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"size_bytes": size, "path": s.store.Path})
}

// handleClearDatabase wipes all connection history, port-usage rollups,
// approved-ports decisions, and threat-intel cache/queue state — but not
// the configured firewall list itself (that lives in config.yaml, not the
// database, and this endpoint never touches it). If pollers are running,
// every one of them is restarted afterward so its in-memory open-session
// tracking doesn't keep pointing at rows that no longer exist — see
// poller.Manager.RestartAll.
func (s *Server) handleClearDatabase(w http.ResponseWriter, r *http.Request) {
	if err := s.store.ClearAllHistory(); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if s.pollers != nil {
		s.pollers.RestartAll()
	}
	size, err := s.store.SizeBytes()
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "size_bytes": size})
}
