// Package enrich is a small registry of free, keyless "what do we know
// about this IP" lookups (WHOIS-style identity — who owns it, what's it
// called, what's exposed on it — not risk scoring; that's
// internal/threatintel). Each Source is independently enabled/disabled
// (see config.Config.EnabledSources) and the registry tracks a running
// health status per source — last check time, last error, consecutive
// failures — so the Settings UI can show whether a source is actually
// working, rate-limited, or unreachable, not just whether it's turned on.
package enrich

import (
	"context"
	"sync"
	"time"
)

// Result is one source's answer for one IP. Summary is a single
// human-readable line for inline display; Fields carries the same data
// broken out for anything that wants it structured.
type Result struct {
	Source  string            `json:"source"`
	Summary string            `json:"summary"`
	Fields  map[string]string `json:"fields,omitempty"`
}

// Source is one lookup provider. Key is a stable machine identifier
// (config key, API path segment); Name is what the UI shows.
type Source interface {
	Key() string
	Name() string
	Lookup(ctx context.Context, ip string) (Result, error)
}

// Status is one source's current health, independent of whether it's
// currently enabled — a source keeps its last-known status even if
// disabled, so re-enabling it doesn't wipe the history.
type Status struct {
	Key                 string    `json:"key"`
	Name                string    `json:"name"`
	LastCheckedAt       time.Time `json:"last_checked_at,omitempty"`
	LastOK              bool      `json:"last_ok"`
	LastError           string    `json:"last_error,omitempty"`
	ConsecutiveFailures int       `json:"consecutive_failures"`
	TotalLookups        int       `json:"total_lookups"`
}

// DefaultTimeout bounds a single source's lookup call.
const DefaultTimeout = 6 * time.Second

// Registry holds every known source (regardless of enablement — that's a
// config concern) and tracks their health.
type Registry struct {
	mu      sync.Mutex
	sources map[string]Source
	order   []string
	status  map[string]*Status
}

func NewRegistry(sources ...Source) *Registry {
	r := &Registry{sources: map[string]Source{}, status: map[string]*Status{}}
	for _, s := range sources {
		r.sources[s.Key()] = s
		r.order = append(r.order, s.Key())
		r.status[s.Key()] = &Status{Key: s.Key(), Name: s.Name()}
	}
	return r
}

// Keys returns every registered source key, in registration order.
func (r *Registry) Keys() []string {
	out := make([]string, len(r.order))
	copy(out, r.order)
	return out
}

// Lookup runs one source's lookup and records the outcome into its
// status, regardless of success or failure.
func (r *Registry) Lookup(ctx context.Context, key, ip string) (Result, error) {
	r.mu.Lock()
	src, ok := r.sources[key]
	r.mu.Unlock()
	if !ok {
		return Result{}, errUnknownSource(key)
	}

	lookupCtx, cancel := context.WithTimeout(ctx, DefaultTimeout)
	defer cancel()
	res, err := src.Lookup(lookupCtx, ip)

	r.mu.Lock()
	st := r.status[key]
	st.LastCheckedAt = time.Now().UTC()
	st.TotalLookups++
	if err != nil {
		st.LastOK = false
		st.LastError = err.Error()
		st.ConsecutiveFailures++
	} else {
		st.LastOK = true
		st.LastError = ""
		st.ConsecutiveFailures = 0
	}
	r.mu.Unlock()

	return res, err
}

// Status returns a snapshot of every registered source's current health.
func (r *Registry) Status() []Status {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]Status, 0, len(r.order))
	for _, key := range r.order {
		out = append(out, *r.status[key])
	}
	return out
}

type errUnknownSource string

func (e errUnknownSource) Error() string { return "unknown enrichment source: " + string(e) }
