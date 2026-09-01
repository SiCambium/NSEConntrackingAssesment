// Package config loads conntrackd's YAML configuration and resolves where
// its runtime data (SQLite DB, known_hosts, the config file itself) lives.
//
// That location deliberately defaults to the OS application-support
// directory rather than the source tree: this project's source lives in a
// OneDrive-synced folder, and the DB/config contain internal LAN
// topology and firewall SSH passwords that shouldn't silently end up
// mirrored to cloud storage just because of where the binary happens to be
// built from.
package config

import (
	"fmt"
	"os"
	"path/filepath"
	"sync"

	"gopkg.in/yaml.v3"
)

// AllowedPollIntervalsSeconds is the fixed set of poll/display intervals
// offered in the Settings UI, matching NSELocalSSH's own dashboard refresh
// picker. Kept as a closed set (rather than a free-text field) so nobody
// accidentally fat-fingers a sub-second interval that hammers the device.
var AllowedPollIntervalsSeconds = []int{1, 2, 5, 10, 20, 30, 60}

func ValidPollInterval(seconds int) bool {
	for _, v := range AllowedPollIntervalsSeconds {
		if v == seconds {
			return true
		}
	}
	return false
}

// Firewall is one monitored device. Data for each firewall is always kept
// scoped by ID — never merged with another firewall's — per the user's
// explicit requirement that multiple firewalls' results must not blend.
type Firewall struct {
	ID                  string `yaml:"id"`
	Name                string `yaml:"name"`
	Host                string `yaml:"host"`
	Port                int    `yaml:"port"`
	User                string `yaml:"user"`
	Password            string `yaml:"password"`
	PollIntervalSeconds int    `yaml:"poll_interval_seconds"`
}

func (f Firewall) PollInterval() int {
	if f.PollIntervalSeconds <= 0 {
		return 30
	}
	return f.PollIntervalSeconds
}

// GreyNoiseConfig configures the (free, keyless) GreyNoise Community
// threat-intel lookup. Its daily budget defaults to the unauthenticated
// rate limit GreyNoise documents for the Community API (10/day) — see
// internal/threatintel/greynoise.
type GreyNoiseConfig struct {
	Enabled         bool `yaml:"enabled"`
	DailyBudget     int  `yaml:"daily_budget"`
	CacheTTLDays    int  `yaml:"cache_ttl_days"`
	NegativeTTLDays int  `yaml:"negative_cache_ttl_days"`
}

func (g GreyNoiseConfig) Budget() int {
	if g.DailyBudget <= 0 {
		return 10
	}
	return g.DailyBudget
}

func (g GreyNoiseConfig) CacheTTL() int {
	if g.CacheTTLDays <= 0 {
		return 14
	}
	return g.CacheTTLDays
}

func (g GreyNoiseConfig) NegativeTTL() int {
	if g.NegativeTTLDays <= 0 {
		return 3
	}
	return g.NegativeTTLDays
}

type Config struct {
	ListenAddr string          `yaml:"listen_addr"`
	Firewalls  []Firewall      `yaml:"firewalls"`
	GreyNoise  GreyNoiseConfig `yaml:"greynoise"`

	// EnabledSources gates each internal/enrich lookup source
	// independently, keyed by its Source.Key() (e.g. "ipwhois", "rdap",
	// "rdns", "cymru", "shodan") — all off by default, matching
	// NSELocalSSH's own ip_lookup preference, since these are the only
	// features in this app that send a bare destination IP to a third
	// party outside the GreyNoise reputation path.
	EnabledSources map[string]bool `yaml:"enabled_sources"`

	// path is the file this Config was loaded from; not serialized.
	path string `yaml:"-"`
}

// SourceEnabled reports whether an internal/enrich source is turned on.
// A nil/absent map (the zero value, and every source's default) means
// disabled — never enabled by omission.
func (c Config) SourceEnabled(key string) bool {
	return c.EnabledSources[key]
}

func (c Config) Addr() string {
	if c.ListenAddr == "" {
		return "127.0.0.1:8090"
	}
	return c.ListenAddr
}

// DataDir returns the directory holding conntrackd's runtime data
// (database, known_hosts, and — unless overridden — the config file
// itself). Override with $CONNTRACK_HOME; otherwise this is
// "ConnTrack" under the OS's per-user application-support directory
// (e.g. ~/Library/Application Support/ConnTrack on macOS), which is
// intentionally outside any cloud-synced project folder.
func DataDir() (string, error) {
	if v := os.Getenv("CONNTRACK_HOME"); v != "" {
		return v, nil
	}
	base, err := os.UserConfigDir()
	if err != nil {
		return "", fmt.Errorf("resolving app data directory: %w", err)
	}
	return filepath.Join(base, "ConnTrack"), nil
}

// DefaultConfigPath is DataDir()/config.yaml.
func DefaultConfigPath() (string, error) {
	dir, err := DataDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, "config.yaml"), nil
}

// Load reads and validates the config file at path. If path is empty, it
// resolves to DefaultConfigPath(). A missing file is not an error — it
// loads as an empty Config (zero firewalls), so a fresh install can start
// up and have its first firewall added through the Settings UI rather
// than requiring a hand-edited file to exist first.
func Load(path string) (Config, error) {
	if path == "" {
		p, err := DefaultConfigPath()
		if err != nil {
			return Config{}, err
		}
		path = p
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return Config{path: path}, nil
		}
		return Config{}, fmt.Errorf("reading config %s: %w", path, err)
	}
	var cfg Config
	if err := yaml.Unmarshal(raw, &cfg); err != nil {
		return Config{}, fmt.Errorf("parsing config %s: %w", path, err)
	}
	cfg.path = path
	if err := validate(&cfg); err != nil {
		return Config{}, err
	}
	return cfg, nil
}

// validate checks firewall entries and fills in defaults (port 22, a
// default poll interval) in place.
func validate(cfg *Config) error {
	seen := map[string]bool{}
	for i, fw := range cfg.Firewalls {
		if fw.ID == "" {
			return fmt.Errorf("firewalls[%d]: id is required", i)
		}
		if seen[fw.ID] {
			return fmt.Errorf("firewalls[%d]: duplicate id %q", i, fw.ID)
		}
		seen[fw.ID] = true
		if fw.Host == "" {
			return fmt.Errorf("firewall %q: host is required", fw.ID)
		}
		if fw.User == "" {
			return fmt.Errorf("firewall %q: user is required", fw.ID)
		}
		if fw.Port == 0 {
			cfg.Firewalls[i].Port = 22
		}
		if fw.PollIntervalSeconds != 0 && !ValidPollInterval(fw.PollIntervalSeconds) {
			return fmt.Errorf("firewall %q: poll_interval_seconds must be one of %v", fw.ID, AllowedPollIntervalsSeconds)
		}
	}
	return nil
}

// Save writes cfg to path as YAML, mode 0600 (it contains SSH passwords),
// creating the parent directory if needed.
func Save(path string, cfg Config) error {
	if dir := filepath.Dir(path); dir != "." {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return fmt.Errorf("creating config dir: %w", err)
		}
	}
	raw, err := yaml.Marshal(cfg)
	if err != nil {
		return fmt.Errorf("encoding config: %w", err)
	}
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		return fmt.Errorf("writing config %s: %w", path, err)
	}
	return nil
}

// Store is a concurrency-safe, disk-backed holder of the running Config,
// used by the web Settings handlers: every mutation is validated and
// persisted before it's visible to Get(), so a bad edit never leaves the
// in-memory config and the on-disk file disagreeing.
type Store struct {
	mu   sync.Mutex
	path string
	cfg  Config
}

// OpenStore loads path (creating no file yet if one doesn't exist — the
// first Update call will create it) and returns a Store wrapping it.
func OpenStore(path string) (*Store, error) {
	cfg, err := Load(path)
	if err != nil {
		return nil, err
	}
	return &Store{path: path, cfg: cfg}, nil
}

// Get returns the current config.
func (s *Store) Get() Config {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.cfg
}

// Update applies mutate to a copy of the current config, validates it,
// persists it to disk, and — only if all of that succeeds — commits it as
// the new current config. mutate's changes are discarded on any error.
func (s *Store) Update(mutate func(*Config) error) (Config, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	next := s.cfg
	next.Firewalls = append([]Firewall{}, s.cfg.Firewalls...)
	if err := mutate(&next); err != nil {
		return Config{}, err
	}
	if err := validate(&next); err != nil {
		return Config{}, err
	}
	if err := Save(s.path, next); err != nil {
		return Config{}, err
	}
	next.path = s.path
	s.cfg = next
	return s.cfg, nil
}

// EnsureDataDir creates DataDir() (mode 0700) if it doesn't already exist.
func EnsureDataDir() (string, error) {
	dir, err := DataDir()
	if err != nil {
		return "", err
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", fmt.Errorf("creating data dir %s: %w", dir, err)
	}
	return dir, nil
}
