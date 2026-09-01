package config

import (
	"path/filepath"
	"testing"
)

func TestLoad_MissingFileReturnsEmptyConfig(t *testing.T) {
	cfg, err := Load(filepath.Join(t.TempDir(), "does-not-exist.yaml"))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if len(cfg.Firewalls) != 0 {
		t.Fatalf("expected zero firewalls for a missing config file, got %d", len(cfg.Firewalls))
	}
}

func TestLoad_RejectsDuplicateIDs(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.yaml")
	if err := Save(path, Config{Firewalls: []Firewall{
		{ID: "a", Host: "1.1.1.1", User: "admin"},
		{ID: "a", Host: "2.2.2.2", User: "admin"},
	}}); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(path); err == nil {
		t.Fatalf("expected an error for duplicate firewall ids")
	}
}

func TestLoad_RejectsInvalidPollInterval(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.yaml")
	if err := Save(path, Config{Firewalls: []Firewall{
		{ID: "a", Host: "1.1.1.1", User: "admin", PollIntervalSeconds: 7},
	}}); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(path); err == nil {
		t.Fatalf("expected an error for a poll interval outside the allowed set")
	}
}

func TestSaveThenLoad_RoundTrips(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.yaml")
	original := Config{
		ListenAddr: "127.0.0.1:9999",
		Firewalls:  []Firewall{{ID: "home", Name: "Home", Host: "10.0.0.1", Port: 22, User: "admin", Password: "secret", PollIntervalSeconds: 10}},
		GreyNoise:  GreyNoiseConfig{Enabled: true, DailyBudget: 5},
	}
	if err := Save(path, original); err != nil {
		t.Fatalf("Save: %v", err)
	}
	loaded, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if loaded.Addr() != original.ListenAddr || len(loaded.Firewalls) != 1 || loaded.Firewalls[0].Password != "secret" {
		t.Fatalf("round trip mismatch: %+v", loaded)
	}
}

func TestPollInterval_DefaultsTo30(t *testing.T) {
	if got := (Firewall{}).PollInterval(); got != 30 {
		t.Fatalf("PollInterval() = %d, want 30", got)
	}
	if got := (Firewall{PollIntervalSeconds: 5}).PollInterval(); got != 5 {
		t.Fatalf("PollInterval() = %d, want 5", got)
	}
}

func TestValidPollInterval(t *testing.T) {
	for _, v := range AllowedPollIntervalsSeconds {
		if !ValidPollInterval(v) {
			t.Errorf("expected %d to be a valid poll interval", v)
		}
	}
	if ValidPollInterval(7) {
		t.Errorf("expected 7 to be rejected as an invalid poll interval")
	}
}

func TestStore_AddRejectsDuplicateAndPreservesConfigOnError(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.yaml")
	st, err := OpenStore(path)
	if err != nil {
		t.Fatalf("OpenStore: %v", err)
	}
	if _, err := st.Update(func(c *Config) error {
		c.Firewalls = append(c.Firewalls, Firewall{ID: "home", Host: "10.0.0.1", User: "admin", Password: "x"})
		return nil
	}); err != nil {
		t.Fatalf("Update (add): %v", err)
	}

	// A rejected update must not corrupt the store's in-memory state.
	_, err = st.Update(func(c *Config) error {
		c.Firewalls = append(c.Firewalls, Firewall{ID: "home", Host: "10.0.0.2", User: "admin", Password: "y"})
		return nil // duplicate id — validate() should reject this
	})
	if err == nil {
		t.Fatalf("expected duplicate-id update to be rejected")
	}
	if got := st.Get(); len(got.Firewalls) != 1 || got.Firewalls[0].Host != "10.0.0.1" {
		t.Fatalf("expected the store to be unchanged after a rejected update, got %+v", got)
	}

	// The on-disk file must also reflect only the successful update.
	reloaded, err := Load(path)
	if err != nil {
		t.Fatalf("reloading from disk: %v", err)
	}
	if len(reloaded.Firewalls) != 1 {
		t.Fatalf("expected the rejected update to never reach disk, got %d firewalls", len(reloaded.Firewalls))
	}
}

func TestStore_EditAndRemove(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.yaml")
	st, err := OpenStore(path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := st.Update(func(c *Config) error {
		c.Firewalls = append(c.Firewalls, Firewall{ID: "home", Host: "10.0.0.1", User: "admin", Password: "x"})
		return nil
	}); err != nil {
		t.Fatal(err)
	}

	updated, err := st.Update(func(c *Config) error {
		for i := range c.Firewalls {
			if c.Firewalls[i].ID == "home" {
				c.Firewalls[i].Host = "10.0.0.99"
			}
		}
		return nil
	})
	if err != nil {
		t.Fatalf("Update (edit): %v", err)
	}
	if updated.Firewalls[0].Host != "10.0.0.99" {
		t.Fatalf("expected edited host, got %+v", updated.Firewalls[0])
	}

	removed, err := st.Update(func(c *Config) error {
		var kept []Firewall
		for _, fw := range c.Firewalls {
			if fw.ID != "home" {
				kept = append(kept, fw)
			}
		}
		c.Firewalls = kept
		return nil
	})
	if err != nil {
		t.Fatalf("Update (remove): %v", err)
	}
	if len(removed.Firewalls) != 0 {
		t.Fatalf("expected no firewalls after removal, got %+v", removed.Firewalls)
	}
}
