// Package appserver wires up everything conntrackd needs — config, the
// database, per-firewall pollers, threat-intel, and the web handler — in
// one place, so both entry points (cmd/conntrackd, the plain-browser
// binary, and cmd/conntrack-app, the native desktop window) share the
// exact same backend instead of duplicating this bootstrap. Mirrors how
// NSELocalSSH's cmd/nse-status and cmd/nse-app both just wrap the same
// nse.Server.
package appserver

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"time"

	"conntrackd/internal/config"
	"conntrackd/internal/poller"
	"conntrackd/internal/sshclient"
	"conntrackd/internal/store"
	"conntrackd/internal/threatintel"
	"conntrackd/internal/threatintel/greynoise"
	"conntrackd/internal/web"
)

const (
	pruneInterval   = 24 * time.Hour
	retentionWindow = 90 * 24 * time.Hour
)

// App holds every running component so the caller can read config (e.g.
// the listen address for browser mode) and shut things down cleanly.
type App struct {
	Config  *config.Store
	Store   *store.Store
	Pollers *poller.Manager
	Handler http.Handler
}

// New loads configPath (or the default data-dir location if empty),
// opens the database, starts a poller for every configured firewall, and
// returns the composed web handler. It does not start listening — that's
// the caller's job (plain http.ListenAndServe for browser mode, or a
// webview window's own local listener for app mode).
func New(ctx context.Context, configPath string) (*App, error) {
	dataDir, err := config.EnsureDataDir()
	if err != nil {
		return nil, fmt.Errorf("preparing data dir: %w", err)
	}
	if configPath == "" {
		configPath, err = config.DefaultConfigPath()
		if err != nil {
			return nil, err
		}
	}

	cfgStore, err := config.OpenStore(configPath)
	if err != nil {
		return nil, fmt.Errorf("loading config: %w", err)
	}
	cfg := cfgStore.Get()

	st, err := store.Open(dataDir)
	if err != nil {
		return nil, fmt.Errorf("opening database: %w", err)
	}

	var reputation *threatintel.Manager
	if cfg.GreyNoise.Enabled {
		reputation = threatintel.NewManager(
			st, greynoise.New(), cfg.GreyNoise.Budget(),
			time.Duration(cfg.GreyNoise.CacheTTL())*24*time.Hour,
			time.Duration(cfg.GreyNoise.NegativeTTL())*24*time.Hour,
		)
		go reputation.RunDripWorker(ctx)
	}

	hostKeyCallback := sshclient.TrustedHostKeyCallback(dataDir + "/known_hosts.json")
	var enqueue poller.EnqueueReputation
	if reputation != nil {
		enqueue = reputation.Enqueue
	}
	pollers := poller.NewManager(ctx, st, hostKeyCallback, enqueue)
	pollers.Reload(cfg.Firewalls)

	go runPruneLoop(ctx, st)

	handler := web.New(st, reputation, cfgStore, pollers)
	return &App{Config: cfgStore, Store: st, Pollers: pollers, Handler: handler}, nil
}

// Close stops every poller and closes the database. The caller is
// responsible for shutting down whatever's actually listening (an
// http.Server, a webview window) first.
func (a *App) Close() {
	a.Pollers.StopAll()
	a.Store.Close()
}

func runPruneLoop(ctx context.Context, st *store.Store) {
	ticker := time.NewTicker(pruneInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			cutoff := time.Now().Add(-retentionWindow)
			if _, _, err := st.PruneOlderThan(cutoff); err != nil {
				log.Printf("appserver: prune: %v", err)
			}
		}
	}
}
