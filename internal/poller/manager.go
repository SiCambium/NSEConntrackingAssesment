package poller

import (
	"context"
	"log"
	"sync"
	"time"

	"conntrackd/internal/config"
	"conntrackd/internal/sshclient"
	"conntrackd/internal/store"

	"golang.org/x/crypto/ssh"
)

type running struct {
	cancel context.CancelFunc
	client *sshclient.Client
	fw     config.Firewall
}

// Manager supervises one Poller goroutine per configured firewall and lets
// the set of firewalls (and their host/user/password/poll interval) change
// at runtime — via Reload — without restarting the process. This is what
// lets the Settings UI add/edit/remove a firewall and have it take effect
// immediately.
type Manager struct {
	store           *store.Store
	hostKeyCallback ssh.HostKeyCallback
	enqueue         EnqueueReputation

	mu      sync.Mutex
	ctx     context.Context
	running map[string]*running
}

func NewManager(ctx context.Context, st *store.Store, hostKeyCallback ssh.HostKeyCallback, enqueue EnqueueReputation) *Manager {
	return &Manager{
		store: st, hostKeyCallback: hostKeyCallback, enqueue: enqueue,
		ctx: ctx, running: map[string]*running{},
	}
}

// Reload starts pollers for any firewall in firewalls not currently
// running, stops any currently-running firewall no longer present, and
// restarts (stop then start) any whose connection details or poll
// interval changed. Safe to call repeatedly, including with the same set.
func (m *Manager) Reload(firewalls []config.Firewall) {
	m.mu.Lock()
	defer m.mu.Unlock()

	want := make(map[string]config.Firewall, len(firewalls))
	for _, fw := range firewalls {
		want[fw.ID] = fw
	}

	for id, r := range m.running {
		if _, ok := want[id]; !ok {
			m.stopLocked(id)
			continue
		}
		if connectionChanged(r.fw, want[id]) {
			m.stopLocked(id)
		}
	}
	for id, fw := range want {
		if _, ok := m.running[id]; !ok {
			m.startLocked(fw)
		}
	}
}

func connectionChanged(old, next config.Firewall) bool {
	return old.Host != next.Host || old.Port != next.Port || old.User != next.User ||
		old.Password != next.Password || old.PollInterval() != next.PollInterval()
}

func (m *Manager) startLocked(fw config.Firewall) {
	if err := m.store.SyncFirewall(fw.ID, fw.Name, fw.Host, fw.Port); err != nil {
		log.Printf("poller manager: registering firewall %s: %v", fw.ID, err)
		return
	}
	client := sshclient.New(sshclient.Config{Host: fw.Host, Port: fw.Port, User: fw.User, Password: fw.Password}, m.hostKeyCallback)
	p := New(fw.ID, fw.Name, client, m.store, time.Duration(fw.PollInterval())*time.Second, m.enqueue)

	ctx, cancel := context.WithCancel(m.ctx)
	m.running[fw.ID] = &running{cancel: cancel, client: client, fw: fw}
	go p.Run(ctx)
	log.Printf("poller manager: polling %s (%s) every %ds", fw.Name, fw.Host, fw.PollInterval())
}

// stopLocked cancels a running poller's context and closes its SSH
// connection. It does not touch that firewall's stored history — removing
// a firewall from config only stops polling it, it never deletes data.
func (m *Manager) stopLocked(id string) {
	r, ok := m.running[id]
	if !ok {
		return
	}
	r.cancel()
	r.client.Close()
	delete(m.running, id)
	log.Printf("poller manager: stopped polling %s", id)
}

// StopAll cancels every running poller — used on shutdown.
func (m *Manager) StopAll() {
	m.mu.Lock()
	defer m.mu.Unlock()
	for id := range m.running {
		m.stopLocked(id)
	}
}

// RestartAll stops and restarts every currently running poller — used
// after a full database clear (see store.ClearAllHistory), since each
// poller's in-memory open-session map would otherwise keep referencing
// session IDs the database no longer has, silently no-op-ing their
// updates until they naturally close and reopen. Restarting rebuilds each
// poller from scratch, which correctly finds zero open sessions in the
// now-empty database.
func (m *Manager) RestartAll() {
	m.mu.Lock()
	defer m.mu.Unlock()
	fws := make([]config.Firewall, 0, len(m.running))
	for _, r := range m.running {
		fws = append(fws, r.fw)
	}
	for _, fw := range fws {
		m.stopLocked(fw.ID)
	}
	for _, fw := range fws {
		m.startLocked(fw)
	}
}

// RunningIDs returns the firewall IDs currently being polled.
func (m *Manager) RunningIDs() []string {
	m.mu.Lock()
	defer m.mu.Unlock()
	ids := make([]string, 0, len(m.running))
	for id := range m.running {
		ids = append(ids, id)
	}
	return ids
}
