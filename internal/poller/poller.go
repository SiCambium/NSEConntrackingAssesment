// Package poller runs the per-firewall SSH poll loop: parse `show
// conntrack` / `service show conntrack`, diff against the previously-known
// open flows, and write the results into store.Store.
package poller

import (
	"context"
	"log"
	"time"

	"conntrackd/internal/nse"
	"conntrackd/internal/sshclient"
	"conntrackd/internal/store"
)

// HeartbeatInterval is how often a still-open, unchanged flow gets a
// 'heartbeat' flow_samples row written, so long-lived sessions (VPN, SSH,
// cloud sync) still produce a byte-count time series in search history
// instead of only a start/end pair.
const HeartbeatInterval = 5 * time.Minute

const cmdShowConntrack = "show conntrack"
const cmdServiceShowConntrack = "service show conntrack"

// EnqueueReputation is called for every newly-seen, non-private
// destination IP, so the poller can request a threat-intel lookup without
// importing the threatintel package directly (avoids a poller<->threatintel
// dependency cycle, since threatintel also needs the store).
type EnqueueReputation func(firewallID, ip string, priority int)

type trackedSession struct {
	sessionID    int64
	txBytes      int64
	rxBytes      int64
	tcpState     string
	lastSampleAt time.Time
}

// Poller runs the poll loop for one firewall.
type Poller struct {
	FirewallID string
	Name       string
	client     *sshclient.Client
	store      *store.Store
	interval   time.Duration
	enqueue    EnqueueReputation

	open map[string]*trackedSession
}

func New(firewallID, name string, client *sshclient.Client, st *store.Store, interval time.Duration, enqueue EnqueueReputation) *Poller {
	return &Poller{
		FirewallID: firewallID,
		Name:       name,
		client:     client,
		store:      st,
		interval:   interval,
		enqueue:    enqueue,
		open:       map[string]*trackedSession{},
	}
}

// Run polls on a ticker until ctx is cancelled. It rebuilds its in-memory
// open-session map from the store first, so a restart doesn't treat every
// still-live flow as brand new.
func (p *Poller) Run(ctx context.Context) {
	if err := p.loadOpenSessions(); err != nil {
		log.Printf("poller[%s]: loading open sessions: %v", p.FirewallID, err)
	}

	p.pollOnce(ctx)
	ticker := time.NewTicker(p.interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			p.pollOnce(ctx)
		}
	}
}

func (p *Poller) loadOpenSessions() error {
	sessions, err := p.store.OpenSessions(p.FirewallID)
	if err != nil {
		return err
	}
	for key, fs := range sessions {
		p.open[key] = &trackedSession{
			sessionID: fs.ID,
			txBytes:   fs.TxBytes,
			rxBytes:   fs.RxBytes,
			tcpState:  fs.TCPState,
			// lastSampleAt is unknown across a restart; treat "now" as the
			// baseline so the next heartbeat fires a full interval out
			// rather than immediately for every resumed session.
			lastSampleAt: time.Now(),
		}
	}
	return nil
}

func (p *Poller) pollOnce(ctx context.Context) {
	summaryRaw, err := p.client.Run(cmdServiceShowConntrack, 20*time.Second)
	if err != nil {
		log.Printf("poller[%s]: %s: %v", p.FirewallID, cmdServiceShowConntrack, err)
		_ = p.store.RecordPollFailure(p.FirewallID, err)
		return
	}
	summary := nse.ParseConntrackSummary(summaryRaw)

	flowsRaw, err := p.client.Run(cmdShowConntrack, 30*time.Second)
	if err != nil {
		log.Printf("poller[%s]: %s: %v", p.FirewallID, cmdShowConntrack, err)
		_ = p.store.RecordPollFailure(p.FirewallID, err)
		return
	}
	flows := nse.ParseConntrackFlows(flowsRaw)

	if err := p.store.RecordPollSuccess(p.FirewallID, summary.Limit, summary.Usage, summary.NAT); err != nil {
		log.Printf("poller[%s]: recording poll success: %v", p.FirewallID, err)
	}

	p.ApplyPoll(flows, time.Now().UTC())
}

// ApplyPoll updates the store from one batch of already-parsed flows as of
// now — split out from pollOnce so the same diff/upsert/close logic a live
// SSH poll uses can also be driven by something else, such as a replay
// tool feeding captured fixture output through the exact same path (see
// cmd/replay), or a test.
func (p *Poller) ApplyPoll(flows []nse.ConntrackFlow, now time.Time) {
	seen := make(map[string]bool, len(flows))
	for _, f := range flows {
		key := SessionKey(f)
		seen[key] = true
		if err := p.applyFlow(f, key, now); err != nil {
			log.Printf("poller[%s]: applying flow %s: %v", p.FirewallID, key, err)
		}
	}
	p.closeMissing(seen, now)
}

// closeMissing closes every tracked session whose key is absent from the
// latest poll's seen set — split out from pollOnce so it can be exercised
// without a live SSH client in tests.
func (p *Poller) closeMissing(seen map[string]bool, now time.Time) {
	for key, tracked := range p.open {
		if seen[key] {
			continue
		}
		if err := p.store.CloseSession(tracked.sessionID, now); err != nil {
			log.Printf("poller[%s]: closing session %s: %v", p.FirewallID, key, err)
			continue
		}
		delete(p.open, key)
	}
}

func (p *Poller) applyFlow(f nse.ConntrackFlow, key string, now time.Time) error {
	srcPort, dstPort := atoiSafe(f.SrcPort), atoiSafe(f.DstPort)
	isPrivate := IsPrivateOrReserved(f.OriginDst)
	newBytes := f.TxBytes + f.RxBytes

	tracked, existing := p.open[key]
	if !existing {
		fs := store.FlowSession{
			FirewallID: p.FirewallID, SessionKey: key, Protocol: f.Protocol,
			OriginSrc: f.OriginSrc, OriginDst: f.OriginDst, SrcPort: srcPort, DstPort: dstPort,
			NatedIP: f.NatedIP, NatedPort: atoiSafe(f.NatedPort), TCPState: f.TCPState,
			Direction: f.Direction, Application: f.Application, HostName: f.HostName,
			TTLLast: atoiSafe(f.TTL), TxPackets: f.TxPackets, TxBytes: f.TxBytes,
			RxPackets: f.RxPackets, RxBytes: f.RxBytes, IsDstPrivate: isPrivate,
			FirstSeen: now, LastSeen: now, SampleCount: 1,
		}
		id, err := p.store.InsertSession(fs)
		if err != nil {
			return err
		}
		if err := p.store.InsertSample(sampleFromFlow(id, p.FirewallID, "start", now, f)); err != nil {
			return err
		}
		if err := p.store.BumpPortUsage(p.FirewallID, f.Protocol, dstPort, f.Application, f.OriginDst, now, newBytes, true); err != nil {
			return err
		}
		if !isPrivate && p.enqueue != nil {
			p.enqueue(p.FirewallID, f.OriginDst, 0)
		}
		p.open[key] = &trackedSession{sessionID: id, txBytes: f.TxBytes, rxBytes: f.RxBytes, tcpState: f.TCPState, lastSampleAt: now}
		return nil
	}

	delta := (f.TxBytes + f.RxBytes) - (tracked.txBytes + tracked.rxBytes)
	if delta < 0 {
		// Counters went backwards (device-side reset/rollover) — treat as
		// a fresh baseline rather than recording a negative byte delta.
		delta = 0
	}
	fs := store.FlowSession{
		TCPState: f.TCPState, Direction: f.Direction, Application: f.Application, HostName: f.HostName,
		TTLLast: atoiSafe(f.TTL), TxPackets: f.TxPackets, TxBytes: f.TxBytes, RxPackets: f.RxPackets,
		RxBytes: f.RxBytes, LastSeen: now,
	}
	if err := p.store.UpdateSession(tracked.sessionID, fs); err != nil {
		return err
	}
	if err := p.store.BumpPortUsage(p.FirewallID, f.Protocol, dstPort, f.Application, f.OriginDst, now, delta, false); err != nil {
		return err
	}

	stateChanged := f.TCPState != tracked.tcpState
	dueForHeartbeat := now.Sub(tracked.lastSampleAt) >= HeartbeatInterval
	if stateChanged || dueForHeartbeat {
		eventType := "heartbeat"
		if stateChanged {
			eventType = "state_change"
		}
		if err := p.store.InsertSample(sampleFromFlow(tracked.sessionID, p.FirewallID, eventType, now, f)); err != nil {
			return err
		}
		tracked.lastSampleAt = now
	}

	tracked.txBytes, tracked.rxBytes, tracked.tcpState = f.TxBytes, f.RxBytes, f.TCPState
	return nil
}

func sampleFromFlow(sessionID int64, firewallID, eventType string, seenAt time.Time, f nse.ConntrackFlow) store.FlowSample {
	return store.FlowSample{
		SessionID: sessionID, FirewallID: firewallID, EventType: eventType, SeenAt: seenAt,
		Protocol: f.Protocol, OriginSrc: f.OriginSrc, OriginDst: f.OriginDst,
		SrcPort: atoiSafe(f.SrcPort), DstPort: atoiSafe(f.DstPort),
		NatedIP: f.NatedIP, NatedPort: atoiSafe(f.NatedPort), TCPState: f.TCPState,
		Direction: f.Direction, Application: f.Application, HostName: f.HostName, TTL: atoiSafe(f.TTL),
		TxPackets: f.TxPackets, TxBytes: f.TxBytes, RxPackets: f.RxPackets, RxBytes: f.RxBytes,
	}
}
