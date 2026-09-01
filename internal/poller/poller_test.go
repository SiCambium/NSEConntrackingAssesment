package poller

import (
	"testing"
	"time"

	"conntrackd/internal/nse"
	"conntrackd/internal/store"
)

func newTestPoller(t *testing.T) (*Poller, *store.Store, []string) {
	t.Helper()
	st, err := store.Open(t.TempDir())
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	t.Cleanup(func() { st.Close() })
	if err := st.SyncFirewall("home", "Home", "10.0.0.1", 22); err != nil {
		t.Fatal(err)
	}

	var enqueued []string
	p := New("home", "Home", nil, st, 30*time.Second, func(firewallID, ip string, priority int) {
		enqueued = append(enqueued, ip)
	})
	return p, st, enqueued
}

func TestApplyFlow_NewPublicDestinationEnqueuesReputation(t *testing.T) {
	p, st, _ := newTestPoller(t)
	var enqueued []string
	p.enqueue = func(firewallID, ip string, priority int) { enqueued = append(enqueued, ip) }

	f := nse.ConntrackFlow{
		Protocol: "TCP", OriginSrc: "172.23.1.36", OriginDst: "34.238.200.39",
		SrcPort: "56345", DstPort: "443", TxBytes: 5835, RxBytes: 9386,
		TCPState: "ESTABLISHED", Direction: "LAN TO WAN", Application: "amazon_aws",
	}
	now := time.Now().UTC()
	if err := p.applyFlow(f, SessionKey(f), now); err != nil {
		t.Fatalf("applyFlow: %v", err)
	}
	if len(enqueued) != 1 || enqueued[0] != "34.238.200.39" {
		t.Fatalf("expected public dst IP enqueued for reputation, got %v", enqueued)
	}

	usage, err := st.ListPortUsage("home")
	if err != nil {
		t.Fatal(err)
	}
	if len(usage) != 1 || usage[0].TotalBytes != 5835+9386 {
		t.Fatalf("unexpected port_usage: %+v", usage)
	}
}

func TestApplyFlow_PrivateDestinationSkipsReputation(t *testing.T) {
	p, _, _ := newTestPoller(t)
	var enqueued []string
	p.enqueue = func(firewallID, ip string, priority int) { enqueued = append(enqueued, ip) }

	f := nse.ConntrackFlow{
		Protocol: "UDP", OriginSrc: "172.23.1.36", OriginDst: "172.23.0.1",
		SrcPort: "52738", DstPort: "53", TxBytes: 73, RxBytes: 89, Direction: "LAN TO LAN", Application: "dns",
	}
	if err := p.applyFlow(f, SessionKey(f), time.Now().UTC()); err != nil {
		t.Fatalf("applyFlow: %v", err)
	}
	if len(enqueued) != 0 {
		t.Fatalf("expected no reputation lookup for a private destination, got %v", enqueued)
	}
}

func TestApplyFlow_UpdateComputesByteDeltaAndDetectsStateChange(t *testing.T) {
	p, st, _ := newTestPoller(t)

	f := nse.ConntrackFlow{
		Protocol: "TCP", OriginSrc: "172.23.1.36", OriginDst: "34.238.200.39",
		SrcPort: "56345", DstPort: "443", TxBytes: 1000, RxBytes: 1000, TCPState: "SYN_SENT",
	}
	key := SessionKey(f)
	t0 := time.Now().UTC()
	if err := p.applyFlow(f, key, t0); err != nil {
		t.Fatal(err)
	}

	// Second poll: counters grew, state changed ESTABLISHED.
	f.TxBytes, f.RxBytes, f.TCPState = 3000, 2000, "ESTABLISHED"
	t1 := t0.Add(30 * time.Second)
	if err := p.applyFlow(f, key, t1); err != nil {
		t.Fatal(err)
	}

	usage, err := st.ListPortUsage("home")
	if err != nil {
		t.Fatal(err)
	}
	if len(usage) != 1 {
		t.Fatalf("expected 1 port_usage bucket, got %d", len(usage))
	}
	wantTotal := int64(1000+1000) + int64((3000+2000)-(1000+1000))
	if usage[0].TotalBytes != wantTotal {
		t.Fatalf("TotalBytes = %d, want %d (delta accounting)", usage[0].TotalBytes, wantTotal)
	}
	if usage[0].SampleCount != 1 {
		t.Fatalf("SampleCount = %d, want 1 (only the new-session poll counts)", usage[0].SampleCount)
	}

	tracked := p.open[key]
	samples, err := st.SessionSamples(tracked.sessionID)
	if err != nil {
		t.Fatal(err)
	}
	if len(samples) != 2 {
		t.Fatalf("expected start + state_change samples, got %d", len(samples))
	}
	if samples[1].EventType != "state_change" {
		t.Fatalf("expected second sample to be state_change, got %s", samples[1].EventType)
	}

	open, err := st.OpenSessions("home")
	if err != nil {
		t.Fatal(err)
	}
	got, ok := open[key]
	if !ok || got.TCPState != "ESTABLISHED" || got.SampleCount != 2 {
		t.Fatalf("unexpected persisted session state: ok=%v %+v", ok, got)
	}
}

func TestApplyFlow_NoHeartbeatBeforeIntervalElapses(t *testing.T) {
	p, st, _ := newTestPoller(t)
	f := nse.ConntrackFlow{
		Protocol: "TCP", OriginSrc: "172.23.1.36", OriginDst: "34.238.200.39",
		SrcPort: "56345", DstPort: "443", TxBytes: 1000, RxBytes: 1000, TCPState: "ESTABLISHED",
	}
	key := SessionKey(f)
	t0 := time.Now().UTC()
	if err := p.applyFlow(f, key, t0); err != nil {
		t.Fatal(err)
	}
	// Same state, well within the heartbeat interval.
	f.TxBytes, f.RxBytes = 1200, 1200
	if err := p.applyFlow(f, key, t0.Add(30*time.Second)); err != nil {
		t.Fatal(err)
	}
	tracked := p.open[key]
	samples, err := st.SessionSamples(tracked.sessionID)
	if err != nil {
		t.Fatal(err)
	}
	if len(samples) != 1 {
		t.Fatalf("expected only the initial 'start' sample before the heartbeat interval, got %d", len(samples))
	}
}

func TestCloseMissing_ClosesSessionsAbsentFromLatestPoll(t *testing.T) {
	p, st, _ := newTestPoller(t)
	f := nse.ConntrackFlow{
		Protocol: "TCP", OriginSrc: "172.23.1.36", OriginDst: "34.238.200.39",
		SrcPort: "56345", DstPort: "443", TxBytes: 1000, RxBytes: 1000, TCPState: "ESTABLISHED",
	}
	key := SessionKey(f)
	t0 := time.Now().UTC()
	if err := p.applyFlow(f, key, t0); err != nil {
		t.Fatal(err)
	}

	// Flow no longer present in the next poll.
	p.closeMissing(map[string]bool{}, t0.Add(30*time.Second))

	if _, stillTracked := p.open[key]; stillTracked {
		t.Fatalf("expected key removed from in-memory open map after close")
	}
	open, err := st.OpenSessions("home")
	if err != nil {
		t.Fatal(err)
	}
	if _, stillOpen := open[key]; stillOpen {
		t.Fatalf("expected session closed in store")
	}
}

func TestLoadOpenSessions_RebuildsMapFromStore(t *testing.T) {
	p, st, _ := newTestPoller(t)
	f := nse.ConntrackFlow{
		Protocol: "TCP", OriginSrc: "172.23.1.36", OriginDst: "34.238.200.39",
		SrcPort: "56345", DstPort: "443", TxBytes: 5000, RxBytes: 5000, TCPState: "ESTABLISHED",
	}
	key := SessionKey(f)
	if err := p.applyFlow(f, key, time.Now().UTC()); err != nil {
		t.Fatal(err)
	}

	// Simulate a restart: fresh Poller, same store.
	fresh := New("home", "Home", nil, st, 30*time.Second, nil)
	if err := fresh.loadOpenSessions(); err != nil {
		t.Fatalf("loadOpenSessions: %v", err)
	}
	tracked, ok := fresh.open[key]
	if !ok {
		t.Fatalf("expected session rebuilt into open map after restart")
	}
	if tracked.txBytes != 5000 || tracked.rxBytes != 5000 {
		t.Fatalf("expected rebuilt counters to match store, got %+v", tracked)
	}
}
