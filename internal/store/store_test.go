package store

import (
	"testing"
	"time"
)

func newTestStore(t *testing.T) *Store {
	t.Helper()
	s, err := Open(t.TempDir())
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { s.Close() })
	return s
}

func TestFirewallLifecycle(t *testing.T) {
	s := newTestStore(t)
	if err := s.SyncFirewall("home", "Home", "10.0.0.1", 22); err != nil {
		t.Fatalf("SyncFirewall: %v", err)
	}
	if err := s.RecordPollSuccess("home", 262144, 240, 157); err != nil {
		t.Fatalf("RecordPollSuccess: %v", err)
	}
	fw, ok, err := s.GetFirewall("home")
	if err != nil || !ok {
		t.Fatalf("GetFirewall: ok=%v err=%v", ok, err)
	}
	if fw.ConntrackUsage != 240 || !fw.LastPollOK {
		t.Fatalf("unexpected firewall state: %+v", fw)
	}
}

func TestSessionAndPortUsageLifecycle(t *testing.T) {
	s := newTestStore(t)
	if err := s.SyncFirewall("home", "Home", "10.0.0.1", 22); err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()

	fs := FlowSession{
		FirewallID: "home", SessionKey: "TCP|172.23.1.36|34.238.200.39|56345|443",
		Protocol: "TCP", OriginSrc: "172.23.1.36", OriginDst: "34.238.200.39",
		SrcPort: 56345, DstPort: 443, TCPState: "ESTABLISHED", Direction: "LAN TO WAN",
		Application: "amazon_aws", TxBytes: 5835, RxBytes: 9386, TxPackets: 24, RxPackets: 24,
		FirstSeen: now, LastSeen: now, SampleCount: 1,
	}
	id, err := s.InsertSession(fs)
	if err != nil {
		t.Fatalf("InsertSession: %v", err)
	}
	if err := s.InsertSample(FlowSample{
		SessionID: id, FirewallID: "home", EventType: "start", SeenAt: now,
		Protocol: fs.Protocol, OriginSrc: fs.OriginSrc, OriginDst: fs.OriginDst,
		SrcPort: fs.SrcPort, DstPort: fs.DstPort, TCPState: fs.TCPState, Direction: fs.Direction,
		Application: fs.Application, TxBytes: fs.TxBytes, RxBytes: fs.RxBytes,
	}); err != nil {
		t.Fatalf("InsertSample: %v", err)
	}
	if err := s.BumpPortUsage("home", "TCP", 443, "amazon_aws", fs.OriginDst, now, fs.TxBytes+fs.RxBytes, true); err != nil {
		t.Fatalf("BumpPortUsage: %v", err)
	}

	// Poll again: same session reappears with higher counters.
	later := now.Add(30 * time.Second)
	fs.TxBytes, fs.RxBytes = 8000, 15000
	fs.LastSeen = later
	fs.SampleCount = 2
	if err := s.UpdateSession(id, fs); err != nil {
		t.Fatalf("UpdateSession: %v", err)
	}
	delta := (8000 + 15000) - (5835 + 9386)
	if err := s.BumpPortUsage("home", "TCP", 443, "amazon_aws", fs.OriginDst, later, int64(delta), false); err != nil {
		t.Fatalf("BumpPortUsage delta: %v", err)
	}

	open, err := s.OpenSessions("home")
	if err != nil {
		t.Fatalf("OpenSessions: %v", err)
	}
	got, ok := open[fs.SessionKey]
	if !ok {
		t.Fatalf("expected open session for key %s", fs.SessionKey)
	}
	if got.TxBytes != 8000 || got.SampleCount != 2 {
		t.Fatalf("unexpected updated session: %+v", got)
	}

	// Flow disappears from the next poll: close it.
	if err := s.CloseSession(id, later.Add(time.Second)); err != nil {
		t.Fatalf("CloseSession: %v", err)
	}
	if err := s.InsertSample(FlowSample{
		SessionID: id, FirewallID: "home", EventType: "end", SeenAt: later.Add(time.Second),
		Protocol: fs.Protocol, OriginSrc: fs.OriginSrc, OriginDst: fs.OriginDst,
		SrcPort: fs.SrcPort, DstPort: fs.DstPort, Application: fs.Application,
		TxBytes: fs.TxBytes, RxBytes: fs.RxBytes,
	}); err != nil {
		t.Fatalf("InsertSample end: %v", err)
	}

	openAfterClose, err := s.OpenSessions("home")
	if err != nil {
		t.Fatal(err)
	}
	if _, stillOpen := openAfterClose[fs.SessionKey]; stillOpen {
		t.Fatalf("expected session to be closed")
	}

	usage, err := s.ListPortUsage("home")
	if err != nil {
		t.Fatalf("ListPortUsage: %v", err)
	}
	if len(usage) != 1 {
		t.Fatalf("expected 1 port_usage row, got %d", len(usage))
	}
	u := usage[0]
	if u.TotalBytes != 5835+9386+int64(delta) {
		t.Fatalf("total_bytes = %d, want %d", u.TotalBytes, 5835+9386+int64(delta))
	}
	if u.SampleCount != 1 {
		t.Fatalf("sample_count = %d, want 1 (only counted on new session)", u.SampleCount)
	}
	if u.DistinctDstIPs != 1 {
		t.Fatalf("distinct_dst_ips = %d, want 1", u.DistinctDstIPs)
	}

	// Search should find it by dst port and by dst IP substring.
	results, total, err := s.SearchSessions(FlowSearchFilter{FirewallID: "home", DstPort: 443})
	if err != nil {
		t.Fatalf("SearchSessions: %v", err)
	}
	if total != 1 || len(results) != 1 {
		t.Fatalf("SearchSessions by port: total=%d len=%d", total, len(results))
	}
	results, total, err = s.SearchSessions(FlowSearchFilter{FirewallID: "home", OriginDst: "34.238"})
	if err != nil {
		t.Fatalf("SearchSessions: %v", err)
	}
	if total != 1 || len(results) != 1 {
		t.Fatalf("SearchSessions by dst substring: total=%d len=%d", total, len(results))
	}

	samples, err := s.SessionSamples(id)
	if err != nil {
		t.Fatalf("SessionSamples: %v", err)
	}
	if len(samples) != 2 {
		t.Fatalf("expected 2 sample events (start, end), got %d", len(samples))
	}
}

func TestApprovedPorts(t *testing.T) {
	s := newTestStore(t)
	if err := s.SyncFirewall("home", "Home", "10.0.0.1", 22); err != nil {
		t.Fatal(err)
	}
	if err := s.ApprovePort("home", "TCP", 443, "amazon_aws", "AWS HTTPS", "simon"); err != nil {
		t.Fatalf("ApprovePort: %v", err)
	}
	set, err := s.ApprovedSet("home")
	if err != nil {
		t.Fatalf("ApprovedSet: %v", err)
	}
	if !set["TCP|443|amazon_aws"] {
		t.Fatalf("expected TCP|443|amazon_aws to be approved, got %v", set)
	}
	if err := s.UnapprovePort("home", "TCP", 443, "amazon_aws"); err != nil {
		t.Fatalf("UnapprovePort: %v", err)
	}
	set, err = s.ApprovedSet("home")
	if err != nil {
		t.Fatal(err)
	}
	if len(set) != 0 {
		t.Fatalf("expected empty approved set after unapprove, got %v", set)
	}
}

func TestReputationCacheAndQueue(t *testing.T) {
	s := newTestStore(t)
	if err := s.SyncFirewall("home", "Home", "10.0.0.1", 22); err != nil {
		t.Fatal(err)
	}

	if _, ok, err := s.GetReputation("greynoise", "1.2.3.4"); err != nil || ok {
		t.Fatalf("expected no cache entry yet, ok=%v err=%v", ok, err)
	}

	now := time.Now().UTC()
	entry := ReputationEntry{
		Provider: "greynoise", IP: "1.2.3.4", Classification: "malicious",
		IsNoise: true, CheckedAt: now, ExpiresAt: now.Add(14 * 24 * time.Hour),
	}
	if err := s.PutReputation(entry); err != nil {
		t.Fatalf("PutReputation: %v", err)
	}
	got, ok, err := s.GetReputation("greynoise", "1.2.3.4")
	if err != nil || !ok {
		t.Fatalf("GetReputation after put: ok=%v err=%v", ok, err)
	}
	if got.Classification != "malicious" || !got.IsNoise {
		t.Fatalf("unexpected cached entry: %+v", got)
	}

	// Expired entries should report ok=false.
	expired := ReputationEntry{
		Provider: "greynoise", IP: "5.6.7.8", Classification: "unknown",
		CheckedAt: now.Add(-100 * time.Hour), ExpiresAt: now.Add(-1 * time.Hour),
	}
	if err := s.PutReputation(expired); err != nil {
		t.Fatal(err)
	}
	if _, ok, err := s.GetReputation("greynoise", "5.6.7.8"); err != nil || ok {
		t.Fatalf("expected expired entry to report not-ok, ok=%v err=%v", ok, err)
	}

	// Queue: enqueue two, dedupe a third, pop respects priority then FIFO.
	if err := s.EnqueueReputationLookup("greynoise", "9.9.9.9", "home", 0); err != nil {
		t.Fatal(err)
	}
	if err := s.EnqueueReputationLookup("greynoise", "8.8.8.8", "home", 5); err != nil {
		t.Fatal(err)
	}
	if err := s.EnqueueReputationLookup("greynoise", "9.9.9.9", "home", 0); err != nil {
		t.Fatal(err) // dedup, should not error or double-insert
	}
	depth, err := s.QueueDepth("greynoise")
	if err != nil || depth != 2 {
		t.Fatalf("QueueDepth = %d, err=%v, want 2", depth, err)
	}
	item, ok, err := s.PopNextReputationLookup("greynoise")
	if err != nil || !ok {
		t.Fatalf("PopNextReputationLookup: ok=%v err=%v", ok, err)
	}
	if item.IP != "8.8.8.8" {
		t.Fatalf("expected higher-priority IP first, got %s", item.IP)
	}

	// Rate limit tracking.
	used, budget, err := s.RateLimitStatus("greynoise", 10)
	if err != nil {
		t.Fatalf("RateLimitStatus: %v", err)
	}
	if used != 0 || budget != 10 {
		t.Fatalf("RateLimitStatus initial = %d/%d, want 0/10", used, budget)
	}
	if err := s.IncrementRateLimit("greynoise", false); err != nil {
		t.Fatal(err)
	}
	used, budget, err = s.RateLimitStatus("greynoise", 10)
	if err != nil || used != 1 || budget != 10 {
		t.Fatalf("RateLimitStatus after increment = %d/%d err=%v, want 1/10", used, budget, err)
	}
}

func TestPruneOlderThan(t *testing.T) {
	s := newTestStore(t)
	if err := s.SyncFirewall("home", "Home", "10.0.0.1", 22); err != nil {
		t.Fatal(err)
	}
	old := time.Now().Add(-100 * 24 * time.Hour)
	fs := FlowSession{
		FirewallID: "home", SessionKey: "UDP|a|b|1|2", Protocol: "UDP", OriginSrc: "a", OriginDst: "b",
		FirstSeen: old, LastSeen: old, SampleCount: 1,
	}
	id, err := s.InsertSession(fs)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.InsertSample(FlowSample{SessionID: id, FirewallID: "home", EventType: "start", SeenAt: old, Protocol: "UDP", OriginSrc: "a", OriginDst: "b"}); err != nil {
		t.Fatal(err)
	}
	if err := s.CloseSession(id, old.Add(time.Minute)); err != nil {
		t.Fatal(err)
	}

	cutoff := time.Now().Add(-90 * 24 * time.Hour)
	sessDel, sampDel, err := s.PruneOlderThan(cutoff)
	if err != nil {
		t.Fatalf("PruneOlderThan: %v", err)
	}
	if sessDel != 1 || sampDel != 1 {
		t.Fatalf("PruneOlderThan deleted sessions=%d samples=%d, want 1/1", sessDel, sampDel)
	}
}
