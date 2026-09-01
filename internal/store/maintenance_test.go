package store

import (
	"testing"
	"time"
)

func TestClearAllHistory_WipesDataButKeepsFirewall(t *testing.T) {
	s := newTestStore(t)
	if err := s.SyncFirewall("home", "Home", "10.0.0.1", 22); err != nil {
		t.Fatal(err)
	}
	if err := s.RecordPollSuccess("home", 100, 50, 20); err != nil {
		t.Fatal(err)
	}

	now := time.Now().UTC()
	id, err := s.InsertSession(FlowSession{
		FirewallID: "home", SessionKey: "TCP|a|b|1|2", Protocol: "TCP", OriginSrc: "a", OriginDst: "b",
		FirstSeen: now, LastSeen: now, SampleCount: 1,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := s.InsertSample(FlowSample{SessionID: id, FirewallID: "home", EventType: "start", SeenAt: now, Protocol: "TCP", OriginSrc: "a", OriginDst: "b"}); err != nil {
		t.Fatal(err)
	}
	if err := s.BumpPortUsage("home", "TCP", 2, "", "b", now, 100, true); err != nil {
		t.Fatal(err)
	}
	if err := s.ApprovePort("home", "TCP", 2, "", "label", "tester"); err != nil {
		t.Fatal(err)
	}
	if err := s.PutReputation(ReputationEntry{Provider: "p", IP: "b", CheckedAt: now, ExpiresAt: now.Add(time.Hour)}); err != nil {
		t.Fatal(err)
	}
	if err := s.EnqueueReputationLookup("p", "c", "home", 0); err != nil {
		t.Fatal(err)
	}

	if err := s.ClearAllHistory(); err != nil {
		t.Fatalf("ClearAllHistory: %v", err)
	}

	sessions, err := s.OpenSessions("home")
	if err != nil || len(sessions) != 0 {
		t.Fatalf("expected no open sessions after clear, got %v (err %v)", sessions, err)
	}
	usage, err := s.ListPortUsage("home")
	if err != nil || len(usage) != 0 {
		t.Fatalf("expected no port_usage after clear, got %v (err %v)", usage, err)
	}
	approved, err := s.ListApprovedPorts("home")
	if err != nil || len(approved) != 0 {
		t.Fatalf("expected no approved_ports after clear, got %v (err %v)", approved, err)
	}
	if _, ok, err := s.GetReputation("p", "b"); err != nil || ok {
		t.Fatalf("expected reputation cache cleared, ok=%v err=%v", ok, err)
	}
	depth, err := s.QueueDepth("p")
	if err != nil || depth != 0 {
		t.Fatalf("expected reputation queue cleared, depth=%d err=%v", depth, err)
	}

	// The firewall row itself must survive — only its history and cached
	// summary counters reset.
	fw, ok, err := s.GetFirewall("home")
	if err != nil || !ok {
		t.Fatalf("expected firewall to survive a clear: ok=%v err=%v", ok, err)
	}
	if fw.ConntrackUsage != 0 || fw.NATUsage != 0 {
		t.Fatalf("expected stale summary counters reset to zero, got %+v", fw)
	}
}

func TestSizeBytes_ReflectsRealFile(t *testing.T) {
	s := newTestStore(t)
	size, err := s.SizeBytes()
	if err != nil {
		t.Fatalf("SizeBytes: %v", err)
	}
	if size <= 0 {
		t.Fatalf("expected a positive database size for an initialized store, got %d", size)
	}
}
