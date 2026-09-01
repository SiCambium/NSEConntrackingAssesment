package store

import (
	"testing"
	"time"
)

func TestBumpPortUsage_ScopeCounting(t *testing.T) {
	s := newTestStore(t)
	if err := s.SyncFirewall("home", "Home", "10.0.0.1", 22); err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()

	// Two new sessions in the same bucket, different scopes — a bucket
	// really can span more than one category.
	if err := s.BumpPortUsage("home", "TCP", 25, "smtp", "a", now, 100, true, ScopeInternal); err != nil {
		t.Fatal(err)
	}
	if err := s.BumpPortUsage("home", "TCP", 25, "smtp", "b", now, 100, true, ScopeOutbound); err != nil {
		t.Fatal(err)
	}
	// A poll update (isNewSession=false) must NOT double-count scope.
	if err := s.BumpPortUsage("home", "TCP", 25, "smtp", "a", now, 50, false, ScopeInternal); err != nil {
		t.Fatal(err)
	}

	usage, err := s.ListPortUsage("home")
	if err != nil {
		t.Fatal(err)
	}
	if len(usage) != 1 {
		t.Fatalf("expected 1 bucket, got %d", len(usage))
	}
	u := usage[0]
	if u.InternalCount != 1 || u.OutboundCount != 1 || u.InboundCount != 0 || u.ExternalCount != 0 {
		t.Fatalf("unexpected scope counts: %+v", u)
	}
	if got := u.Scope(); got != "mixed" {
		t.Fatalf("Scope() = %q, want mixed", got)
	}
}

func TestPortUsage_Scope(t *testing.T) {
	cases := []struct {
		name string
		u    PortUsage
		want string
	}{
		{"none seen", PortUsage{}, ""},
		{"internal only", PortUsage{InternalCount: 3}, "internal"},
		{"outbound only", PortUsage{OutboundCount: 1}, "outbound"},
		{"inbound only", PortUsage{InboundCount: 2}, "inbound"},
		{"external only", PortUsage{ExternalCount: 1}, "external"},
		{"mixed", PortUsage{InternalCount: 1, OutboundCount: 1}, "mixed"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := c.u.Scope(); got != c.want {
				t.Errorf("Scope() = %q, want %q", got, c.want)
			}
		})
	}
}

func TestSessionsForBucket_ReturnsMatchingConnectionsMostRecentFirst(t *testing.T) {
	s := newTestStore(t)
	if err := s.SyncFirewall("home", "Home", "10.0.0.1", 22); err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()

	// Two sessions on the bucket in question (TCP/23/telnet), one older.
	older := FlowSession{
		FirewallID: "home", SessionKey: "TCP|172.23.1.40|203.0.113.66|1|23", Protocol: "TCP",
		OriginSrc: "172.23.1.40", OriginDst: "203.0.113.66", SrcPort: 1, DstPort: 23, Application: "telnet",
		FirstSeen: now.Add(-time.Hour), LastSeen: now.Add(-time.Hour), SampleCount: 1,
	}
	newer := FlowSession{
		FirewallID: "home", SessionKey: "TCP|172.23.1.41|203.0.113.67|2|23", Protocol: "TCP",
		OriginSrc: "172.23.1.41", OriginDst: "203.0.113.67", SrcPort: 2, DstPort: 23, Application: "telnet",
		FirstSeen: now, LastSeen: now, SampleCount: 1,
	}
	// A session on a different bucket (dst_port 443) that must not appear.
	other := FlowSession{
		FirewallID: "home", SessionKey: "TCP|172.23.1.42|1.1.1.1|3|443", Protocol: "TCP",
		OriginSrc: "172.23.1.42", OriginDst: "1.1.1.1", SrcPort: 3, DstPort: 443, Application: "https",
		FirstSeen: now, LastSeen: now, SampleCount: 1,
	}
	for _, fs := range []FlowSession{older, newer, other} {
		if _, err := s.InsertSession(fs); err != nil {
			t.Fatal(err)
		}
	}

	sessions, total, err := s.SessionsForBucket("home", "TCP", 23, "telnet", 200)
	if err != nil {
		t.Fatalf("SessionsForBucket: %v", err)
	}
	if total != 2 || len(sessions) != 2 {
		t.Fatalf("expected 2 matching sessions, got total=%d len=%d", total, len(sessions))
	}
	if sessions[0].OriginSrc != "172.23.1.41" || sessions[1].OriginSrc != "172.23.1.40" {
		t.Fatalf("expected most-recently-seen first, got %+v then %+v", sessions[0], sessions[1])
	}
}

func TestSessionsForBucket_RespectsLimitButReportsTrueTotal(t *testing.T) {
	s := newTestStore(t)
	if err := s.SyncFirewall("home", "Home", "10.0.0.1", 22); err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	for i := 0; i < 5; i++ {
		fs := FlowSession{
			FirewallID: "home", SessionKey: "TCP|src|dst|" + string(rune('a'+i)) + "|23", Protocol: "TCP",
			OriginSrc: "172.23.1.40", OriginDst: "203.0.113.66", SrcPort: i, DstPort: 23, Application: "telnet",
			FirstSeen: now, LastSeen: now, SampleCount: 1,
		}
		if _, err := s.InsertSession(fs); err != nil {
			t.Fatal(err)
		}
	}
	sessions, total, err := s.SessionsForBucket("home", "TCP", 23, "telnet", 2)
	if err != nil {
		t.Fatalf("SessionsForBucket: %v", err)
	}
	if total != 5 {
		t.Fatalf("total = %d, want 5 (the true count, independent of the limit)", total)
	}
	if len(sessions) != 2 {
		t.Fatalf("len(sessions) = %d, want 2 (respecting the limit)", len(sessions))
	}
}
