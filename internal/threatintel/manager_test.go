package threatintel

import (
	"context"
	"testing"
	"time"

	"conntrackd/internal/store"
)

type fakeProvider struct {
	name    string
	verdict Verdict
	err     error
	calls   int
}

func (f *fakeProvider) Name() string { return f.name }
func (f *fakeProvider) Lookup(ctx context.Context, ip string) (Verdict, error) {
	f.calls++
	if f.err != nil {
		return Verdict{}, f.err
	}
	return f.verdict, nil
}

func newTestManager(t *testing.T, p Provider, budget int) (*Manager, *store.Store) {
	t.Helper()
	st, err := store.Open(t.TempDir())
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	t.Cleanup(func() { st.Close() })
	if err := st.SyncFirewall("home", "Home", "10.0.0.1", 22); err != nil {
		t.Fatal(err)
	}
	return NewManager(st, p, budget, 14*24*time.Hour, 3*24*time.Hour), st
}

func TestEnqueue_SkipsAlreadyCachedIP(t *testing.T) {
	p := &fakeProvider{name: "fake", verdict: Verdict{Classification: "benign"}}
	m, st := newTestManager(t, p, 10)

	now := time.Now().UTC()
	if err := st.PutReputation(store.ReputationEntry{
		Provider: "fake", IP: "8.8.8.8", Classification: "benign", CheckedAt: now, ExpiresAt: now.Add(time.Hour),
	}); err != nil {
		t.Fatal(err)
	}
	m.Enqueue("home", "8.8.8.8", 0)

	depth, err := st.QueueDepth("fake")
	if err != nil {
		t.Fatal(err)
	}
	if depth != 0 {
		t.Fatalf("expected already-cached IP to not be enqueued, queue depth = %d", depth)
	}
}

func TestEnqueue_QueuesUncachedIP(t *testing.T) {
	p := &fakeProvider{name: "fake"}
	m, st := newTestManager(t, p, 10)

	m.Enqueue("home", "1.2.3.4", 5)
	depth, err := st.QueueDepth("fake")
	if err != nil {
		t.Fatal(err)
	}
	if depth != 1 {
		t.Fatalf("expected new IP to be queued, depth = %d", depth)
	}
}

func TestTick_LooksUpAndCachesOneItem(t *testing.T) {
	p := &fakeProvider{name: "fake", verdict: Verdict{Classification: "malicious", IsNoise: true}}
	m, st := newTestManager(t, p, 10)

	m.Enqueue("home", "1.2.3.4", 0)
	m.tick(context.Background())

	if p.calls != 1 {
		t.Fatalf("expected 1 provider call, got %d", p.calls)
	}
	entry, ok, err := st.GetReputation("fake", "1.2.3.4")
	if err != nil || !ok {
		t.Fatalf("expected cached verdict after tick: ok=%v err=%v", ok, err)
	}
	if entry.Classification != "malicious" {
		t.Fatalf("cached classification = %q, want malicious", entry.Classification)
	}
	used, _, err := st.RateLimitStatus("fake", 10)
	if err != nil || used != 1 {
		t.Fatalf("expected rate limit used=1, got %d (err %v)", used, err)
	}
}

func TestTick_RespectsExhaustedBudget(t *testing.T) {
	p := &fakeProvider{name: "fake", verdict: Verdict{Classification: "benign"}}
	m, st := newTestManager(t, p, 1)

	m.Enqueue("home", "1.1.1.1", 0)
	m.Enqueue("home", "2.2.2.2", 0)

	m.tick(context.Background()) // uses the only budget slot
	m.tick(context.Background()) // should be a no-op: budget exhausted

	if p.calls != 1 {
		t.Fatalf("expected exactly 1 provider call once budget is exhausted, got %d", p.calls)
	}
	depth, err := st.QueueDepth("fake")
	if err != nil {
		t.Fatal(err)
	}
	if depth != 1 {
		t.Fatalf("expected 1 item still queued after budget exhaustion, got %d", depth)
	}
}

func TestTick_RateLimitErrorRequeuesAndPinsUsedToBudget(t *testing.T) {
	p := &fakeProvider{name: "fake", err: &RateLimitError{Err: errFake}}
	m, st := newTestManager(t, p, 10)

	m.Enqueue("home", "3.3.3.3", 0)
	m.tick(context.Background())

	used, budget, err := st.RateLimitStatus("fake", 10)
	if err != nil {
		t.Fatal(err)
	}
	if used != budget {
		t.Fatalf("expected used to be pinned to budget on rate-limit error, got %d/%d", used, budget)
	}
	depth, err := st.QueueDepth("fake")
	if err != nil {
		t.Fatal(err)
	}
	if depth != 1 {
		t.Fatalf("expected the item requeued after a rate-limit error, depth = %d", depth)
	}
}

func TestCachedReputation_ReturnsRiskInfo(t *testing.T) {
	p := &fakeProvider{name: "fake"}
	m, st := newTestManager(t, p, 10)

	now := time.Now().UTC()
	if err := st.PutReputation(store.ReputationEntry{
		Provider: "fake", IP: "9.9.9.9", Classification: "malicious", IsNoise: true,
		CheckedAt: now, ExpiresAt: now.Add(time.Hour),
	}); err != nil {
		t.Fatal(err)
	}
	info, ok := m.CachedReputation("9.9.9.9")
	if !ok {
		t.Fatalf("expected cached reputation to be found")
	}
	if info.Classification != "malicious" || !info.Resolved {
		t.Fatalf("unexpected reputation info: %+v", info)
	}

	if _, ok := m.CachedReputation("10.10.10.10"); ok {
		t.Fatalf("expected no reputation for an unqueried IP")
	}
}

type fakeError string

func (e fakeError) Error() string { return string(e) }

var errFake = fakeError("simulated rate limit")
