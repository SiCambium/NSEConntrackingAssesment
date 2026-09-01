package enrich

import (
	"context"
	"errors"
	"testing"
)

type fakeSource struct {
	key, name string
	result    Result
	err       error
	calls     int
}

func (f *fakeSource) Key() string  { return f.key }
func (f *fakeSource) Name() string { return f.name }
func (f *fakeSource) Lookup(ctx context.Context, ip string) (Result, error) {
	f.calls++
	return f.result, f.err
}

func TestRegistry_TracksSuccessAndFailureStatus(t *testing.T) {
	ok := &fakeSource{key: "ok", name: "OK Source", result: Result{Source: "ok", Summary: "fine"}}
	bad := &fakeSource{key: "bad", name: "Bad Source", err: errors.New("boom")}
	r := NewRegistry(ok, bad)

	if _, err := r.Lookup(context.Background(), "ok", "8.8.8.8"); err != nil {
		t.Fatalf("Lookup(ok): %v", err)
	}
	if _, err := r.Lookup(context.Background(), "bad", "8.8.8.8"); err == nil {
		t.Fatalf("expected Lookup(bad) to return an error")
	}
	if _, err := r.Lookup(context.Background(), "bad", "8.8.8.8"); err == nil {
		t.Fatalf("expected second Lookup(bad) to also error")
	}

	statuses := map[string]Status{}
	for _, s := range r.Status() {
		statuses[s.Key] = s
	}

	okStatus := statuses["ok"]
	if !okStatus.LastOK || okStatus.ConsecutiveFailures != 0 || okStatus.TotalLookups != 1 {
		t.Fatalf("unexpected ok status: %+v", okStatus)
	}
	badStatus := statuses["bad"]
	if badStatus.LastOK || badStatus.LastError != "boom" || badStatus.ConsecutiveFailures != 2 || badStatus.TotalLookups != 2 {
		t.Fatalf("unexpected bad status: %+v", badStatus)
	}
}

func TestRegistry_RecoveryResetsConsecutiveFailures(t *testing.T) {
	src := &fakeSource{key: "flaky", name: "Flaky", err: errors.New("down")}
	r := NewRegistry(src)

	r.Lookup(context.Background(), "flaky", "8.8.8.8")
	r.Lookup(context.Background(), "flaky", "8.8.8.8")

	src.err = nil
	src.result = Result{Source: "flaky", Summary: "back up"}
	if _, err := r.Lookup(context.Background(), "flaky", "8.8.8.8"); err != nil {
		t.Fatalf("Lookup after recovery: %v", err)
	}

	status := r.Status()[0]
	if !status.LastOK || status.ConsecutiveFailures != 0 {
		t.Fatalf("expected recovery to reset consecutive failures, got %+v", status)
	}
}

func TestRegistry_UnknownSourceErrors(t *testing.T) {
	r := NewRegistry()
	if _, err := r.Lookup(context.Background(), "nope", "8.8.8.8"); err == nil {
		t.Fatalf("expected an error for an unregistered source key")
	}
}

func TestRejectPrivate(t *testing.T) {
	cases := []string{"192.168.1.1", "10.0.0.1", "127.0.0.1", "169.254.1.1", "100.64.0.1", "not-an-ip", "::1", "fe80::1"}
	for _, ip := range cases {
		if _, err := rejectPrivate(ip); err == nil {
			t.Errorf("rejectPrivate(%q) = nil, want an error", ip)
		}
	}
	if _, err := rejectPrivate("8.8.8.8"); err != nil {
		t.Errorf("rejectPrivate(8.8.8.8) = %v, want nil", err)
	}
}

func TestRDAPEntity_OrgName(t *testing.T) {
	e := rdapEntity{VCardArray: []any{
		"vcard",
		[]any{
			[]any{"version", map[string]any{}, "text", "4.0"},
			[]any{"fn", map[string]any{}, "text", "Example Org LLC"},
		},
	}}
	if got := e.orgName(); got != "Example Org LLC" {
		t.Fatalf("orgName() = %q, want %q", got, "Example Org LLC")
	}

	empty := rdapEntity{}
	if got := empty.orgName(); got != "" {
		t.Fatalf("orgName() on empty entity = %q, want empty", got)
	}
}

func TestSplitPipe(t *testing.T) {
	got := splitPipe("15169 | 8.8.8.0/24 | US | arin | 1992-12-01")
	want := []string{"15169", "8.8.8.0/24", "US", "arin", "1992-12-01"}
	if len(got) != len(want) {
		t.Fatalf("splitPipe len = %d, want %d (%v)", len(got), len(want), got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("splitPipe[%d] = %q, want %q", i, got[i], want[i])
		}
	}
}
