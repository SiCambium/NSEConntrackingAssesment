package poller

import (
	"testing"

	"conntrackd/internal/config"
)

func TestConnectionChanged(t *testing.T) {
	base := config.Firewall{ID: "a", Host: "10.0.0.1", Port: 22, User: "admin", Password: "x", PollIntervalSeconds: 30}

	cases := []struct {
		name string
		next config.Firewall
		want bool
	}{
		{"identical", base, false},
		{"host changed", withHost(base, "10.0.0.2"), true},
		{"port changed", withPort(base, 2222), true},
		{"user changed", withUser(base, "root"), true},
		{"password changed", withPassword(base, "y"), true},
		{"poll interval changed", withInterval(base, 10), true},
		{"name changed only", withName(base, "renamed"), false}, // display-only field, not a reconnect reason
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := connectionChanged(base, c.next); got != c.want {
				t.Errorf("connectionChanged(base, %+v) = %v, want %v", c.next, got, c.want)
			}
		})
	}
}

func withHost(f config.Firewall, v string) config.Firewall     { f.Host = v; return f }
func withPort(f config.Firewall, v int) config.Firewall        { f.Port = v; return f }
func withUser(f config.Firewall, v string) config.Firewall     { f.User = v; return f }
func withPassword(f config.Firewall, v string) config.Firewall { f.Password = v; return f }
func withInterval(f config.Firewall, v int) config.Firewall    { f.PollIntervalSeconds = v; return f }
func withName(f config.Firewall, v string) config.Firewall     { f.Name = v; return f }
