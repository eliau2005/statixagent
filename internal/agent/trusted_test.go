package agent

import (
	"context"
	"testing"
	"time"

	"github.com/eliau2005/statixagent/internal/sshwatch"
)

func TestTrustedLoginSuppressed(t *testing.T) {
	cases := []struct {
		name    string
		trusted []string
		line    string
		alert   bool
	}{
		// Private and ULA sources keep the geo lookup off the network.
		{"empty list alerts", nil, "Accepted publickey for deploy from 10.0.0.7 port 22 ssh2", true},
		{"exact IPv4", []string{"10.0.0.7"}, "Accepted publickey for deploy from 10.0.0.7 port 22 ssh2", false},
		{"other IPv4 still alerts", []string{"10.0.0.7"}, "Accepted publickey for deploy from 10.0.0.8 port 22 ssh2", true},
		{"IPv4 CIDR", []string{"192.168.1.0/24"}, "Accepted password for deploy from 192.168.1.200 port 22 ssh2", false},
		{"IPv4 CIDR boundary", []string{"192.168.1.0/24"}, "Accepted password for deploy from 192.168.2.0 port 22 ssh2", true},
		{"IPv6 CIDR", []string{"fd00:1::/32"}, "Accepted publickey for deploy from fd00:1:5::9 port 22 ssh2", false},
		{"IPv6 outside", []string{"fd00:1::/32"}, "Accepted publickey for deploy from fd00:2::9 port 22 ssh2", true},
		{"root from trusted", []string{"10.0.0.7"}, "Accepted publickey for root from 10.0.0.7 port 22 ssh2", false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			send := &fakeSender{}
			cfg := testConfig()
			cfg.SSH.TrustedIPs = c.trusted
			a := New(cfg, send, nil, testAgent(send).src)

			a.handleAuthLine(context.Background(), c.line, time.Now())
			if got := send.find("SSH login"); got != c.alert {
				t.Errorf("alert sent = %v, want %v: %v", got, c.alert, send.all())
			}
			// Suppression only skips the push: the login stays visible.
			logins := a.hist.Recent(10, func(e sshwatch.Event) bool { return e.Kind == sshwatch.EventLogin })
			if len(logins) != 1 {
				t.Errorf("history logins = %d, want 1", len(logins))
			}
			if a.digest.logins != 1 {
				t.Errorf("digest logins = %d, want 1", a.digest.logins)
			}
		})
	}
}

func TestTrustedIPStillTriggersBruteForce(t *testing.T) {
	send := &fakeSender{}
	cfg := testConfig()
	cfg.SSH.TrustedIPs = []string{"10.0.0.0/8"}
	a := New(cfg, send, nil, testAgent(send).src)
	now := time.Now()
	for i := range 5 {
		a.handleAuthLine(context.Background(), "Failed password for deploy from 10.1.2.3 port 33000 ssh2", now.Add(time.Duration(i)*time.Second))
	}
	if !send.find("Brute-force attack") {
		t.Errorf("failures from a trusted range must still trigger the brute-force alert: %v", send.all())
	}
}
