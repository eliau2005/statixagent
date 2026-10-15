package agent

import (
	"bytes"
	"context"
	"log"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/eliau2005/statixagent/internal/config"
	"github.com/eliau2005/statixagent/internal/sshwatch"
)

// trustedAgent returns a test agent with ssh.trusted_ips set. Sources are
// private or ULA addresses so the geo lookup never leaves the machine.
func trustedAgent(send *fakeSender, entries ...string) *Agent {
	cfg := testConfig()
	cfg.SSH.TrustedIPs = config.MustTrustedIPs(entries...)
	return New(cfg, send, nil, testAgent(send).src)
}

func TestTrustedLoginSuppressed(t *testing.T) {
	cases := []struct {
		name    string
		trusted []string
		line    string
		title   string // expected alert title; "" means no alert
	}{
		{"empty list alerts", nil, "Accepted publickey for deploy from 10.0.0.7 port 22 ssh2", "SSH login"},
		{"exact IPv4", []string{"10.0.0.7"}, "Accepted publickey for deploy from 10.0.0.7 port 22 ssh2", ""},
		{"other IPv4 still alerts", []string{"10.0.0.7"}, "Accepted publickey for deploy from 10.0.0.8 port 22 ssh2", "SSH login"},
		{"IPv4 CIDR", []string{"192.168.1.0/24"}, "Accepted password for deploy from 192.168.1.200 port 22 ssh2", ""},
		{"IPv4 CIDR boundary", []string{"192.168.1.0/24"}, "Accepted password for deploy from 192.168.2.0 port 22 ssh2", "SSH login"},
		{"IPv6 CIDR", []string{"fd00:1::/32"}, "Accepted publickey for deploy from fd00:1:5::9 port 22 ssh2", ""},
		{"IPv6 outside", []string{"fd00:1::/32"}, "Accepted publickey for deploy from fd00:2::9 port 22 ssh2", "SSH login"},
		{"root from trusted still alerts", []string{"10.0.0.7"}, "Accepted publickey for root from 10.0.0.7 port 22 ssh2", "ROOT SSH login"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			send := &fakeSender{}
			a := trustedAgent(send, c.trusted...)

			a.handleAuthLine(context.Background(), c.line, time.Now())
			if c.title == "" && send.find("SSH login") {
				t.Errorf("trusted login must not alert: %v", send.all())
			}
			if c.title != "" && !send.find(c.title) {
				t.Errorf("want %q alert: %v", c.title, send.all())
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
	a := trustedAgent(send, "10.0.0.0/8")
	now := time.Now()
	// Spread the threshold's worth of failures across, but inside, the window.
	step := a.brute.Window / time.Duration(a.brute.Threshold+1)
	for i := range a.brute.Threshold {
		a.handleAuthLine(context.Background(), "Failed password for deploy from 10.1.2.3 port 33000 ssh2", now.Add(time.Duration(i)*step))
	}
	if !send.find("Brute-force attack") {
		t.Errorf("failures from a trusted range must still trigger the brute-force alert: %v", send.all())
	}
}

func TestTrustedLoginAfterFailuresAlerts(t *testing.T) {
	ctx := context.Background()
	failed := "Failed password for deploy from 10.1.2.3 port 33000 ssh2"
	login := "Accepted password for deploy from 10.1.2.3 port 33001 ssh2"

	t.Run("success right after failures alerts", func(t *testing.T) {
		send := &fakeSender{}
		a := trustedAgent(send, "10.0.0.0/8")
		now := time.Now()
		// Below the brute-force threshold, so only the login can alert.
		for i := range a.brute.Threshold - 1 {
			a.handleAuthLine(ctx, failed, now.Add(time.Duration(i)*time.Millisecond))
		}
		a.handleAuthLine(ctx, login, now.Add(time.Second))
		if send.find("Brute-force attack") {
			t.Fatalf("setup crossed the brute-force threshold: %v", send.all())
		}
		if !send.find("SSH login") {
			t.Errorf("login after recent failures from a trusted IP must alert: %v", send.all())
		}
	})

	t.Run("failures outside the window are forgotten", func(t *testing.T) {
		send := &fakeSender{}
		a := trustedAgent(send, "10.0.0.0/8")
		now := time.Now()
		a.handleAuthLine(ctx, failed, now)
		a.handleAuthLine(ctx, login, now.Add(a.brute.Window+time.Second))
		if send.find("SSH login") {
			t.Errorf("stale failure must not unsuppress a trusted login: %v", send.all())
		}
	})

	t.Run("failures from another IP do not count", func(t *testing.T) {
		send := &fakeSender{}
		a := trustedAgent(send, "10.0.0.0/8")
		now := time.Now()
		a.handleAuthLine(ctx, "Failed password for deploy from 10.9.9.9 port 33000 ssh2", now)
		a.handleAuthLine(ctx, login, now.Add(time.Second))
		if send.find("SSH login") {
			t.Errorf("another source's failure must not unsuppress this login: %v", send.all())
		}
	})
}

func TestTrustedLoginUnparseableSourceLogged(t *testing.T) {
	var buf bytes.Buffer
	log.SetOutput(&buf)
	t.Cleanup(func() { log.SetOutput(os.Stderr) })

	send := &fakeSender{}
	a := trustedAgent(send, "10.0.0.0/8")
	a.geo.BaseURL = "http://127.0.0.1:1" // a hostname is not private: keep it offline

	// sshd logs a hostname instead of an address under UseDNS.
	a.handleAuthLine(context.Background(), "Accepted publickey for deploy from host.example.com port 22 ssh2", time.Now())
	if !send.find("SSH login") {
		t.Errorf("a hostname source is never trusted and must alert: %v", send.all())
	}
	if !strings.Contains(buf.String(), `"host.example.com" is not an IP literal`) {
		t.Errorf("log = %q, want the reason the trusted list did not apply", buf.String())
	}

	buf.Reset()
	a.handleAuthLine(context.Background(), "Accepted publickey for deploy from 10.0.0.7 port 22 ssh2", time.Now())
	if buf.Len() != 0 {
		t.Errorf("unexpected log for a parseable source: %q", buf.String())
	}
}
