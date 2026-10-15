package agent

import (
	"bytes"
	"context"
	"errors"
	"log"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/eliau2005/statixagent/internal/config"
	"github.com/eliau2005/statixagent/internal/sshwatch"
	"github.com/eliau2005/statixagent/internal/telegram"
)

// trustedAgent returns a test agent with ssh.trusted_ips set. Sources are
// private or ULA addresses so the geo lookup never leaves the machine.
func trustedAgent(send *fakeSender, entries ...string) *Agent {
	return trustedAgentWithKeys(send, "", entries...)
}

// trustedAgentWithKeys is trustedAgent with a known-keys store at path
// ("" = in-memory only).
func trustedAgentWithKeys(send *fakeSender, path string, entries ...string) *Agent {
	cfg := testConfig()
	cfg.SSH.TrustedIPs = config.MustTrustedIPs(entries...)
	src := testAgent(send).src
	src.KnownKeysPath = path
	return New(cfg, send, nil, src)
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

func keyLogin(user, ip, fp string) string {
	return "Accepted publickey for " + user + " from " + ip + " port 22 ssh2: ED25519 " + fp
}

func TestTrustedLoginNewKey(t *testing.T) {
	type login struct {
		line  string
		title string // expected alert title; "" means no alert
	}
	const trustedIP, otherIP = "10.0.0.7", "10.9.9.9"
	cases := []struct {
		name   string
		known  string // known_keys file content before start
		logins []login
	}{
		{"known key suppressed", "deploy SHA256:aaa\n", []login{
			{keyLogin("deploy", trustedIP, "SHA256:aaa"), ""},
		}},
		{"new key alerts once, then suppressed", "", []login{
			{keyLogin("deploy", trustedIP, "SHA256:aaa"), "SSH login with new key"},
			{keyLogin("deploy", trustedIP, "SHA256:aaa"), ""},
		}},
		{"another new key for the same user alerts", "deploy SHA256:aaa\n", []login{
			{keyLogin("deploy", trustedIP, "SHA256:bbb"), "SSH login with new key"},
		}},
		{"same key, different user alerts", "deploy SHA256:aaa\n", []login{
			{keyLogin("alice", trustedIP, "SHA256:aaa"), "SSH login with new key"},
			{keyLogin("alice", trustedIP, "SHA256:aaa"), ""},
		}},
		{"key first seen from an untrusted IP is known later", "", []login{
			{keyLogin("deploy", otherIP, "SHA256:aaa"), "SSH login"},
			{keyLogin("deploy", trustedIP, "SHA256:aaa"), ""},
		}},
		{"password login suppressed", "", []login{
			{"Accepted password for deploy from " + trustedIP + " port 22 ssh2", ""},
		}},
		{"keyboard-interactive login suppressed", "", []login{
			{"Accepted keyboard-interactive/pam for deploy from " + trustedIP + " port 22 ssh2", ""},
		}},
		{"root with known key still alerts", "root SHA256:aaa\n", []login{
			{keyLogin("root", trustedIP, "SHA256:aaa"), "ROOT SSH login"},
		}},
		{"root with new key alerts as root", "", []login{
			{keyLogin("root", trustedIP, "SHA256:aaa"), "ROOT SSH login"},
		}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "known_keys")
			if c.known != "" {
				if err := os.WriteFile(path, []byte(c.known), 0o600); err != nil {
					t.Fatal(err)
				}
			}
			now := time.Now()
			for i, l := range c.logins {
				send := &fakeSender{}
				// A fresh agent per login also proves the store, not the
				// alert cooldown, is what keeps a repeat quiet.
				a := trustedAgentWithKeys(send, path, "10.0.0.0/24")
				a.handleAuthLine(context.Background(), l.line, now.Add(time.Duration(i)*time.Minute))
				if l.title == "" && len(send.all()) != 0 {
					t.Errorf("login %d must not alert: %v", i, send.all())
				}
				if l.title != "" && !send.find(l.title) {
					t.Errorf("login %d: want %q alert: %v", i, l.title, send.all())
				}
				if l.title == "SSH login" && send.find("new key") {
					t.Errorf("login %d from an untrusted IP is a plain login alert: %v", i, send.all())
				}
			}
		})
	}
}

func TestTrustedNewKeyAlertWording(t *testing.T) {
	send := &fakeSender{}
	a := trustedAgent(send, "10.0.0.0/24")
	a.handleAuthLine(context.Background(), keyLogin("deploy", "10.0.0.7", "SHA256:aaa"), time.Now())
	for _, want := range []string{"SSH login with new key", "deploy from 10.0.0.7 via publickey", "local network", "source IP is trusted", "SHA256:aaa"} {
		if !send.find(want) {
			t.Errorf("alert missing %q: %v", want, send.all())
		}
	}
}

func TestTrustedNewKeyStillSubjectToFailureRule(t *testing.T) {
	path := filepath.Join(t.TempDir(), "known_keys")
	if err := os.WriteFile(path, []byte("deploy SHA256:aaa\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	send := &fakeSender{}
	a := trustedAgentWithKeys(send, path, "10.0.0.0/24")
	now := time.Now()
	a.handleAuthLine(context.Background(), "Failed publickey for deploy from 10.0.0.7 port 22 ssh2", now)
	a.handleAuthLine(context.Background(), keyLogin("deploy", "10.0.0.7", "SHA256:aaa"), now.Add(time.Second))
	if !send.find("SSH login") || send.find("new key") {
		t.Errorf("known key after a recent failure must raise the plain login alert: %v", send.all())
	}
}

// failingSender fails every push while fail is set.
type failingSender struct {
	*fakeSender
	fail bool
}

func (f *failingSender) SendMessageKB(ctx context.Context, chatID int64, html string, kb telegram.Keyboard) (int64, error) {
	if f.fail {
		return 0, errors.New("telegram down")
	}
	return f.fakeSender.SendMessageKB(ctx, chatID, html, kb)
}

func TestTrustedNewKeysWithinCooldownBothAlert(t *testing.T) {
	send := &fakeSender{}
	a := trustedAgent(send, "10.0.0.0/24")
	now := time.Now()
	a.handleAuthLine(context.Background(), keyLogin("deploy", "10.0.0.7", "SHA256:aaa"), now)
	a.handleAuthLine(context.Background(), keyLogin("deploy", "10.0.0.7", "SHA256:bbb"), now.Add(time.Second))
	for _, fp := range []string{"SHA256:aaa", "SHA256:bbb"} {
		if !send.find(fp) {
			t.Errorf("new key %s inside the login cooldown must still alert: %v", fp, send.all())
		}
	}
}

func TestTrustedNewKeyLearnedOnlyAfterDelivery(t *testing.T) {
	send := &failingSender{fakeSender: &fakeSender{}, fail: true}
	cfg := testConfig()
	cfg.SSH.TrustedIPs = config.MustTrustedIPs("10.0.0.0/24")
	a := New(cfg, send, nil, testAgent(send.fakeSender).src)
	now := time.Now()

	a.handleAuthLine(context.Background(), keyLogin("deploy", "10.0.0.7", "SHA256:aaa"), now)
	if a.knownKeys.Load().Known("deploy", "SHA256:aaa") {
		t.Fatal("key must not be learned while its alert could not be sent")
	}

	send.fail = false
	a.handleAuthLine(context.Background(), keyLogin("deploy", "10.0.0.7", "SHA256:aaa"), now.Add(time.Minute))
	if !send.find("SSH login with new key") {
		t.Errorf("undelivered new-key alert must be retried on the next login: %v", send.all())
	}
	if !a.knownKeys.Load().Known("deploy", "SHA256:aaa") {
		t.Error("key must be learned once its alert was delivered")
	}
}

func TestNoKnownKeysWithoutTrustedIPs(t *testing.T) {
	path := filepath.Join(t.TempDir(), "known_keys")
	send := &fakeSender{}
	a := trustedAgentWithKeys(send, path) // no trusted_ips
	a.handleAuthLine(context.Background(), keyLogin("deploy", "10.0.0.7", "SHA256:aaa"), time.Now())
	if !send.find("SSH login") || send.find("new key") {
		t.Errorf("without trusted_ips every login is a plain alert: %v", send.all())
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Errorf("known_keys must not be written without trusted_ips: %v", err)
	}
}

func TestUnmatchableSourceLoggedOncePerSource(t *testing.T) {
	var buf bytes.Buffer
	log.SetOutput(&buf)
	t.Cleanup(func() { log.SetOutput(os.Stderr) })

	send := &fakeSender{}
	a := trustedAgent(send, "10.0.0.0/8")
	a.geo.BaseURL = "http://127.0.0.1:1"
	now := time.Now()
	for i, host := range []string{"a.example.com", "a.example.com", "b.example.com", "a.example.com"} {
		a.handleAuthLine(context.Background(), "Accepted password for deploy from "+host+" port 22 ssh2", now.Add(time.Duration(i)*time.Minute))
	}
	if n := strings.Count(buf.String(), "not an IP literal"); n != 2 {
		t.Errorf("logged %d times, want once per distinct source:\n%s", n, buf.String())
	}
	if n := len(send.all()); n != 4 {
		t.Errorf("alerts = %d, want every login to alert", n)
	}
}
