package agent

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/eliau2005/statixagent/internal/config"
	"github.com/eliau2005/statixagent/internal/telegram"
)

// trustAgent returns an agent with the config baseline cfgTrusted and the
// bot-managed list kept in dir ("" = in-memory). Sources are private or
// ULA so geo lookups stay offline.
func trustAgent(send *fakeSender, dir string, cfgTrusted ...string) *Agent {
	cfg := testConfig()
	cfg.SSH.TrustedIPs = config.MustTrustedIPs(cfgTrusted...)
	src := testAgent(send).src
	if dir != "" {
		src.TrustPath = filepath.Join(dir, "trusted_ips")
		src.KnownKeysPath = filepath.Join(dir, "known_keys")
	}
	return New(cfg, send, nil, src)
}

func (a *Agent) cmd(name string, args ...string) string {
	out, _ := a.router.Invoke(context.Background(), name, args)
	return out
}

func plainLogin(ip string) string {
	return "Accepted password for deploy from " + ip + " port 22 ssh2"
}

// loginAlerts counts "SSH login" pushes caused by line.
func loginAlerts(a *Agent, send *fakeSender, line string, at time.Time) int {
	before := len(send.all())
	a.handleAuthLine(context.Background(), line, at)
	n := 0
	for _, m := range send.all()[before:] {
		if strings.Contains(m, "SSH login") {
			n++
		}
	}
	return n
}

func TestTrustCommand(t *testing.T) {
	cases := []struct {
		name string
		args []string
		want string // substring of the reply
		adds bool   // whether a Telegram entry results
	}{
		{"single IPv4", []string{"10.0.0.7"}, "✅ Trusted <code>10.0.0.7</code>", true},
		{"normalised CIDR", []string{"10.1.2.3/24"}, "✅ Trusted <code>10.1.2.0/24</code>", true},
		{"IPv6 range", []string{"fd00:1::/48"}, "✅ Trusted <code>fd00:1::/48</code>", true},
		{"IPv4-mapped single", []string{"::ffff:10.0.0.7"}, "✅ Trusted <code>10.0.0.7</code>", true},
		{"exact config entry", []string{"192.168.1.0/24"}, "already trusted (config.toml)", false},
		{"covered by config", []string{"192.168.1.9"}, "covered by <code>192.168.1.0/24</code> (config.toml)", false},
		{"0.0.0.0/0 rejected", []string{"0.0.0.0/0"}, "trusts every address", false},
		{"::/0 rejected", []string{"::/0"}, "trusts every address", false},
		{"short mapped range rejected", []string{"::ffff:10.0.0.0/64"}, "ambiguous IPv4-mapped range", false},
		{"invalid", []string{"10.0.0.300"}, "invalid IP address", false},
		{"hostname", []string{"example.com"}, "invalid IP address", false},
		{"no argument", nil, "Usage: /trust", false},
		{"two arguments", []string{"10.0.0.7", "10.0.0.8"}, "Usage: /trust", false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			a := trustAgent(&fakeSender{}, "", "192.168.1.0/24")
			got := a.cmd("trust", c.args...)
			if !strings.Contains(got, c.want) {
				t.Errorf("reply = %q, want %q", got, c.want)
			}
			if n := a.trustStore.Len(); (n == 1) != c.adds {
				t.Errorf("telegram entries = %d, want added=%v", n, c.adds)
			}
		})
	}
}

func TestTrustCommandDuplicatesAndLimit(t *testing.T) {
	a := trustAgent(&fakeSender{}, "")
	a.cmd("trust", "10.0.0.0/24")
	if got := a.cmd("trust", "10.0.0.0/24"); !strings.Contains(got, "already trusted (Telegram)") {
		t.Errorf("duplicate: %q", got)
	}
	if got := a.cmd("trust", "10.0.0.9"); !strings.Contains(got, "covered by <code>10.0.0.0/24</code> (Telegram)") {
		t.Errorf("covered: %q", got)
	}
	// A broader range is accepted; the narrower entry is left alone.
	if got := a.cmd("trust", "10.0.0.0/16"); !strings.Contains(got, "✅ Trusted") {
		t.Errorf("broader range: %q", got)
	}

	for i := a.trustStore.Len(); i < maxTelegramTrusted; i++ {
		a.cmd("trust", fmt.Sprintf("172.16.%d.1", i))
	}
	if got := a.cmd("trust", "172.31.0.1"); !strings.Contains(got, "Limit of 64") {
		t.Errorf("over the cap: %q", got)
	}
	if n := a.trustStore.Len(); n != maxTelegramTrusted {
		t.Errorf("entries = %d, want the cap %d", n, maxTelegramTrusted)
	}
}

func TestUntrustCommand(t *testing.T) {
	a := trustAgent(&fakeSender{}, "", "192.168.1.0/24")
	a.cmd("trust", "10.0.0.7")
	a.cmd("trust", "10.1.2.3") // narrower first: once /16 exists it is refused as covered
	a.cmd("trust", "10.1.0.0/16")
	cases := []struct{ arg, want string }{
		{"10.0.0.7", "🗑 Removed <code>10.0.0.7</code>. Its SSH logins alert again."},
		{"10.0.0.7", "<code>10.0.0.7</code> is not trusted."},
		{"192.168.1.0/24", "comes from config.toml"},
		{"192.168.1.5", "covered by <code>192.168.1.0/24</code> (config.toml)"},
		{"10.1.9.9", "covered by <code>10.1.0.0/16</code> (Telegram)"},
		{"10.1.2.3", "still covered by <code>10.1.0.0/16</code> (Telegram)"},
		{"0.0.0.0/0", "trusts every address"},
	}
	for _, c := range cases {
		if got := a.cmd("untrust", c.arg); !strings.Contains(got, c.want) {
			t.Errorf("/untrust %s = %q, want %q", c.arg, got, c.want)
		}
	}
	if got := a.cmd("untrust"); !strings.Contains(got, "Usage: /untrust") {
		t.Errorf("no argument: %q", got)
	}
}

func TestTrustedView(t *testing.T) {
	a := trustAgent(&fakeSender{}, "", "192.168.1.0/24")
	if got := a.cmd("trusted"); !strings.Contains(got, "<code>192.168.1.0/24</code>") || !strings.Contains(got, "(0/64") || !strings.Contains(got, "(none)") {
		t.Errorf("view = %q", got)
	}
	a.cmd("trust", "fd00:1::7")
	got := a.cmd("trusted")
	cfgAt, tgAt := strings.Index(got, "192.168.1.0/24"), strings.Index(got, "fd00:1::7")
	if cfgAt < 0 || tgAt < 0 || strings.Index(got, "config.toml") > cfgAt || strings.Index(got, "Telegram") > tgAt || cfgAt > tgAt {
		t.Errorf("entries not listed under their source:\n%s", got)
	}
	for _, want := range []string{"(1/64", "Root logins", "always alert"} {
		if !strings.Contains(got, want) {
			t.Errorf("view missing %q:\n%s", want, got)
		}
	}
}

func TestTrustAppliesImmediately(t *testing.T) {
	send := &fakeSender{}
	a := trustAgent(send, "")
	now := time.Now()
	if n := loginAlerts(a, send, plainLogin("10.0.0.7"), now); n != 1 {
		t.Fatalf("untrusted login alerts = %d, want 1", n)
	}
	a.cmd("trust", "10.0.0.7")
	if n := loginAlerts(a, send, plainLogin("10.0.0.7"), now.Add(time.Minute)); n != 0 {
		t.Errorf("login right after /trust alerted %d times", n)
	}
	a.cmd("untrust", "10.0.0.7")
	if n := loginAlerts(a, send, plainLogin("10.0.0.7"), now.Add(2*time.Minute)); n != 1 {
		t.Errorf("login right after /untrust alerts = %d, want 1", n)
	}
}

func TestTrustPersistsAndMergesWithConfig(t *testing.T) {
	dir := t.TempDir()
	a := trustAgent(&fakeSender{}, dir, "192.168.1.0/24")
	a.cmd("trust", "10.0.0.7")

	raw, err := os.ReadFile(filepath.Join(dir, "trusted_ips"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(raw), "\n10.0.0.7\n") || strings.Contains(string(raw), "192.168.1.0/24") {
		t.Errorf("state file must hold only Telegram entries:\n%s", raw)
	}

	// A restart: config and state file are merged again.
	send := &fakeSender{}
	b := trustAgent(send, dir, "192.168.1.0/24")
	now := time.Now()
	for _, ip := range []string{"10.0.0.7", "192.168.1.9"} {
		if n := loginAlerts(b, send, plainLogin(ip), now); n != 0 {
			t.Errorf("login from %s after restart alerted", ip)
		}
	}
	if n := loginAlerts(b, send, plainLogin("10.0.0.8"), now); n != 1 {
		t.Error("an untrusted source must still alert after restart")
	}
	if got := b.cmd("untrust", "192.168.1.0/24"); !strings.Contains(got, "comes from config.toml") {
		t.Errorf("config entry must stay: %q", got)
	}
}

func TestTelegramTrustKeepsSafetyRules(t *testing.T) {
	dir := t.TempDir()
	send := &fakeSender{}
	a := trustAgent(send, dir) // nothing trusted at start
	if a.knownKeys.Load() != nil {
		t.Fatal("known_keys must not load while nothing is trusted")
	}
	ctx := context.Background()
	now := time.Now()
	a.handleAuthLine(ctx, keyLogin("deploy", "10.0.0.7", "SHA256:old"), now)
	if _, err := os.Stat(filepath.Join(dir, "known_keys")); !os.IsNotExist(err) {
		t.Errorf("known_keys written before anything was trusted: %v", err)
	}

	a.cmd("trust", "10.0.0.0/24")
	if a.knownKeys.Load() == nil {
		t.Fatal("known_keys must load when the merged list becomes non-empty")
	}
	cases := []struct {
		line  string
		title string
	}{
		{keyLogin("root", "10.0.0.7", "SHA256:r"), "ROOT SSH login"},
		{keyLogin("deploy", "10.0.0.7", "SHA256:new"), "SSH login with new key"},
		{keyLogin("deploy", "10.0.0.7", "SHA256:new"), ""}, // now known
	}
	for i, c := range cases {
		before := len(send.all())
		a.handleAuthLine(ctx, c.line, now.Add(time.Duration(i+1)*time.Minute))
		got := strings.Join(send.all()[before:], "\n")
		if c.title == "" && got != "" {
			t.Errorf("case %d must not alert: %s", i, got)
		}
		if c.title != "" && !strings.Contains(got, c.title) {
			t.Errorf("case %d: want %q, got %q", i, c.title, got)
		}
	}

	later := now.Add(10 * time.Minute)
	a.handleAuthLine(ctx, "Failed password for deploy from 10.0.0.9 port 22 ssh2", later)
	if n := loginAlerts(a, send, plainLogin("10.0.0.9"), later.Add(time.Second)); n != 1 {
		t.Errorf("login right after a failure from a Telegram-trusted IP alerts = %d, want 1", n)
	}

	for i := range a.brute.Threshold {
		a.handleAuthLine(ctx, "Failed password for deploy from 10.0.0.20 port 22 ssh2", later.Add(time.Duration(i)*time.Second))
	}
	if !send.find("Brute-force attack") {
		t.Error("brute force from a Telegram-trusted IP must still alert")
	}
}

// lastKeyboard returns the keyboard of the last message sent.
func (f *fakeSender) lastKeyboard() telegram.Keyboard {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.keyboards[len(f.keyboards)-1]
}

func (f *fakeSender) lastMarkup() markupEdit {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.markups[len(f.markups)-1]
}

func hasData(kb telegram.Keyboard, prefix string) bool {
	for _, row := range kb {
		for _, b := range row {
			if strings.HasPrefix(b.Data, prefix) {
				return true
			}
		}
	}
	return false
}

func labels(kb telegram.Keyboard) string {
	var out []string
	for _, row := range kb {
		for _, b := range row {
			out = append(out, b.Text)
		}
	}
	return strings.Join(out, " | ")
}

func TestTrustButtonOnlyOnPlainLogins(t *testing.T) {
	ctx := context.Background()
	now := time.Now()
	cases := []struct {
		name    string
		trusted []string
		lines   []string
		button  bool
	}{
		{"plain login", nil, []string{plainLogin("10.0.0.7")}, true},
		{"plain IPv6 login", nil, []string{plainLogin("fd00:1::7")}, true},
		{"root login", nil, []string{keyLogin("root", "10.0.0.7", "SHA256:a")}, false},
		{"new-key login", []string{"10.0.0.0/24"}, []string{keyLogin("deploy", "10.0.0.7", "SHA256:a")}, false},
		{"hostname source", nil, []string{plainLogin("host.example.com")}, false},
		{"already trusted, alerting after a failure", []string{"10.0.0.0/24"}, []string{
			"Failed password for deploy from 10.0.0.7 port 22 ssh2", plainLogin("10.0.0.7"),
		}, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			send := &fakeSender{}
			a := trustAgent(send, "", c.trusted...)
			a.geo.BaseURL = "http://127.0.0.1:1"
			for i, l := range c.lines {
				a.handleAuthLine(ctx, l, now.Add(time.Duration(i)*time.Second))
			}
			if len(send.all()) == 0 {
				t.Fatal("no alert sent")
			}
			if got := hasData(send.lastKeyboard(), cbTrust); got != c.button {
				t.Errorf("trust button = %v, want %v: %s", got, c.button, labels(send.lastKeyboard()))
			}
		})
	}

	t.Run("brute-force alert", func(t *testing.T) {
		send := &fakeSender{}
		a := trustAgent(send, "")
		for i := range a.brute.Threshold {
			a.handleAuthLine(ctx, "Failed password for deploy from 10.0.0.7 port 22 ssh2", now.Add(time.Duration(i)*time.Second))
		}
		if !send.find("Brute-force attack") || hasData(send.lastKeyboard(), cbTrust) {
			t.Errorf("brute-force alert must not offer trust: %s", labels(send.lastKeyboard()))
		}
	})
}

func TestTrustButtonConfirmFlow(t *testing.T) {
	send := &fakeSender{}
	a := trustAgent(send, t.TempDir())
	ctx := context.Background()
	now := time.Now()
	a.handleAuthLine(ctx, plainLogin("10.0.0.7"), now)
	original := send.lastKeyboard()
	msgID := send.nextID + 1000
	press := func(data string) markupEdit {
		t.Helper()
		a.handleCallback(ctx, &telegram.Callback{ID: "cb", ChatID: 42, MessageID: msgID, Data: data})
		m := send.lastMarkup()
		if m.id != msgID {
			t.Fatalf("edited message %d, want the alert %d", m.id, msgID)
		}
		return m
	}

	// Tap 1: confirm screen restating the IP; nothing trusted yet.
	m := press("tip:10.0.0.7")
	if !strings.Contains(labels(m.kb), "10.0.0.7") || !hasData(m.kb, "tipk:10.0.0.7") || !hasData(m.kb, "tipc:10.0.0.7") {
		t.Errorf("confirm screen = %s", labels(m.kb))
	}
	if a.trustStore.Len() != 0 {
		t.Fatal("the first tap must not trust anything")
	}

	// Cancel restores the original keyboard exactly, snooze included.
	if m := press("tipc:10.0.0.7"); !reflect.DeepEqual(m.kb, original) {
		t.Errorf("cancel restored %s, want %s", labels(m.kb), labels(original))
	}
	if a.trustStore.Len() != 0 {
		t.Fatal("cancel must not trust anything")
	}

	// Tap 1 again, then confirm.
	press("tip:10.0.0.7")
	// Yes restores the alert's keyboard, snooze included, minus Trust,
	// with the outcome as a label below it.
	m = press("tipk:10.0.0.7")
	if got := labels(m.kb[len(m.kb)-1:]); got != "✅ Trusted 10.0.0.7" {
		t.Errorf("result line = %q", got)
	}
	if hasData(m.kb, "tip:") || !hasData(m.kb, "snz:") || !hasData(m.kb, "~1o|ses") || !strings.Contains(labels(m.kb), "📋 Copy IP") {
		t.Errorf("restored keyboard = %s", labels(m.kb))
	}
	if n := loginAlerts(a, send, plainLogin("10.0.0.7"), now.Add(time.Minute)); n != 0 {
		t.Error("confirmed IP must be trusted immediately")
	}
	// Only keyboards were edited: the alert text (user, geo) is untouched.
	if send.editCount() != 0 {
		t.Errorf("alert text was edited %d times", send.editCount())
	}

	// A stale button on an old alert: no confirm screen.
	if m := press("tip:10.0.0.7"); !strings.Contains(labels(m.kb), "Already trusted") {
		t.Errorf("stale button = %s", labels(m.kb))
	}
	if m := press("tipk:10.0.0.7"); !strings.Contains(labels(m.kb), "Already trusted") {
		t.Errorf("repeated confirm = %s", labels(m.kb))
	}
}

func TestTrustCancelAfterRestart(t *testing.T) {
	send := &fakeSender{}
	a := trustAgent(send, "")
	a.handleCallback(context.Background(), &telegram.Callback{ID: "cb", ChatID: 42, MessageID: 999, Data: "tipc:10.0.0.7"})
	kb := send.lastMarkup().kb
	if !hasData(kb, "~1o|ses") || !hasData(kb, "tip:10.0.0.7") || hasData(kb, "snz:") {
		t.Errorf("restored keyboard without a remembered alert = %s", labels(kb))
	}
}

func TestTrustCallbackRejectsForgedData(t *testing.T) {
	for _, data := range []string{
		"tipk:10.0.0.0/8",         // ranges never come from a button
		"tipk:0.0.0.0/0",          // trust-all
		"tipk:::/0",               // trust-all IPv6
		"tipk:::ffff:10.0.0.7",    // non-canonical form of a valid address
		"tipk:::ffff:10.0.0.0/64", // ambiguous mapped range
		"tipk:010.0.0.7",          // not an address
		"tipk:host.example.com",
		"tipk:fe80::1%eth0",
		"tipk:",
		"tip:10.0.0.0/8",
		"tipc:garbage",
	} {
		t.Run(data, func(t *testing.T) {
			send := &fakeSender{}
			a := trustAgent(send, "")
			a.handleCallback(context.Background(), &telegram.Callback{ID: "cb", ChatID: 42, MessageID: 1, Data: data})
			kb := send.lastMarkup().kb
			if got := labels(kb[len(kb)-1:]); got != "⚠️ Not trusted: invalid button" || hasData(kb, "tip") {
				t.Errorf("result = %q", got)
			}
			if a.trustStore.Len() != 0 {
				t.Errorf("forged data trusted %v", a.trustStore.Entries())
			}
		})
	}

	t.Run("foreign chat", func(t *testing.T) {
		send := &fakeSender{}
		a := trustAgent(send, "")
		a.handleCallback(context.Background(), &telegram.Callback{ID: "cb", ChatID: 7, MessageID: 1, Data: "tipk:10.0.0.7"})
		if a.trustStore.Len() != 0 || len(send.markups) != 0 {
			t.Error("a press from another chat must be ignored")
		}
	})
}

// TestTrustConcurrentWithLogins runs logins (auth loop) against /trust,
// /untrust and /trusted (bot loop); run with -race.
func TestTrustConcurrentWithLogins(t *testing.T) {
	send := &fakeSender{}
	a := trustAgent(send, t.TempDir(), "192.168.1.0/24")
	ctx := context.Background()
	now := time.Now()
	var wg sync.WaitGroup
	wg.Go(func() {
		for i := range 300 {
			a.handleAuthLine(ctx, plainLogin(fmt.Sprintf("10.0.0.%d", i%8)), now.Add(time.Duration(i)*time.Second))
			a.handleAuthLine(ctx, keyLogin("deploy", "10.0.0.1", fmt.Sprintf("SHA256:k%d", i%5)), now.Add(time.Duration(i)*time.Second))
		}
	})
	wg.Go(func() {
		for i := range 100 {
			ip := fmt.Sprintf("10.0.0.%d", 4+i%4) // never 10.0.0.3, the button's
			a.cmd("trust", ip)
			a.cmd("trusted")
			a.cmd("untrust", ip)
		}
	})
	wg.Go(func() {
		for i := range 100 {
			a.handleCallback(ctx, &telegram.Callback{ID: "cb", ChatID: 42, MessageID: int64(i), Data: "tipk:10.0.0.3"})
		}
	})
	wg.Wait()
	if got := a.cmd("trusted"); !strings.Contains(got, "10.0.0.3") {
		t.Errorf("button-trusted entry missing after the race:\n%s", got)
	}
}
