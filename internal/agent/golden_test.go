package agent

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/eliau2005/statixagent/internal/config"
	"github.com/eliau2005/statixagent/internal/sshwatch"
	"github.com/eliau2005/statixagent/internal/telegram"
	"github.com/eliau2005/statixagent/internal/tgui"
)

// Characterization goldens: today's keyboards and texts, pinned before
// the callback layer is refactored onto tgui. A diff here means a screen
// changed; when that is intended, rewrite them with
//
//	go test ./internal/agent -run Golden -update

var update = flag.Bool("update", false, "rewrite testdata/*.golden from the current output")

// dumpKeyboard renders a keyboard one row per line as "[label] → data",
// a copy button as "[label] ⧉ text", and a style as "(style)".
func dumpKeyboard(kb telegram.Keyboard) string {
	var b strings.Builder
	for _, row := range kb {
		for i, btn := range row {
			if i > 0 {
				b.WriteString("  ")
			}
			if btn.Copy != "" {
				fmt.Fprintf(&b, "[%s] ⧉ %s", btn.Text, btn.Copy)
			} else {
				fmt.Fprintf(&b, "[%s] → %s", btn.Text, btn.Data)
			}
			if btn.Style != "" {
				fmt.Fprintf(&b, " (%s)", btn.Style)
			}
		}
		b.WriteString("\n")
	}
	return b.String()
}

// checkGolden compares a screen's text and keyboard to testdata/<name>.golden.
func checkGolden(t *testing.T, name, text string, kb telegram.Keyboard) {
	t.Helper()
	got := text + "\n--- keyboard ---\n" + dumpKeyboard(kb)
	path := filepath.Join("testdata", name+".golden")
	if *update {
		if err := os.MkdirAll("testdata", 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(got), 0o644); err != nil {
			t.Fatal(err)
		}
		return
	}
	want, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("%v (run with -update to create it)", err)
	}
	if got != string(want) {
		t.Errorf("%s changed:\n--- got ---\n%s\n--- want ---\n%s", path, got, want)
	}
}

// runFunc adapts a function to services.Runner.
type runFunc func(name string, args ...string) (string, error)

func (f runFunc) Run(_ context.Context, name string, args ...string) (string, error) {
	return f(name, args...)
}

// ufwOnly answers every ufw call with out and err; any other binary (the
// sshd, systemctl and ss port probes) is not installed, so the SSH port
// falls back to 22.
func ufwOnly(out string, err error) runFunc {
	return func(name string, _ ...string) (string, error) {
		if strings.HasSuffix(name, "ufw") {
			return out, err
		}
		return "", &exec.Error{Name: name, Err: exec.ErrNotFound}
	}
}

func TestGoldenAlertKeyboards(t *testing.T) {
	a := testAgent(&fakeSender{})
	keys := []string{
		"ssh-login:alice@203.0.113.9", "ssh-newkey:alice", "ssh-brute:198.51.100.7", "keys:/root/.ssh/authorized_keys",
		"cpu", "mem", "disk:/", "temp", "ssl:example.com", "docker:web", "docker-up:web", "docker-restart:web",
		"battery", "power-loss", "power-restored", "reboot",
		"svc:nginx.service", "port:5432", "http:" + callbackDigest("https://api.example/hz"), "proc:redis-server",
		// Over 64 bytes as snz:d:<key>: the snooze button falls back to a digest.
		"disk:/var/lib/docker/overlay2/0123456789abcdef0123456789abcdef/merged",
	}
	for _, key := range keys {
		name := strings.NewReplacer(":", "_", "/", "_", "@", "_", ".", "_").Replace(key)
		checkGolden(t, "alert__"+name, key, a.alertKeyboard(key))
	}
	// Snoozed: the row becomes its Undo.
	a.now = func() time.Time { return time.Date(2026, 10, 15, 14, 5, 0, 0, time.Local) }
	a.engine.Snooze("cpu", a.now().Add(8*time.Hour))
	checkGolden(t, "alert__cpu_snoozed", "cpu", a.alertKeyboard("cpu"))
	// A watched unit, with service actions on: Restart asks from the alert.
	a.cfg.Watch.Services = []string{"nginx"}
	a.cfg.Actions.Enabled = true
	checkGolden(t, "alert__svc_nginx_service_actions", "svc:nginx.service", a.alertKeyboard("svc:nginx.service"))
}

func TestGoldenSettings(t *testing.T) {
	a := testAgent(&fakeSender{})
	text, kb := a.settingsView()
	checkGolden(t, "settings__default", text, kb)

	a.cfg.Digest.Enabled, a.cfg.Digest.Hour = false, 7
	a.cfg.Thresholds.TempCelsius = 105
	text, kb = a.settingsView()
	checkGolden(t, "settings__digest_off", text, kb)
}

func TestGoldenFirewall(t *testing.T) {
	const (
		open      = "Status: active\n\nTo                         Action      From\n--                         ------      ----\n22/tcp                     ALLOW       Anywhere\n"
		closed    = "Status: active\n\nTo                         Action      From\n--                         ------      ----\n22/tcp                     DENY        Anywhere\n"
		unmanaged = "Status: active\n\nTo                         Action      From\n--                         ------      ----\n80/tcp                     ALLOW       Anywhere\n"
	)
	cases := []struct {
		name   string
		runner runFunc // nil: no runner in this build
	}{
		{"unavailable", nil},
		{"missing", ufwOnly("", &exec.Error{Name: "ufw", Err: exec.ErrNotFound})},
		{"unusable", ufwOnly("ERROR: You need to be root to run this script", errors.New("exit status 1"))},
		{"inactive", ufwOnly("Status: inactive", nil)},
		{"unparsed", ufwOnly("<not ufw & friends>", nil)},
		{"open", ufwOnly(open, nil)},
		{"closed", ufwOnly(closed, nil)},
		{"unmanaged", ufwOnly(unmanaged, nil)},
		{"openssh_verbose", ufwOnly(ufwVerboseOpenSSH, nil)},
	}
	for _, tc := range cases {
		a := testAgent(&fakeSender{})
		if tc.runner != nil {
			a.src.Runner = tc.runner
		}
		text, kb := a.firewallView(context.Background())
		checkGolden(t, "firewall__"+tc.name, text, kb)
	}
	for _, data := range []string{"fw_close_ask", "fw_open_ask"} {
		send := &fakeSender{}
		a := testAgent(send)
		a.cfg.Firewall.AllowCloseSSH = true
		// Fixed randomness: the screen's tokens are part of the golden.
		a.tokens = tgui.NewTokens(a.now, strings.NewReader(strings.Repeat("statix-golden-", 8)))
		a.handleCallback(context.Background(), &telegram.Callback{ID: "c1", ChatID: 42, MessageID: 5, Data: data})
		checkGolden(t, "firewall__"+data, send.lastEdit().html, send.lastEdit().kb)
		if data == "fw_close_ask" {
			// Closing SSH is confirmed twice, the second time in other words.
			yes := tokenData(send.lastEdit().kb, tgui.ActYes)
			a.handleCallback(context.Background(), &telegram.Callback{ID: "c2", ChatID: 42, MessageID: 5, Data: yes})
			checkGolden(t, "firewall__fw_close_final", send.lastEdit().html, send.lastEdit().kb)
		}
	}
}

func TestGoldenWatching(t *testing.T) {
	a := testAgent(&fakeSender{})
	text, kb := a.watchingView()
	checkGolden(t, "watching__empty", text, kb)

	a.cfg.Watch = config.Watch{
		Services:  []string{"nginx.service", "a-very-long-unit-name-for-truncation@instance.service"},
		Processes: []string{"postgres"},
		Ports:     []config.PortCheck{{Port: 443, Label: "<https>"}, {Port: 8080}},
		SSLHosts:  []string{"example.com:8443"},
		HTTPChecks: []config.HTTPCheck{
			{URL: "https://example.com/health?check=1&verbose=true", ExpectStatus: 200},
		},
	}
	text, kb = a.watchingView()
	checkGolden(t, "watching__populated", text, kb)

	// Paged, opened from Services: page 2 of 3, Back to Services.
	for i := range 10 {
		a.cfg.Watch.Ports = append(a.cfg.Watch.Ports, config.PortCheck{Port: 9000 + i})
	}
	text, kb = a.screen(context.Background(), tgui.Call{Act: tgui.ActView, Args: []string{scrWatching, "2"}, From: scrServices})
	checkGolden(t, "watching__page_2", text, kb)
}

func TestGoldenScans(t *testing.T) {
	ctx := context.Background()
	a := testAgent(&fakeSender{})
	a.src.Runner = scanRunner{listOutput: "" +
		"nginx.service loaded active running A high performance web server\n" +
		"cron.service loaded active running Regular background program processing daemon & more\n" +
		"statix-agent.service loaded active running StatixAgent\n" +
		"ssh.service loaded active running OpenBSD Secure Shell server\n"}
	a.cfg.Watch.Services = []string{"ssh.service"}
	text, kb := a.servicesScanView(ctx)
	checkGolden(t, "scan__services", text, kb)

	a.cfg.Watch.Services = []string{"ssh.service", "nginx.service", "cron.service"}
	text, kb = a.servicesScanView(ctx)
	checkGolden(t, "scan__services_all_watched", text, kb)

	a.src.Runner = nil
	text, kb = a.servicesScanView(ctx)
	checkGolden(t, "scan__services_unavailable", text, kb)

	ports := []int{22, 80, 443}
	for p := 3000; p < 3012; p++ {
		ports = append(ports, p)
	}
	a.src.ListListeners = func() ([]int, error) { return ports, nil }
	a.cfg.Watch.Ports = []config.PortCheck{{Port: 22}}
	text, kb = a.portsScanView()
	checkGolden(t, "scan__ports", text, kb)

	a.src.ListListeners = func() ([]int, error) { return []int{22}, nil }
	text, kb = a.portsScanView()
	checkGolden(t, "scan__ports_all_watched", text, kb)
}

func TestGoldenSSHSessions(t *testing.T) {
	ctx := context.Background()
	epoch := time.Date(2026, 3, 1, 12, 0, 0, 0, time.UTC)
	a := testAgent(&fakeSender{})
	a.now = func() time.Time { return epoch }

	text, kb := a.sshSessionsView(ctx)
	checkGolden(t, "ssh__unavailable", text, kb)

	sessions := []sshwatch.Session{
		{User: "alice", TTY: "pts/0", Host: "10.0.0.5", Since: epoch.Add(-3 * time.Hour)},
		{User: "bob", TTY: "pts/1", Host: "192.168.1.20", Since: epoch.Add(-90 * time.Second)},
		{User: "carol-with-a-long-name", TTY: "pts/12", Host: "10.0.0.7", Since: epoch.Add(-26 * time.Hour)},
		{User: "mallory", TTY: "-rf", Host: "10.0.0.8", Since: epoch.Add(-time.Minute)},
	}
	a.src.Sessions = func() ([]sshwatch.Session, error) { return sessions, nil }
	text, kb = a.sshSessionsView(ctx)
	checkGolden(t, "ssh__no_runner", text, kb)

	a.src.Runner = runFunc(func(string, ...string) (string, error) { return "", nil })
	text, kb = a.sshSessionsView(ctx)
	checkGolden(t, "ssh__sessions", text, kb)

	a.src.Sessions = func() ([]sshwatch.Session, error) { return nil, nil }
	text, kb = a.sshSessionsView(ctx)
	checkGolden(t, "ssh__none", text, kb)

	a.src.Sessions = func() ([]sshwatch.Session, error) { return nil, errors.New("utmp: <denied>") }
	text, kb = a.sshSessionsView(ctx)
	checkGolden(t, "ssh__error", text, kb)
}

func TestGoldenTrustKeyboards(t *testing.T) {
	ctx := context.Background()
	send := &fakeSender{}
	a := testAgent(send)

	for _, ip := range []string{"203.0.113.9", "2001:db8::1", "host.example.com"} {
		name := strings.NewReplacer(":", "_", ".", "_").Replace(ip)
		checkGolden(t, "trust__login_"+name, ip, a.loginKeyboard("ssh-login:alice@"+ip, ip))
	}

	// Each press edits only the keyboard; the golden pins the markup it sets.
	tap := func(name string, msgID int64, data string) {
		t.Helper()
		before := len(send.markups)
		a.handleTrustCallback(ctx, &telegram.Callback{ID: "c", ChatID: 42, MessageID: msgID, Data: data})
		if len(send.markups) != before+1 {
			t.Fatalf("%s: %d markup edits, want 1", data, len(send.markups)-before)
		}
		checkGolden(t, "trust__"+name, data, send.markups[len(send.markups)-1].kb)
	}
	a.rememberTrustAlert(7, "ssh-login:alice@203.0.113.9")
	tap("ask", 7, cbTrust+"203.0.113.9")
	tap("invalid", 7, cbTrust+"203.0.113.009")
	tap("cancel_known", 7, cbTrustCancel+"203.0.113.9")
	tap("cancel_after_restart", 8, cbTrustCancel+"203.0.113.9")
	tap("confirm", 7, cbTrustConfirm+"203.0.113.9")
	tap("ask_already_trusted", 7, cbTrust+"203.0.113.9")

	checkGolden(t, "trust__login_trusted", "203.0.113.9", a.loginKeyboard("ssh-login:alice@203.0.113.9", "203.0.113.9"))
}
