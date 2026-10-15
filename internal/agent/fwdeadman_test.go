package agent

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/eliau2005/statixagent/internal/telegram"
	"github.com/eliau2005/statixagent/internal/tgui"
)

// fakeUFW is ufw over real rule files in a temp dir: every command reads
// and writes user.rules and user6.rules (one rule spec per line), so the
// agent's snapshot, hash and byte restore act on the same bytes the fake
// reports. It also answers systemd-run, systemctl, ss and sshd.
type fakeUFW struct {
	dir string

	mu           sync.Mutex
	calls        [][]string // name + args
	ss           string     // `ss -Htn state established`
	noSystemdRun bool
	failOn       string // a ufw command starting with this fails
}

func newFakeUFW(t *testing.T, rules ...string) *fakeUFW {
	t.Helper()
	f := &fakeUFW{dir: t.TempDir()}
	var v4, v6 []string
	for _, r := range rules {
		fam := ruleFamily(r)
		if fam != "v6" {
			v4 = append(v4, r)
		}
		if fam != "v4" {
			v6 = append(v6, r)
		}
	}
	f.write("user.rules", v4)
	f.write("user6.rules", v6)
	return f
}

// ruleFamily is v4, v6 or both, from a "from <cidr>" source.
func ruleFamily(spec string) string {
	w := strings.Fields(spec)
	if i := slices.Index(w, "from"); i >= 0 && i+1 < len(w) && w[i+1] != "any" {
		if strings.Contains(w[i+1], ":") {
			return "v6"
		}
		return "v4"
	}
	return "both"
}

func (f *fakeUFW) read(name string) []string {
	data, err := os.ReadFile(filepath.Join(f.dir, name))
	if err != nil || len(data) == 0 {
		return nil
	}
	return strings.Split(strings.TrimSuffix(string(data), "\n"), "\n")
}

func (f *fakeUFW) write(name string, rules []string) {
	data := ""
	if len(rules) > 0 {
		data = strings.Join(rules, "\n") + "\n"
	}
	if err := os.WriteFile(filepath.Join(f.dir, name), []byte(data), 0o600); err != nil {
		panic(err)
	}
}

// files is the rule files' bytes, to compare states exactly.
func (f *fakeUFW) files() string {
	a, _ := os.ReadFile(filepath.Join(f.dir, "user.rules"))
	b, _ := os.ReadFile(filepath.Join(f.dir, "user6.rules"))
	return string(a) + "|" + string(b)
}

// foreign is another writer (fail2ban, a human) changing the rules.
func (f *fakeUFW) foreign(spec string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.write("user.rules", append([]string{spec}, f.read("user.rules")...))
}

func (f *fakeUFW) setSS(out string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.ss = out
}

func (f *fakeUFW) callsOf(name string) [][]string {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out [][]string
	for _, c := range f.calls {
		if c[0] == name {
			out = append(out, c)
		}
	}
	return out
}

// ruleCalls are the ufw invocations that change rules.
func (f *fakeUFW) ruleCalls() []string {
	var out []string
	for _, c := range f.callsOf("ufw") {
		switch c[1] {
		case "status", "show", "version":
			continue
		}
		out = append(out, strings.Join(c[1:], " "))
	}
	return out
}

func (f *fakeUFW) Run(_ context.Context, name string, args ...string) (string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = append(f.calls, append([]string{name}, args...))
	switch name {
	case "ufw":
	case "systemd-run":
		if f.noSystemdRun {
			return "", &exec.Error{Name: name, Err: exec.ErrNotFound}
		}
		return "Running timer as unit: " + strings.TrimPrefix(args[0], "--unit=") + ".timer", nil
	case "systemctl":
		return "", nil
	case "ss":
		if slices.Contains(args, "established") {
			return f.ss, nil
		}
		return "", nil
	default:
		return "", &exec.Error{Name: name, Err: exec.ErrNotFound}
	}
	joined := strings.Join(args, " ")
	if f.failOn != "" && strings.HasPrefix(joined, f.failOn) {
		return "ERROR: Could not open /etc/ufw/user.rules: read-only file system", errors.New("exit status 1")
	}
	v4, v6 := f.read("user.rules"), f.read("user6.rules")
	switch {
	case args[0] == "status":
		return f.status(v4, v6), nil
	case joined == "show added":
		out := "Added user rules (see 'ufw status' for running firewall):\n"
		for _, r := range v4 {
			out += "ufw " + r + "\n"
		}
		for _, r := range v6 {
			if !slices.Contains(v4, r) {
				out += "ufw " + r + "\n"
			}
		}
		return out, nil
	case args[0] == "reload":
		return "Firewall reloaded", nil
	case args[0] == "version":
		return "ufw 0.36.2", nil
	case args[0] == "insert":
		spec := strings.Join(args[2:], " ")
		if len(v4) == 0 {
			return "ERROR: Invalid position '1'", errors.New("exit status 1")
		}
		if slices.Contains(v4, spec) {
			return "Skipping inserting existing rule", nil
		}
		fam := ruleFamily(spec)
		if fam != "v6" {
			f.write("user.rules", append([]string{spec}, v4...))
		}
		if fam != "v4" {
			f.write("user6.rules", append([]string{spec}, v6...))
		}
		return "Rule inserted", nil
	case args[0] == "--force" && args[1] == "delete":
		spec := strings.Join(args[2:], " ")
		if !slices.Contains(v4, spec) && !slices.Contains(v6, spec) {
			return "Could not delete non-existent rule", nil
		}
		f.write("user.rules", slices.DeleteFunc(v4, func(r string) bool { return r == spec }))
		f.write("user6.rules", slices.DeleteFunc(v6, func(r string) bool { return r == spec }))
		return "Rule deleted", nil
	default: // add
		spec := joined
		fam := ruleFamily(spec)
		if fam != "v6" && !slices.Contains(v4, spec) {
			f.write("user.rules", append(v4, spec))
		}
		if fam != "v4" && !slices.Contains(v6, spec) {
			f.write("user6.rules", append(v6, spec))
		}
		return "Rule added", nil
	}
}

// status renders the rules as `ufw status verbose` does.
func (f *fakeUFW) status(v4, v6 []string) string {
	var b strings.Builder
	b.WriteString("Status: active\nLogging: on (low)\n" +
		"Default: deny (incoming), allow (outgoing), disabled (routed)\nNew profiles: skip\n\n" +
		"To                         Action      From\n--                         ------      ----\n")
	row := func(spec string, v6 bool) {
		w := strings.Fields(spec)
		to, from := "Anywhere", "Anywhere"
		switch {
		case len(w) == 2 && w[1] == "OpenSSH":
			to = "22/tcp (OpenSSH)"
			if v6 {
				to = "22/tcp (OpenSSH (v6))"
			}
		case len(w) == 2:
			to = w[1]
			if v6 {
				to += " (v6)"
			}
		case len(w) == 3 && w[1] == "from":
			from = w[2]
			if v6 {
				to = "Anywhere (v6)"
			}
		}
		if v6 && from == "Anywhere" {
			from = "Anywhere (v6)"
		}
		fmt.Fprintf(&b, "%-26s %-11s %s\n", to, strings.ToUpper(w[0])+" IN", from)
	}
	for _, r := range v4 {
		row(r, false)
	}
	for _, r := range v6 {
		row(r, true)
	}
	return b.String()
}

// fakeClock drives a.now and a.fwAfter: timers fire only in Advance.
type fakeClock struct {
	mu     sync.Mutex
	now    time.Time
	timers []*fakeTimer
}

type fakeTimer struct {
	at             time.Time
	f              func()
	stopped, fired bool
}

func newFakeClock() *fakeClock {
	return &fakeClock{now: time.Date(2026, 10, 15, 12, 0, 0, 0, time.UTC)}
}

func (c *fakeClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

func (c *fakeClock) After(d time.Duration, f func()) func() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	t := &fakeTimer{at: c.now.Add(d), f: f}
	c.timers = append(c.timers, t)
	return func() bool {
		c.mu.Lock()
		defer c.mu.Unlock()
		was := !t.stopped && !t.fired
		t.stopped = true
		return was
	}
}

// Advance moves the clock, firing due timers in order.
func (c *fakeClock) Advance(d time.Duration) {
	c.mu.Lock()
	target := c.now.Add(d)
	c.mu.Unlock()
	for {
		c.mu.Lock()
		var next *fakeTimer
		for _, t := range c.timers {
			if !t.stopped && !t.fired && !t.at.After(target) && (next == nil || t.at.Before(next.at)) {
				next = t
			}
		}
		if next == nil {
			c.now = target
			c.mu.Unlock()
			return
		}
		next.fired = true
		if next.at.After(c.now) {
			c.now = next.at
		}
		c.mu.Unlock()
		next.f()
	}
}

// pending counts the timers still armed.
func (c *fakeClock) pending() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	n := 0
	for _, t := range c.timers {
		if !t.stopped && !t.fired {
			n++
		}
	}
	return n
}

// allowFw lets a test agent close SSH and run trials, with throwaway
// state and rules directories.
func allowFw(t *testing.T, a *Agent) {
	t.Helper()
	a.cfg.Firewall.AllowCloseSSH = true
	a.src.FwDir = filepath.Join(t.TempDir(), "fw-pending")
	if a.src.UFWDir == "" {
		a.src.UFWDir = t.TempDir()
	}
}

const (
	testSelf = "/usr/local/bin/statix-agent"
	testCfg  = "/etc/statix-agent/config.toml"
	trialMsg = 8
)

// fwAgent is an agent over fakeUFW with a fake clock, allowed to close SSH.
func fwAgent(t *testing.T, f *fakeUFW) (*Agent, *fakeSender, *fakeClock) {
	t.Helper()
	send := &fakeSender{}
	a := testAgent(send)
	a.src.Runner = f
	a.src.UFWDir = f.dir
	allowFw(t, a)
	a.src.SelfPath, a.src.ConfigPath = testSelf, testCfg
	clk := newFakeClock()
	a.now, a.fwAfter = clk.Now, clk.After
	return a, send, clk
}

// restart is a new agent process over the same disk state.
func restart(t *testing.T, old *Agent, f *fakeUFW, now time.Time) (*Agent, *fakeSender, *fakeClock) {
	t.Helper()
	a, send, clk := fwAgent(t, f)
	a.src.FwDir = old.src.FwDir
	clk.now = now
	return a, send, clk
}

func fwPress(t *testing.T, a *Agent, id, data string) {
	t.Helper()
	a.handleCallback(context.Background(), &telegram.Callback{ID: id, ChatID: 42, FromID: 42, ChatType: "private", MessageID: trialMsg, Data: data})
}

// buttonData is the data of the button whose label starts with label.
func buttonDataPrefix(kb telegram.Keyboard, label string) string {
	for _, row := range kb {
		for _, b := range row {
			if strings.HasPrefix(b.Text, label) {
				return b.Data
			}
		}
	}
	return ""
}

// closeSSH runs Close port 22 through both confirms.
func closeSSH(t *testing.T, a *Agent, send *fakeSender) {
	t.Helper()
	fwPress(t, a, "ask", "fw_close_ask")
	fwPress(t, a, "yes1", tokenData(lastEditKB(send), tgui.ActYes))
	fwPress(t, a, "yes2", tokenData(lastEditKB(send), tgui.ActYes))
}

func openSSH(t *testing.T, a *Agent, send *fakeSender) {
	t.Helper()
	fwPress(t, a, "ask", "fw_open_ask")
	fwPress(t, a, "yes1", tokenData(lastEditKB(send), tgui.ActYes))
}

func pendingTrial(t *testing.T, a *Agent) (fwTrialRecord, bool) {
	t.Helper()
	rec, ok, err := loadTrial(a.src.FwDir)
	if err != nil {
		t.Fatal(err)
	}
	return rec, ok
}

const adminPeer = "0 0 10.0.0.5:22 203.0.113.4:50000"

func TestFirewallCloseUnderTrialAndKeepNeedsEvidence(t *testing.T) {
	f := newFakeUFW(t, "allow OpenSSH", "allow 80/tcp")
	f.setSS(adminPeer)
	a, send, clk := fwAgent(t, f)
	before := f.files()

	closeSSH(t, a, send)

	// The corrected write path: the conflicting app rule deleted by
	// spec, the deny inserted at 1, then a reload.
	want := []string{"--force delete allow OpenSSH", "insert 1 deny 22/tcp", "reload"}
	if got := f.ruleCalls(); !slices.Equal(got, want) {
		t.Fatalf("rule calls = %q, want %q", got, want)
	}
	rec, ok := pendingTrial(t, a)
	if !ok || rec.PreSHA == "" || rec.PostSHA == "" || rec.PreSHA == rec.PostSHA || !rec.Layer1 || !rec.Evidence {
		t.Fatalf("trial record = %+v", rec)
	}
	if rec.MsgID != trialMsg || rec.ActorID != 42 || rec.ChatID != 42 {
		t.Errorf("trial bound to %d/%d/%d", rec.ChatID, rec.MsgID, rec.ActorID)
	}
	if !rec.Deadline.Equal(clk.Now().Add(120 * time.Second)) {
		t.Errorf("deadline = %v, want now+120s", rec.Deadline)
	}
	last := send.lastEdit()
	if !strings.Contains(last.html, "Trial applied") || !strings.Contains(last.html, "rollback in 2:00") ||
		!strings.Contains(last.html, "12:02:00 UTC") {
		t.Errorf("countdown = %q", last.html)
	}
	keep, back := buttonDataPrefix(last.kb, "✅ Keep"), buttonDataPrefix(last.kb, "↩️ Roll back")
	if keep == "" || back == "" || len(keep) > 64 {
		t.Fatalf("countdown keyboard = %+v", last.kb)
	}

	// Countdown edits, every 10 s.
	edits := send.editCount()
	clk.Advance(10 * time.Second)
	if send.editCount() != edits+1 || !strings.Contains(send.lastEdit().html, "rollback in 1:50") {
		t.Errorf("countdown tick: %d edits, %q", send.editCount()-edits, send.lastEdit().html)
	}

	// Someone else cannot press Keep.
	a.handleCallback(context.Background(), &telegram.Callback{ID: "intruder", ChatID: 42, FromID: 7, ChatType: "private", MessageID: trialMsg, Data: keep})
	if _, ok := pendingTrial(t, a); !ok {
		t.Fatal("another user's Keep ended the trial")
	}

	// Keep without a new SSH connection is refused (Decision 15).
	fwPress(t, a, "keep1", keep)
	if _, ok := pendingTrial(t, a); !ok {
		t.Fatal("Keep without evidence ended the trial")
	}
	last = send.lastEdit()
	if !strings.Contains(last.html, "Not kept") {
		t.Errorf("Keep without evidence = %q", last.html)
	}
	keep = buttonDataPrefix(last.kb, "✅ Keep")
	if keep == "" {
		t.Fatalf("no fresh Keep after a refused one: %+v", last.kb)
	}

	// A new connection (another SSH port is out of scope; the fake
	// shows one on 22 from a new source port) is the evidence.
	f.setSS(adminPeer + "\n0 0 10.0.0.5:22 203.0.113.4:50001")
	fwPress(t, a, "keep2", keep)
	if _, ok := pendingTrial(t, a); ok {
		t.Fatal("Keep with evidence left the trial pending")
	}
	if !strings.Contains(send.lastEdit().html, "✅ Kept · snapshot "+rec.ID) {
		t.Errorf("kept = %q", send.lastEdit().html)
	}
	stops := slices.DeleteFunc(f.callsOf("systemctl"), func(c []string) bool { return c[1] != "stop" })
	if len(stops) != 1 || !slices.Equal(stops[0], []string{"systemctl", "stop", "statix-fw-rollback-" + rec.ID + ".timer"}) {
		t.Errorf("systemctl calls = %v", stops)
	}
	if f.files() == before {
		t.Error("Keep rolled the change back")
	}
	// Nothing fires later: no rollback, no countdown edit.
	edits = send.editCount()
	clk.Advance(10 * time.Minute)
	if send.editCount() != edits || f.files() == before {
		t.Errorf("timers outlived Keep: %d edits", send.editCount()-edits)
	}
	if _, err := os.Stat(filepath.Join(a.src.FwDir, rec.ID, "user.rules")); err != nil {
		t.Errorf("snapshot not kept: %v", err)
	}
}

func TestFirewallSystemdRunArgv(t *testing.T) {
	f := newFakeUFW(t, "allow 22/tcp", "allow 80/tcp")
	a, send, _ := fwAgent(t, f)
	a.cfg.Firewall.TrialSeconds = 300
	openSSH(t, a, send) // already open: still a trial
	rec, ok := pendingTrial(t, a)
	if !ok {
		t.Fatal("no trial")
	}
	runs := f.callsOf("systemd-run")
	want := []string{"systemd-run", "--unit=statix-fw-rollback-" + rec.ID, "--on-active=300s",
		"--timer-property=AccuracySec=1s", "--property=Type=oneshot",
		testSelf, "--config", testCfg, "--fw-rollback", rec.ID}
	if len(runs) != 1 || !slices.Equal(runs[0], want) {
		t.Errorf("systemd-run = %q\nwant %q", runs, want)
	}
}

func TestFirewallWithoutSystemdRunCapsTrial(t *testing.T) {
	f := newFakeUFW(t, "deny 22/tcp", "allow 80/tcp")
	f.noSystemdRun = true
	a, send, clk := fwAgent(t, f)
	before := f.files()
	openSSH(t, a, send)
	rec, _ := pendingTrial(t, a)
	if rec.Layer1 || !rec.Deadline.Equal(clk.Now().Add(60*time.Second)) {
		t.Fatalf("record = %+v", rec)
	}
	if !strings.Contains(send.lastEdit().html, "systemd-run is unavailable") {
		t.Errorf("countdown must warn: %q", send.lastEdit().html)
	}
	// Layer 2 alone, at the deadline itself.
	clk.Advance(60 * time.Second)
	if f.files() != before {
		t.Error("layer 2 did not roll back at the deadline")
	}
}

func TestFirewallOpenNeedsNoOptInAndKeepsWithoutEvidence(t *testing.T) {
	f := newFakeUFW(t, "deny 22/tcp", "allow 80/tcp")
	a, send, _ := fwAgent(t, f)
	a.cfg.Firewall.AllowCloseSSH = false
	text, kb := a.firewallView(context.Background())
	if !strings.Contains(text, "🔒 <b>closed</b>") || buttonDataPrefix(kb, "🔓 Open") != "~1fo" {
		t.Fatalf("closed view = %q %+v", text, kb)
	}
	openSSH(t, a, send)
	if got, want := f.ruleCalls(), []string{"--force delete deny 22/tcp", "insert 1 allow 22/tcp", "reload"}; !slices.Equal(got, want) {
		t.Fatalf("rule calls = %q, want %q", got, want)
	}
	fwPress(t, a, "keep", buttonDataPrefix(lastEditKB(send), "✅ Keep"))
	if _, ok := pendingTrial(t, a); ok || !strings.Contains(send.lastEdit().html, "Kept") {
		t.Errorf("Keep of an open: %q", send.lastEdit().html)
	}
}

func TestFirewallCloseSSHOffByDefault(t *testing.T) {
	for _, rules := range [][]string{{"allow 22/tcp"}, {"allow 80/tcp"}} {
		f := newFakeUFW(t, rules...)
		a, send, _ := fwAgent(t, f)
		a.cfg.Firewall.AllowCloseSSH = false
		_, kb := a.firewallView(context.Background())
		for _, row := range kb {
			for _, b := range row {
				if b.Data == "fw_close_ask" || b.Data == "~1fc" || strings.HasPrefix(b.Text, "🔒 Close") {
					t.Errorf("%v: Close rendered while allow_close_ssh is off: %+v", rules, kb)
				}
			}
		}
		// The ask button, the legacy Yes, and a token minted anyway.
		for _, data := range []string{"~1fc", "fw_close_ask", "fw_close"} {
			fwPress(t, a, data, data)
			last := send.lastEdit()
			if !strings.Contains(last.html, "allow_close_ssh") || tokenData(last.kb, tgui.ActYes) != "" {
				t.Errorf("%s: %q %+v", data, last.html, last.kb)
			}
		}
		nonce, err := a.tokens.Mint(tgui.Intent{Action: actFwClose, Target: sshPort, ActorID: 42, ChatID: 42, MessageID: trialMsg, Final: true})
		if err != nil {
			t.Fatal(err)
		}
		data, _ := tgui.Encode(a.tokens.Yes(nonce))
		fwPress(t, a, "forged", data)
		if !strings.Contains(send.lastEdit().html, "allow_close_ssh") {
			t.Errorf("token: %q", send.lastEdit().html)
		}
		if calls := f.ruleCalls(); len(calls) != 0 {
			t.Errorf("rules changed while closing is off: %q", calls)
		}
		if _, ok := pendingTrial(t, a); ok {
			t.Error("a trial started")
		}
		send.mu.Lock()
		n := len(send.answered)
		send.mu.Unlock()
		if n != 4 {
			t.Errorf("answered %d times, want once per press", n)
		}
	}
}

func TestFirewallAutoRollbackAndIdempotent(t *testing.T) {
	f := newFakeUFW(t, "allow OpenSSH", "allow 80/tcp")
	a, send, clk := fwAgent(t, f)
	before := f.files()
	closeSSH(t, a, send)
	rec, _ := pendingTrial(t, a)
	// Layer 1 is expected first; layer 2 waits 5 s more.
	clk.Advance(120 * time.Second)
	if f.files() == before {
		t.Fatal("layer 2 fired before its grace")
	}
	clk.Advance(5 * time.Second)
	if f.files() != before {
		t.Fatalf("not rolled back:\n%s\nwant\n%s", f.files(), before)
	}
	if _, ok := pendingTrial(t, a); ok {
		t.Error("current.json kept after rollback")
	}
	if last := send.lastEdit(); last.messageID != trialMsg || !strings.Contains(last.html, "Rolled back") {
		t.Errorf("notice = %+v", last)
	}
	if clk.pending() != 0 {
		t.Errorf("%d timers left", clk.pending())
	}
	// Layer 1 arriving late, or a second rollback, does nothing.
	reloads := len(f.ruleCalls())
	if err := RunFwRollback(context.Background(), a.cfg, a.src, nil, rec.ID); err != nil {
		t.Fatal(err)
	}
	if out := a.rollbackTrial(context.Background(), rec.ID); !out.drift {
		t.Errorf("second rollback = %+v", out)
	}
	if len(f.ruleCalls()) != reloads || f.files() != before {
		t.Errorf("rollback repeated: %q", f.ruleCalls()[reloads:])
	}
}

func TestFirewallRollbackIdempotentOnPreSHA(t *testing.T) {
	f := newFakeUFW(t, "allow OpenSSH", "allow 80/tcp")
	a, send, _ := fwAgent(t, f)
	before := f.files()
	closeSSH(t, a, send)
	rec, _ := pendingTrial(t, a)
	// A rollback that restored the files but died before cleaning up.
	snap, err := loadSnap(filepath.Join(a.src.FwDir, rec.ID))
	if err != nil {
		t.Fatal(err)
	}
	for name, data := range snap.Files {
		os.WriteFile(filepath.Join(f.dir, name), data, 0o600)
	}
	n := len(f.ruleCalls())
	if err := RunFwRollback(context.Background(), a.cfg, a.src, send, rec.ID); err != nil {
		t.Fatal(err)
	}
	if got := f.ruleCalls()[n:]; len(got) != 0 {
		t.Errorf("pre_sha rollback ran %q, want cleanup only", got)
	}
	if _, ok := pendingTrial(t, a); ok || f.files() != before {
		t.Error("not cleaned up")
	}
}

func TestFirewallRollbackButton(t *testing.T) {
	f := newFakeUFW(t, "deny 22/tcp")
	a, send, clk := fwAgent(t, f)
	before := f.files()
	openSSH(t, a, send)
	fwPress(t, a, "back", buttonDataPrefix(lastEditKB(send), "↩️ Roll back"))
	if f.files() != before || !strings.Contains(send.lastEdit().html, "Rolled back") {
		t.Errorf("roll back now: %q", send.lastEdit().html)
	}
	// Keep on the same countdown is now stale.
	edits := send.editCount()
	clk.Advance(5 * time.Minute)
	if send.editCount() != edits {
		t.Error("timers outlived the rollback")
	}
}

func TestFirewallApplyFailureRollsBack(t *testing.T) {
	// The delete succeeds, the insert fails: the half-applied plan is
	// restored from the snapshot at once.
	f := newFakeUFW(t, "allow OpenSSH", "allow 80/tcp")
	f.failOn = "insert"
	a, send, _ := fwAgent(t, f)
	before := f.files()
	closeSSH(t, a, send)
	last := send.lastEdit()
	if !strings.Contains(last.html, "Change failed") || !strings.Contains(last.html, "read-only file system") {
		t.Errorf("failure = %q", last.html)
	}
	if f.files() != before {
		t.Error("a failed apply was not rolled back")
	}
	if _, ok := pendingTrial(t, a); ok {
		t.Error("trial left pending")
	}
}

// TestFirewallCrashAtEachStep kills the agent after each apply step and
// starts a new one over the same disk, before and after the deadline.
// Whatever the step, the rules end as they were.
func TestFirewallCrashAtEachStep(t *testing.T) {
	type crash struct{ step string }
	for _, step := range []string{"snapshot", "record", "layer1", "apply", "post"} {
		for _, late := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/late=%v", step, late), func(t *testing.T) {
				f := newFakeUFW(t, "allow OpenSSH", "allow 80/tcp")
				a, send, clk := fwAgent(t, f)
				before := f.files()
				a.fwCrash = func(s string) {
					if s == step {
						panic(crash{s})
					}
				}
				func() {
					defer func() {
						if r := recover(); r != (crash{step}) {
							t.Fatalf("recovered %v", r)
						}
					}()
					closeSSH(t, a, send)
				}()
				applied := step == "apply" || step == "post"
				if applied == (f.files() == before) {
					t.Fatalf("after a crash at %s the rules changed=%v", step, f.files() != before)
				}

				now := clk.Now().Add(30 * time.Second)
				if late {
					now = clk.Now().Add(10 * time.Minute)
				}
				b, send2, clk2 := restart(t, a, f, now)
				b.reconcileFwTrial(context.Background())
				rec, pending := pendingTrial(t, b)
				switch {
				case step == "snapshot":
					if pending {
						t.Fatal("a trial with no record is pending")
					}
				case late:
					if pending || f.files() != before {
						t.Fatalf("late start did not roll back: pending=%v", pending)
					}
					if !strings.Contains(send2.lastEdit().html, "Rolled back") || send2.lastEdit().messageID != trialMsg {
						t.Errorf("notice = %+v", send2.lastEdit())
					}
				default:
					// Re-armed: the countdown resumes with fresh buttons
					// bound to the same message and user.
					if !pending || b.fwTrial == nil || b.fwTrial.id != rec.ID {
						t.Fatalf("not re-armed: %+v", b.fwTrial)
					}
					if last := send2.lastEdit(); last.messageID != trialMsg || buttonDataPrefix(last.kb, "✅ Keep") == "" {
						t.Errorf("countdown not resumed: %+v", last)
					}
					clk2.Advance(rec.Deadline.Sub(clk2.Now()) + 6*time.Second)
					if _, still := pendingTrial(t, b); still || f.files() != before {
						t.Fatal("re-armed layer 2 did not roll back")
					}
				}
				if f.files() != before {
					t.Errorf("rules not restored after a crash at %s", step)
				}
			})
		}
	}
}

func TestFirewallResumedKeepWorks(t *testing.T) {
	f := newFakeUFW(t, "deny 22/tcp", "allow 80/tcp")
	a, send, clk := fwAgent(t, f)
	openSSH(t, a, send)
	changed := f.files()
	b, send2, _ := restart(t, a, f, clk.Now().Add(20*time.Second))
	b.reconcileFwTrial(context.Background())
	// The old process's buttons are gone with its memory: stale.
	fwPress(t, b, "old", buttonDataPrefix(lastEditKB(send), "✅ Keep"))
	if _, ok := pendingTrial(t, b); !ok {
		t.Fatal("a previous boot's Keep ended the trial")
	}
	fwPress(t, b, "new", buttonDataPrefix(send2.edits[0].kb, "✅ Keep"))
	if _, ok := pendingTrial(t, b); ok || f.files() != changed {
		t.Error("resumed Keep did not keep")
	}
}

func TestFirewallForeignEditKeepsOtherRules(t *testing.T) {
	f := newFakeUFW(t, "allow OpenSSH", "allow 80/tcp")
	f.setSS(adminPeer)
	a, send, _ := fwAgent(t, f)
	closeSSH(t, a, send)
	rec, _ := pendingTrial(t, a)
	f.foreign("deny from 198.51.100.7") // fail2ban, say
	n := len(f.ruleCalls())
	if err := RunFwRollback(context.Background(), a.cfg, a.src, send, rec.ID); err != nil {
		t.Fatal(err)
	}
	// The inverse plan, by spec: the inserted deny removed, the deleted
	// app rule back.
	want := []string{"--force delete deny 22/tcp", "allow OpenSSH", "reload"}
	if got := f.ruleCalls()[n:]; !slices.Equal(got, want) {
		t.Errorf("inverse = %q, want %q", got, want)
	}
	v4 := f.read("user.rules")
	if !slices.Contains(v4, "deny from 198.51.100.7") || !slices.Contains(v4, "allow OpenSSH") || slices.Contains(v4, "deny 22/tcp") {
		t.Errorf("rules after inverse = %q", v4)
	}
	if last := send.lastEdit(); !strings.Contains(last.html, "changes were kept") || !strings.Contains(last.html, "198.51.100.7") {
		t.Errorf("notice = %q", last.html)
	}
	if _, ok := pendingTrial(t, a); ok {
		t.Error("trial left pending")
	}
}

func TestFirewallForeignEditByteRestoreWhenSSHBlocked(t *testing.T) {
	f := newFakeUFW(t, "allow OpenSSH", "allow 80/tcp")
	f.setSS(adminPeer)
	a, send, _ := fwAgent(t, f)
	before := f.files()
	closeSSH(t, a, send)
	rec, _ := pendingTrial(t, a)
	// The foreign rule blocks the admin peer outright: undoing only the
	// trial would leave them locked out.
	f.foreign("deny from 203.0.113.0/24")
	if err := RunFwRollback(context.Background(), a.cfg, a.src, send, rec.ID); err != nil {
		t.Fatal(err)
	}
	if f.files() != before {
		t.Errorf("snapshot not restored:\n%s\nwant\n%s", f.files(), before)
	}
	if last := send.lastEdit(); !strings.Contains(last.html, "restored byte for byte") || !strings.Contains(last.html, "203.0.113.4") {
		t.Errorf("notice = %q", last.html)
	}
}

func TestSelfUpdateBlockedDuringTrial(t *testing.T) {
	f := newFakeUFW(t, "deny 22/tcp")
	a, send, _ := fwAgent(t, f)
	applied := 0
	a.src.UpdateCheck = func(context.Context) (string, bool, error) { return "v9", true, nil }
	a.src.UpdateApply = func(context.Context) error { applied++; return nil }
	// A confirm screen shown before the trial started.
	nonce, _ := a.tokens.Mint(tgui.Intent{Action: actUpdate, Target: "agent", ActorID: 42, ChatID: 42, MessageID: 99})
	yes, _ := tgui.Encode(a.tokens.Yes(nonce))

	openSSH(t, a, send)
	if !a.FwTrialPending() {
		t.Fatal("no trial pending")
	}
	keep := buttonDataPrefix(lastEditKB(send), "✅ Keep")
	if p := a.confirms[actUpdate].prompt(context.Background(), "agent", false); p.yes != "" || p.text != trialPendingText {
		t.Errorf("update prompt during a trial = %+v", p)
	}
	a.handleCallback(context.Background(), &telegram.Callback{ID: "u", ChatID: 42, FromID: 42, ChatType: "private", MessageID: 99, Data: yes})
	if applied != 0 || !strings.Contains(send.lastEdit().html, trialPendingText) {
		t.Errorf("update ran during a trial: applied=%d %q", applied, send.lastEdit().html)
	}
	fwPress(t, a, "keep", keep)
	if a.FwTrialPending() {
		t.Fatal("trial still pending after Keep")
	}
	if p := a.confirms[actUpdate].prompt(context.Background(), "agent", false); p.yes == "" {
		t.Errorf("update still blocked after Keep: %+v", p)
	}
}

func TestFirewallCountdownStopsOn429(t *testing.T) {
	f := newFakeUFW(t, "deny 22/tcp")
	a, send, clk := fwAgent(t, f)
	openSSH(t, a, send)
	send.mu.Lock()
	send.editErr = &telegram.APIError{Code: 429, Description: "Too Many Requests", RetryAfter: 40 * time.Second}
	send.events = nil
	send.mu.Unlock()
	clk.Advance(50 * time.Second)
	if n := strings.Count(strings.Join(send.eventLog(), ","), "edit"); n != 1 {
		t.Errorf("countdown edits after a 429 = %d, want 1", n)
	}
}

func TestSSHPortPlanDualStack(t *testing.T) {
	f := newFakeUFW(t, "allow OpenSSH", "allow 80/tcp", "deny from 2001:db8::/32")
	b := &ufwBackend{run: f, dir: f.dir}
	ctx := context.Background()
	p := b.Probe(ctx)
	if !p.fw.hasV6() || p.state != fwOpen {
		t.Fatalf("fixture probe = %+v", p)
	}
	added, tr := b.added(ctx)
	if tr != nil {
		t.Fatal(tr.err)
	}
	plan := sshPortPlan(added, p.fw, false)
	want := fwPlan{{Op: opDelete, Spec: []string{"allow", "OpenSSH"}}, {Op: opInsert, Spec: []string{"deny", "22/tcp"}}}
	if fmt.Sprint(plan) != fmt.Sprint(want) {
		t.Fatalf("plan = %v, want %v", plan, want)
	}
	if _, err := b.Apply(ctx, plan); err != nil {
		t.Fatal(err)
	}
	// Both families closed, the v6-only rule kept below the insert.
	after := b.Probe(ctx)
	if f := verifySSHPort(after, false); f != nil {
		t.Errorf("verify: %s", f.display())
	}
	if v6 := f.read("user6.rules"); !slices.Equal(v6, []string{"deny 22/tcp", "allow 80/tcp", "deny from 2001:db8::/32"}) {
		t.Errorf("user6.rules = %q", v6)
	}
	// The inverse takes exactly that back.
	if inv := plan.inverse(); fmt.Sprint(inv) != fmt.Sprint(fwPlan{{Op: opDelete, Spec: []string{"deny", "22/tcp"}}, {Op: opAdd, Spec: []string{"allow", "OpenSSH"}}}) {
		t.Errorf("inverse = %v", inv)
	}
}

func TestSSHPortPlanEmptyV4AddsInsteadOfInsert(t *testing.T) {
	f := newFakeUFW(t, "allow 22/tcp", "allow from 2001:db8::/32")
	b := &ufwBackend{run: f, dir: f.dir}
	ctx := context.Background()
	p := b.Probe(ctx)
	added, _ := b.added(ctx)
	plan := sshPortPlan(added, p.fw, false)
	want := fwPlan{{Op: opDelete, Spec: []string{"allow", "22/tcp"}}, {Op: opAdd, Spec: []string{"deny", "22/tcp"}}}
	if fmt.Sprint(plan) != fmt.Sprint(want) {
		t.Fatalf("plan = %v, want %v", plan, want)
	}
	if _, err := b.Apply(ctx, plan); err != nil {
		t.Fatal(err)
	}
	if f := verifySSHPort(b.Probe(ctx), false); f != nil {
		t.Errorf("verify: %s", f.display())
	}
}

func TestParseRuleSpec(t *testing.T) {
	st := parseUFWOutput("Status: active\n\nTo Action From\n22/tcp (OpenSSH) ALLOW IN Anywhere\n80,443/tcp (Nginx Full) ALLOW IN Anywhere\n")
	cases := []struct {
		spec    string
		sshOnly bool
	}{
		{"allow 22/tcp", true},
		{"limit 22", true},
		{"allow OpenSSH", true},
		{"allow 'Nginx Full'", false},
		{"allow 22/udp", false},
		{"allow 20:30/tcp", false},
		{"allow from 10.0.0.0/8 to any port 22", false},
		{"allow from any to any port 22 proto tcp", true},
		{"allow in on eth0 to any port 22", false},
		{"allow log 22/tcp comment 'ssh access'", true},
		{"allow out 22/tcp", false},
	}
	for _, tc := range cases {
		r, ok := parseRuleSpec(splitQuoted(tc.spec))
		if got := ok && r.sshOnly(st); got != tc.sshOnly {
			t.Errorf("%q: sshOnly = %v (%+v)", tc.spec, got, r)
		}
	}
	if got := parseShowAdded("Added user rules (see 'ufw status' for running firewall):\nufw allow 'Nginx Full'\nufw route allow 80\n(None)\n"); fmt.Sprint(got) != "[[allow Nginx Full]]" {
		t.Errorf("parseShowAdded = %q", got)
	}
}

func TestParseSSEstablished(t *testing.T) {
	out := "0 0 10.0.0.5:22 203.0.113.4:50000\n" +
		"0 0 [::ffff:10.0.0.5]:22 [::ffff:198.51.100.1]:40000\n" +
		"0 0 [2001:db8::5]:2222 [2001:db8::9]:41000\n" +
		"0 0 10.0.0.5:443 203.0.113.9:1234\n"
	got := connKeys(parseSSEstablished(out, []int{22, 2222}))
	want := []string{"10.0.0.5:22>203.0.113.4:50000", "10.0.0.5:22>198.51.100.1:40000", "[2001:db8::5]:2222>[2001:db8::9]:41000"}
	if !slices.Equal(got, want) {
		t.Errorf("conns = %q, want %q", got, want)
	}
}

func TestRunFwRollbackRejectsBadID(t *testing.T) {
	a := testAgent(&fakeSender{})
	for _, id := range []string{"", "../etc", "ABCDEF12", "a1b2c3d4e"} {
		if err := RunFwRollback(context.Background(), a.cfg, a.src, nil, id); err == nil {
			t.Errorf("id %q accepted", id)
		}
	}
}

func TestHashRuleFilesDistinguishesMissing(t *testing.T) {
	if hashRuleFiles(map[string][]byte{"user.rules": nil}) == hashRuleFiles(map[string][]byte{"user.rules": {}, "user6.rules": {}}) {
		t.Error("an absent user6.rules hashes like an empty one")
	}
	if !bytes.Equal([]byte(hashRuleFiles(nil)), []byte(hashRuleFiles(map[string][]byte{}))) {
		t.Error("hash not deterministic")
	}
}
