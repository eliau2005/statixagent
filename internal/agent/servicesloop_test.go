package agent

import (
	"context"
	"errors"
	"net"
	"net/http"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/eliau2005/statixagent/internal/alert"
	"github.com/eliau2005/statixagent/internal/config"
	"github.com/eliau2005/statixagent/internal/services"
	"github.com/eliau2005/statixagent/internal/telegram"
	"github.com/eliau2005/statixagent/internal/tgui"
)

// watchFixture is a host with one watched item of each kind whose state
// tests flip between passes: nginx in systemd, a local port, an HTTP
// check and the redis-server process.
type watchFixture struct {
	mu     sync.Mutex
	unit   string // nginx's ActiveState
	status int    // the HTTP check's answer
	proc   services.State
	port   int
	ln     net.Listener
	now    time.Time
}

func (f *watchFixture) Run(_ context.Context, name string, args ...string) (string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if name == "systemctl" && len(args) > 0 && args[0] == "list-units" {
		return "nginx.service loaded " + f.unit + " running A web server\n", nil
	}
	return "", errors.New("unexpected " + name)
}

// set puts every item in the healthy or failing state.
func (f *watchFixture) set(t *testing.T, ok bool) {
	t.Helper()
	f.mu.Lock()
	defer f.mu.Unlock()
	f.unit, f.status, f.proc = "failed", 503, services.StateDown
	if ok {
		f.unit, f.status, f.proc = "active", 200, services.StateOK
	}
	switch {
	case ok && f.ln == nil:
		ln, err := net.Listen("tcp", "127.0.0.1:"+strconv.Itoa(f.port))
		if err != nil {
			t.Skipf("cannot listen on the watched port again: %v", err)
		}
		f.ln = ln
	case !ok && f.ln != nil:
		f.ln.Close()
		f.ln = nil
	}
}

// advance moves the fixture clock on.
func (f *watchFixture) advance(d time.Duration) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.now = f.now.Add(d)
}

// watchAgent is an agent watching the fixture's items, all healthy.
func watchAgent(t *testing.T) (*Agent, *fakeSender, *watchFixture) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Skipf("no loopback listener: %v", err)
	}
	f := &watchFixture{ln: ln, port: ln.Addr().(*net.TCPAddr).Port, now: screenEpoch}
	t.Cleanup(func() {
		f.mu.Lock()
		defer f.mu.Unlock()
		if f.ln != nil {
			f.ln.Close()
		}
	})
	f.set(t, true)
	send := &fakeSender{}
	a := testAgent(send)
	a.now = func() time.Time {
		f.mu.Lock()
		defer f.mu.Unlock()
		return f.now
	}
	a.src.Runner = f
	a.src.ProcFS = func(names []string) ([]services.Result, error) {
		f.mu.Lock()
		defer f.mu.Unlock()
		var out []services.Result
		for _, n := range names {
			out = append(out, services.Result{Name: n, State: f.proc, Detail: map[bool]string{true: "1 running", false: "not running"}[f.proc == services.StateOK]})
		}
		return out, nil
	}
	prev := httpClient
	httpClient = &http.Client{Transport: roundTrip(func(r *http.Request) (*http.Response, error) {
		f.mu.Lock()
		defer f.mu.Unlock()
		return &http.Response{StatusCode: f.status, Body: http.NoBody, Request: r}, nil
	})}
	t.Cleanup(func() { httpClient = prev })
	a.cfg.Watch = config.Watch{
		Services:   []string{"nginx"},
		Processes:  []string{"redis-server"},
		Ports:      []config.PortCheck{{Port: f.port, Label: "web"}},
		HTTPChecks: []config.HTTPCheck{{URL: "https://api.example/hz"}},
	}
	return a, send, f
}

// alertTexts is what was sent since from.
func alertTexts(send *fakeSender, from int) []string {
	send.mu.Lock()
	defer send.mu.Unlock()
	return slices.Clone(send.sent[from:])
}

// wantSent checks that n messages were sent since from, each line of
// want in one of them, and returns the new count.
func wantSent(t *testing.T, send *fakeSender, from, n int, step string, want ...string) int {
	t.Helper()
	got := alertTexts(send, from)
	if len(got) != n {
		t.Fatalf("%s: sent %d messages, want %d:\n%s", step, len(got), n, strings.Join(got, "\n"))
	}
	for _, w := range want {
		if !slices.ContainsFunc(got, func(s string) bool { return strings.Contains(s, w) }) {
			t.Errorf("%s: no message with %q in:\n%s", step, w, strings.Join(got, "\n"))
		}
	}
	return from + n
}

func TestServicesAlertOnTransitionsOnly(t *testing.T) {
	ctx := context.Background()
	a, send, f := watchAgent(t)
	port := strconv.Itoa(f.port)
	pass := func(d time.Duration) {
		f.advance(d)
		a.checkServices(ctx)
	}

	pass(0)
	n := wantSent(t, send, 0, 0, "healthy baseline")
	pass(time.Minute)
	n = wantSent(t, send, n, 0, "still healthy")

	f.set(t, false)
	pass(time.Minute)
	n = wantSent(t, send, n, 4, "failing",
		"🚨 <b>Unit failing</b>", "nginx.service: failed",
		"🚨 <b>Port failing</b>", "port "+port+" (web): closed",
		"⚠️ <b>HTTP check failing</b>", "https://api.example/hz: got 503, want 200",
		"🚨 <b>Process failing</b>", "redis-server: not running")
	pass(time.Minute)
	n = wantSent(t, send, n, 0, "still failing")

	f.set(t, true)
	pass(time.Minute)
	n = wantSent(t, send, n, 4, "recovered",
		"✅ <b>Unit recovered</b>", "nginx.service is active again",
		"✅ <b>Port recovered</b>", "port "+port+" (web) is listening again",
		"✅ <b>HTTP check recovered</b>", "https://api.example/hz is OK again",
		"✅ <b>Process recovered</b>", "redis-server is running again")
	pass(time.Minute)
	wantSent(t, send, n, 0, "still healthy")
}

// A flap inside the cooldown is not alerted, nor is its recovery; a
// failure that outlasts the cooldown is.
func TestServicesAlertCooldown(t *testing.T) {
	ctx := context.Background()
	a, send, f := watchAgent(t)
	a.cfg.Watch = config.Watch{Services: []string{"nginx"}}
	pass := func(d time.Duration) {
		f.advance(d)
		a.checkServices(ctx)
	}
	pass(0)
	f.set(t, false)
	pass(time.Minute)
	n := wantSent(t, send, 0, 1, "failing", "Unit failing")
	f.set(t, true)
	pass(time.Minute)
	n = wantSent(t, send, n, 1, "recovered", "Unit recovered")

	f.set(t, false)
	pass(time.Minute)
	n = wantSent(t, send, n, 0, "failing again inside the cooldown")
	f.set(t, true)
	pass(time.Minute)
	n = wantSent(t, send, n, 0, "recovered from an unalerted failure")

	f.set(t, false)
	pass(time.Minute)
	n = wantSent(t, send, n, 0, "failing again inside the cooldown")
	pass(10 * time.Minute)
	wantSent(t, send, n, 1, "still failing past the cooldown", "Unit failing")
}

// The first pass only records: failures already there when the agent
// starts are not repeated, but their recovery is news.
func TestServicesStartupSilent(t *testing.T) {
	ctx := context.Background()
	a, send, f := watchAgent(t)
	f.set(t, false)
	a.checkServices(ctx)
	n := wantSent(t, send, 0, 0, "failing at startup")
	f.advance(time.Minute)
	a.checkServices(ctx)
	n = wantSent(t, send, n, 0, "still failing")

	f.set(t, true)
	f.advance(time.Minute)
	a.checkServices(ctx)
	n = wantSent(t, send, n, 4, "recovered", "Unit recovered", "Port recovered", "HTTP check recovered", "Process recovered")

	// An item watched later is only recorded on its first pass too.
	a.cfg.Watch.Processes = append(a.cfg.Watch.Processes, "postgres")
	f.mu.Lock()
	f.proc = services.StateDown
	f.mu.Unlock()
	f.advance(time.Minute)
	a.checkServices(ctx)
	wantSent(t, send, n, 1, "redis-server stops as postgres is first seen", "redis-server: not running")
}

// A snoozed check alerts neither its failure nor its recovery; one still
// failing when the snooze ends alerts then.
func TestServicesAlertSnooze(t *testing.T) {
	ctx := context.Background()
	a, send, f := watchAgent(t)
	a.cfg.Watch = config.Watch{Services: []string{"nginx"}}
	a.checkServices(ctx)
	a.engine.Snooze("svc:nginx.service", a.now().Add(time.Hour))

	for _, ok := range []bool{false, true, false} {
		f.set(t, ok)
		f.advance(time.Minute)
		a.checkServices(ctx)
	}
	n := wantSent(t, send, 0, 0, "snoozed")

	f.advance(time.Hour)
	a.checkServices(ctx)
	wantSent(t, send, n, 1, "snooze over, still failing", "Unit failing")
}

func TestWatchAlertKeys(t *testing.T) {
	long := "https://api.example/a/very/long/path?with=query&and=more"
	for _, tc := range []struct {
		it   svItem
		want string
	}{
		{svItem{kind: watchUnit, name: "nginx.service"}, "svc:nginx.service"},
		{svItem{kind: watchPort, name: "5432"}, "port:5432"},
		{svItem{kind: watchHTTP, name: long}, "http:" + callbackDigest(long)},
		{svItem{kind: watchProc, name: "redis-server"}, "proc:redis-server"},
	} {
		if got := watchAlertKey(tc.it); got != tc.want {
			t.Errorf("watchAlertKey(%+v) = %q, want %q", tc.it, got, tc.want)
		}
	}
}

// firstRow is an alert keyboard's first row: data by label.
func firstRow(kb telegram.Keyboard) map[string]string {
	m := map[string]string{}
	for _, b := range kb[0] {
		m[b.Text] = b.Data
	}
	return m
}

// [🔁 Restart] is offered only when service actions are on and allow the
// unit, and it only ever asks: its data names an ask act.
func TestServiceAlertRestartOnlyWhenAllowed(t *testing.T) {
	restart := callData(tgui.Call{Act: askUnitAct, Args: []string{services.VerbRestart, callbackDigest("nginx.service")}, From: fromAlert})
	open := callData(tgui.Call{Act: tgui.ActOpen, Args: []string{scrUnit, callbackDigest("nginx.service")}})
	for _, tc := range []struct {
		name    string
		key     string
		actions config.Actions
		restart bool
	}{
		{"actions off", "svc:nginx.service", config.Actions{}, false},
		{"watched unit, default allow", "svc:nginx.service", config.Actions{Enabled: true}, true},
		{"not watched, default allow", "svc:cron.service", config.Actions{Enabled: true}, false},
		{"not in allow", "svc:nginx.service", config.Actions{Enabled: true, Allow: []string{"postgresql"}}, false},
		{"named in allow", "svc:nginx.service", config.Actions{Enabled: true, Allow: []string{"nginx"}}, true},
		{"always denied", "svc:statix-agent.service", config.Actions{Enabled: true, Allow: []string{"statix-agent"}}, false},
	} {
		a := testAgent(&fakeSender{})
		a.cfg.Watch.Services = []string{"nginx", "statix-agent"}
		a.cfg.Actions = tc.actions
		row := firstRow(a.alertKeyboard(tc.key))
		if _, ok := row["🔍 Open"]; !ok {
			t.Errorf("%s: no Open button: %v", tc.name, row)
		}
		if _, ok := row["🔁 Restart"]; ok != tc.restart {
			t.Errorf("%s: Restart offered = %v, want %v", tc.name, ok, tc.restart)
		}
		if tc.key == "svc:nginx.service" {
			if row["🔍 Open"] != open {
				t.Errorf("%s: Open = %q, want %q", tc.name, row["🔍 Open"], open)
			}
			if tc.restart && row["🔁 Restart"] != restart {
				t.Errorf("%s: Restart = %q, want %q", tc.name, row["🔁 Restart"], restart)
			}
		}
	}
}

// Restart on an alert opens a confirm token in a new message replying to
// the alert, which keeps its text and keyboard; only that message's Yes
// restarts the unit.
func TestServiceAlertRestartThroughToken(t *testing.T) {
	ctx := context.Background()
	a, send, r, _ := actionAgent(t)
	alertID, err := a.pushAlertKB(ctx, alert.Alert{Key: "svc:postgresql.service", Severity: alert.Critical,
		Title: "Unit failing", Body: "postgresql.service: failed"}, a.alertKeyboard("svc:postgresql.service"))
	if err != nil {
		t.Fatal(err)
	}
	cb := func(id string, msg int64, data string) *telegram.Callback {
		return &telegram.Callback{ID: id, ChatID: 42, ChatType: "private", FromID: 42, MessageID: msg, Data: data}
	}
	send.mu.Lock()
	restart := buttonData(send.keyboards[0], "🔁 Restart")
	send.mu.Unlock()
	a.handleCallback(ctx, cb("restart", alertID, restart))
	if jobs := r.queued(); len(jobs) != 0 {
		t.Fatalf("Restart acted without a confirm: %v", jobs)
	}
	send.mu.Lock()
	edits, markups, answered := len(send.edits), len(send.markups), slices.Clone(send.answered)
	prompt, promptKB, replyTo := send.sent[1], send.keyboards[1], send.replyTo[1]
	send.mu.Unlock()
	if edits != 0 || markups != 0 {
		t.Fatalf("the alert changed: %d edits, %d keyboard edits", edits, markups)
	}
	if len(answered) != 1 {
		t.Fatalf("answered %v, want exactly once", answered)
	}
	if replyTo != alertID || !strings.Contains(prompt, "Restart postgresql.service?") {
		t.Fatalf("confirm not sent as a reply to the alert (reply to %d): %q", replyTo, prompt)
	}
	promptID := lastSentID(send)
	yes := tokenData(promptKB, tgui.ActYes)
	if yes == "" {
		t.Fatalf("no confirm token: %v", promptKB)
	}
	// The token is bound to the prompt: the same Yes on the alert is stale.
	a.handleCallback(ctx, cb("yes-on-alert", alertID, yes))
	if jobs := r.queued(); len(jobs) != 0 {
		t.Fatalf("a Yes on another message acted: %v", jobs)
	}
	a.handleCallback(ctx, cb("yes", promptID, yes))
	jobs := r.queued()
	if len(jobs) != 1 || !slices.Equal(jobs[0][len(jobs[0])-3:], []string{services.VerbRestart, "--", "postgresql.service"}) {
		t.Fatalf("jobs = %v, want one restart of postgresql.service", jobs)
	}
}

// A Restart that is no longer allowed when pressed (actions turned off
// since the alert) is refused in a reply, and nothing runs.
func TestServiceAlertRestartRefused(t *testing.T) {
	ctx := context.Background()
	a, send, r, _ := actionAgent(t)
	data := buttonData(a.alertKeyboard("svc:postgresql.service"), "🔁 Restart")
	a.cfg.Actions.Enabled = false
	a.handleCallback(ctx, &telegram.Callback{ID: "restart", ChatID: 42, ChatType: "private", FromID: 42, MessageID: 7, Data: data})
	if jobs := r.queued(); len(jobs) != 0 {
		t.Fatalf("a refused Restart acted: %v", jobs)
	}
	send.mu.Lock()
	defer send.mu.Unlock()
	if len(send.sent) != 1 || send.replyTo[0] != 7 || !strings.Contains(send.sent[0], "Refused") || len(send.edits) != 0 {
		t.Fatalf("no refusal in a reply: sent %q, replies %v, %d edits", send.sent, send.replyTo, len(send.edits))
	}
	if tokenData(send.keyboards[0], tgui.ActYes) != "" {
		t.Fatal("a refusal carries a confirm token")
	}
}

// Open on an alert sends the unit's detail as a reply; the alert stays.
func TestServiceAlertOpen(t *testing.T) {
	ctx := context.Background()
	a, send, _, _ := actionAgent(t)
	data := buttonData(a.alertKeyboard("svc:postgresql.service"), "🔍 Open")
	a.handleCallback(ctx, &telegram.Callback{ID: "open", ChatID: 42, ChatType: "private", FromID: 42, MessageID: 7, Data: data})
	send.mu.Lock()
	defer send.mu.Unlock()
	if len(send.sent) != 1 || send.replyTo[0] != 7 || !strings.Contains(send.sent[0], "postgresql.service") || len(send.edits) != 0 {
		t.Fatalf("Open did not reply with the unit: sent %q, replies %v, %d edits", send.sent, send.replyTo, len(send.edits))
	}
}
