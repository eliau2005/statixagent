package agent

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"

	"github.com/eliau2005/statixagent/internal/config"
	"github.com/eliau2005/statixagent/internal/services"
	"github.com/eliau2005/statixagent/internal/telegram"
	"github.com/eliau2005/statixagent/internal/tgui"
)

// actionUnits is the hub fixtures' systemd plus the units the deny-list
// and the double confirm are about.
const actionUnits = hubUnits +
	"docker.service loaded active running Docker Application Container Engine\n" +
	"statix-agent.service loaded active running statix agent\n" +
	"dbus.service loaded active running D-Bus System Message Bus\n" +
	"systemd-journald.service loaded active running Journal Service\n"

// actRunner is a systemd for the service actions: it lists actionUnits,
// shows each unit as hubShow has it or else active, records the jobs
// queued (a stop leaves the unit inactive, anything else a new active
// run) and answers journalctl with logs.
type actRunner struct {
	mu   sync.Mutex
	logs string
	jobs [][]string
	runs []string
}

func (r *actRunner) Run(_ context.Context, name string, args ...string) (string, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.runs = append(r.runs, name+" "+strings.Join(args, " "))
	switch {
	case name == "journalctl":
		return r.logs, nil
	case name != "systemctl":
		return "", errors.New("not installed")
	case args[0] == "list-units":
		return actionUnits, nil
	case args[0] == "show" && strings.Contains(args[1], "InvocationID"):
		state := "active"
		if n := len(r.jobs); n > 0 && r.jobs[n-1][3] == services.VerbStop {
			state = "inactive"
		}
		return fmt.Sprintf("ActiveState=%s\nInvocationID=%d\n", state, len(r.jobs)), nil
	case args[0] == "show":
		if out, ok := hubShow[args[len(args)-1]]; ok {
			return out, nil
		}
		return "LoadState=loaded\nActiveState=active\nSubState=running\nUnitFileState=enabled\nNRestarts=0\n", nil
	case slices.Contains(args, "--no-block"):
		r.jobs = append(r.jobs, append([]string{name}, args...))
		return "", nil
	}
	return "", fmt.Errorf("unexpected systemctl %q", args)
}

func (r *actRunner) queued() [][]string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return slices.Clone(r.jobs)
}

func (r *actRunner) ran(prefix string) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	return slices.ContainsFunc(r.runs, func(s string) bool { return strings.HasPrefix(s, prefix) })
}

// secretToken is the bot token of the action fixtures; it must never
// reach a screen.
const secretToken = "123456789:AAH-s3cret_TOKEN"

// actionAgent is the screen fixtures with service actions on, every
// fixture unit and container allowed, and the bot token secretToken.
func actionAgent(t *testing.T) (*Agent, *fakeSender, *actRunner, *fakeEngine) {
	t.Helper()
	send := &fakeSender{}
	a := screenAgent(t, send)
	r := &actRunner{}
	a.src.Runner = r
	var engine *fakeEngine
	a.src.Docker, engine = dockerEngine(t)
	a.cfg.Telegram.Token = secretToken
	a.cfg.Actions = config.Actions{Enabled: true, Allow: []string{"nginx", "postgresql", "ssh", "docker",
		"statix-agent.service", "dbus", "systemd-journald", "x<evil>&.service", "web", "api"}}
	return a, send, r, engine
}

func unitAsk(verb, unit string) string {
	return callData(tgui.Call{Act: askUnitAct, Args: []string{verb, callbackDigest(unit)}})
}

func containerAsk(verb, id string) string {
	return callData(tgui.Call{Act: askContainerAct, Args: []string{verb, id[:shortIDLen]}})
}

func unitDetail(unit string) tgui.Call {
	return tgui.Call{Act: tgui.ActView, Args: []string{scrUnit, callbackDigest(unit)}, From: scrUnits}
}

func containerDetail(id string) tgui.Call {
	return tgui.Call{Act: tgui.ActView, Args: []string{scrContainer, id[:shortIDLen]}, From: scrDocker}
}

// actsOf lists the acts of kb's buttons other than navigation.
func actsOf(kb telegram.Keyboard) []string {
	var acts []string
	for _, row := range kb {
		for _, b := range row {
			if c, err := tgui.Decode(b.Data); err == nil && c.Act != tgui.ActView {
				acts = append(acts, c.Act+"|"+strings.Join(c.Args, "|"))
			} else if err == nil && (c.Args[0] == scrUnitLogs || c.Args[0] == scrContainerLogs) {
				acts = append(acts, "logs")
			}
		}
	}
	return acts
}

// lastEditText is the text of the last edit, "" when there is none.
func lastEditText(send *fakeSender) string {
	send.mu.Lock()
	defer send.mu.Unlock()
	if len(send.edits) == 0 {
		return ""
	}
	return send.edits[len(send.edits)-1].html
}

// tokenless is a keyboard dump with the confirm token left out, which
// differs on every run.
func tokenless(kb telegram.Keyboard) telegram.Keyboard {
	out := telegram.Keyboard{}
	for _, row := range kb {
		var r []telegram.Button
		for _, b := range row {
			if strings.HasPrefix(b.Data, "~1y|") || strings.HasPrefix(b.Data, "~1n|") {
				b.Data = b.Data[:4] + "<token>"
			}
			r = append(r, b)
		}
		out = append(out, r)
	}
	return out
}

func TestGoldenServiceActions(t *testing.T) {
	ctx := context.Background()
	a, send, r, engine := actionAgent(t)
	a.src.SelfContainer = apiID
	r.logs = "2026-10-15T14:03:00+0000 web-01 postgres[412]: FATAL: <could not> bind & listen\n" +
		"2026-10-15T14:03:01+0000 web-01 systemd[1]: postgresql.service: Failed with result 'exit-code'.\n"
	engine.logs = "listening on :8080\npanic: <nil> map & more\n"
	for _, tc := range []struct {
		name string
		c    tgui.Call
	}{
		{"unit", unitDetail("postgresql.service")},
		{"unit_denied", unitDetail("statix-agent.service")},
		{"unit_not_allowed", unitDetail("cron.service")},
		{"container", containerDetail(webID)},
		{"container_self", containerDetail(apiID)},
		{"unit_logs", tgui.Call{Act: tgui.ActView, Args: []string{scrUnitLogs, callbackDigest("postgresql.service")}, From: scrUnitsWatched}},
		{"container_logs", tgui.Call{Act: tgui.ActView, Args: []string{scrContainerLogs, webID[:shortIDLen]}, From: scrDocker}},
		{"logs_gone", tgui.Call{Act: tgui.ActView, Args: []string{scrUnitLogs, callbackDigest("vanished.service")}}},
	} {
		text, kb := a.screen(ctx, tc.c)
		checkGolden(t, "svaction__"+tc.name, text, kb)
		checkButtons(t, a, tc.name, kb, a.ui.Screens())
	}
	for _, tc := range []struct{ name, ask string }{
		{"confirm_restart", unitAsk(services.VerbRestart, "postgresql.service")},
		{"confirm_container_stop", containerAsk(services.VerbStop, webID)},
		{"refused", unitAsk(services.VerbStop, "dbus.service")},
	} {
		press(a, tc.name, tc.ask)
		checkGolden(t, "svaction__"+tc.name, lastEditText(send), tokenless(lastEditKB(send)))
	}
	press(a, "ask", unitAsk(services.VerbStop, "ssh.service"))
	press(a, "yes", tokenData(lastEditKB(send), tgui.ActYes))
	checkGolden(t, "svaction__confirm_ssh_final", lastEditText(send), tokenless(lastEditKB(send)))
}

// Off by default: no detail screen offers an action or logs, and a forged
// press is refused, audited, and runs nothing.
func TestServiceActionsOffByDefault(t *testing.T) {
	ctx := context.Background()
	a, send, r, engine := actionAgent(t)
	a.cfg.Actions = config.Default().Actions
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	a.audit = newAuditLog(path)
	for _, c := range []tgui.Call{unitDetail("postgresql.service"), unitDetail("nginx.service"), containerDetail(webID)} {
		if _, kb := a.screen(ctx, c); len(actsOf(kb)) > 0 {
			t.Errorf("%v offers %v with actions off", c.Args, actsOf(kb))
		}
	}
	for _, data := range []string{unitAsk(services.VerbRestart, "nginx.service"), containerAsk(services.VerbStop, webID)} {
		press(a, "forged", data)
		if text := lastEditText(send); !strings.Contains(text, "Service actions are off") || tokenData(lastEditKB(send), tgui.ActYes) != "" {
			t.Errorf("%s: %q, want refused", data, text)
		}
	}
	text, _ := a.screen(ctx, tgui.Call{Act: tgui.ActView, Args: []string{scrUnitLogs, callbackDigest("nginx.service")}})
	if !strings.Contains(text, "Service actions are off") {
		t.Errorf("logs with actions off: %q", text)
	}
	if r.ran("journalctl") || len(r.queued()) > 0 || len(engine.posts) > 0 {
		t.Errorf("ran %v, posted %v", r.runs, engine.posts)
	}
	if phases := auditPhases(t, path); !slices.Equal(phases, []string{phaseDenied, phaseDenied}) {
		t.Errorf("audit phases %v", phases)
	}
}

// auditPhases reads the phases of the audit file at path.
func auditPhases(t *testing.T, path string) []string {
	t.Helper()
	var phases []string
	for _, r := range auditRecords(t, path) {
		phases = append(phases, r.Phase)
	}
	return phases
}

func auditRecords(t *testing.T, path string) []auditRecord {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var recs []auditRecord
	for line := range strings.SplitSeq(strings.TrimSpace(string(raw)), "\n") {
		var r auditRecord
		if err := json.Unmarshal([]byte(line), &r); err != nil {
			t.Fatalf("line %q: %v", line, err)
		}
		recs = append(recs, r)
	}
	return recs
}

// The always-denied targets are never offered, whatever actions.allow
// says, and a forged press on one is refused.
func TestServiceActionDenyList(t *testing.T) {
	ctx := context.Background()
	for _, tc := range []struct {
		name   string
		detail tgui.Call
		ask    func(verb string) string
	}{
		{"agent", unitDetail("statix-agent.service"), func(v string) string { return unitAsk(v, "statix-agent.service") }},
		{"dbus", unitDetail("dbus.service"), func(v string) string { return unitAsk(v, "dbus.service") }},
		{"systemd", unitDetail("systemd-journald.service"), func(v string) string { return unitAsk(v, "systemd-journald.service") }},
		{"self container", containerDetail(apiID), func(v string) string { return containerAsk(v, apiID) }},
	} {
		a, send, r, engine := actionAgent(t)
		a.src.SelfContainer = apiID
		path := filepath.Join(t.TempDir(), "audit.jsonl")
		a.audit = newAuditLog(path)
		_, kb := a.screen(ctx, tc.detail)
		if acts := actsOf(kb); !slices.Equal(acts, []string{"logs"}) {
			t.Errorf("%s: detail offers %v, want logs only", tc.name, acts)
		}
		for _, verb := range svVerbs {
			press(a, "forged", tc.ask(verb))
			if text := lastEditText(send); !strings.Contains(text, "⛔ <b>Refused</b>") || tokenData(lastEditKB(send), tgui.ActYes) != "" {
				t.Errorf("%s %s: %q, want refused", tc.name, verb, text)
			}
		}
		if len(r.queued()) > 0 || len(engine.posts) > 0 {
			t.Errorf("%s: queued %v, posted %v", tc.name, r.queued(), engine.posts)
		}
		for _, rec := range auditRecords(t, path) {
			if rec.Phase != phaseDenied {
				t.Errorf("%s: audit %+v, want denied only", tc.name, rec)
			}
		}
	}
}

// actions.allow decides what is offered; empty, it means the watched
// units and no container.
func TestServiceActionAllowList(t *testing.T) {
	ctx := context.Background()
	for _, tc := range []struct {
		name    string
		allow   []string
		offered map[string]bool // by detail
	}{
		{"default: watched units", nil, map[string]bool{"nginx.service": true, "postgresql.service": false, "web": false}},
		{"named", []string{"postgresql.service", "web"}, map[string]bool{"nginx.service": false, "postgresql.service": true, "web": true}},
		{"bare unit name", []string{"postgresql"}, map[string]bool{"postgresql.service": true, "web": false}},
	} {
		a, send, r, engine := actionAgent(t)
		a.cfg.Actions.Allow = tc.allow
		for name, want := range tc.offered {
			c, ask := unitDetail(name), unitAsk(services.VerbRestart, name)
			if name == "web" {
				c, ask = containerDetail(webID), containerAsk(services.VerbRestart, webID)
			}
			_, kb := a.screen(ctx, c)
			if got := len(actsOf(kb)) > 0; got != want {
				t.Errorf("%s: %s offered %v, want %v", tc.name, name, actsOf(kb), want)
			}
			press(a, "ask", ask)
			if got := tokenData(lastEditKB(send), tgui.ActYes) != ""; got != want {
				t.Errorf("%s: %s asked = %v (%q), want %v", tc.name, name, got, lastEditText(send), want)
			}
		}
		if len(r.queued()) > 0 || len(engine.posts) > 0 {
			t.Errorf("%s: acted before any Yes", tc.name)
		}
	}
}

// Malformed presses never reach a confirm screen, and a name or ID that
// is not one the bot hands on is refused.
func TestServiceActionValidation(t *testing.T) {
	d := callbackDigest("nginx.service")
	for _, tc := range []struct {
		data, toast string
	}{
		{"~1ua|enable|" + d, outdatedToast},
		{"~1ua|disable|" + d, outdatedToast},
		{"~1ua|reload|" + d, outdatedToast},
		{"~1ua|restart|" + d[:15], outdatedToast},
		{"~1ua|restart|" + strings.ToUpper(d), outdatedToast},
		{"~1ua|restart", outdatedToast},
		{"~1ua|restart|" + d + "|x", outdatedToast},
		{"~1ua|restart|nginx.service", outdatedToast},
		{"~1ca|restart|web", outdatedToast},
		{"~1ca|restart|" + webID, outdatedToast},
		{"~1ca|kill|" + webID[:12], outdatedToast},
		{"~1ca|restart|" + strings.ToUpper(webID[:12]), outdatedToast},
		{unitAsk(services.VerbRestart, "vanished.service"), itemGoneToast},
		{containerAsk(services.VerbRestart, "0123456789ab"), itemGoneToast},
		{unitAsk(services.VerbRestart, "x<evil>&.service"), "Refused"},
	} {
		a, send, r, engine := actionAgent(t)
		press(a, "p", tc.data)
		if !slices.Equal(send.answered, []string{"p:" + tc.toast}) || tokenData(lastEditKB(send), tgui.ActYes) != "" {
			t.Errorf("%s: answered %v, want %q and no Yes", tc.data, send.answered, tc.toast)
		}
		if len(r.queued()) > 0 || len(engine.posts) > 0 {
			t.Errorf("%s: acted", tc.data)
		}
	}
}

// A Yes runs the action on the item found again, by argv or by the fixed
// Docker template, and leaves a receipt.
func TestServiceActionRuns(t *testing.T) {
	for _, tc := range []struct {
		ask     string
		job     []string // systemctl argv, or
		post    string   // the Docker request
		receipt string
	}{
		{unitAsk(services.VerbRestart, "nginx.service"),
			[]string{"systemctl", "--no-ask-password", "--no-block", "restart", "--", "nginx.service"}, "", "🧾 Restarted · unit nginx.service"},
		{unitAsk(services.VerbStop, "postgresql.service"),
			[]string{"systemctl", "--no-ask-password", "--no-block", "stop", "--", "postgresql.service"}, "", "🧾 Stopped · unit postgresql.service"},
		{unitAsk(services.VerbStart, "ssh.service"),
			[]string{"systemctl", "--no-ask-password", "--no-block", "start", "--", "ssh.service"}, "", "🧾 Started · unit ssh.service"},
		{containerAsk(services.VerbRestart, webID), nil, "/containers/" + webID + "/restart?t=10", "🧾 Restarted · container web"},
		{containerAsk(services.VerbStart, apiID), nil, "/containers/" + apiID + "/start", "🧾 Started · container api"},
	} {
		a, send, r, engine := actionAgent(t)
		confirmThrough(t, a, send, tc.ask, 7)
		var jobs [][]string
		if tc.job != nil {
			jobs = [][]string{tc.job}
		}
		if got := r.queued(); !slices.EqualFunc(got, jobs, slices.Equal) {
			t.Errorf("%s: queued %q, want %q", tc.ask, got, jobs)
		}
		var posts []string
		if tc.post != "" {
			posts = []string{tc.post}
		}
		if !slices.Equal(engine.posts, posts) {
			t.Errorf("%s: posted %q, want %q", tc.ask, engine.posts, posts)
		}
		if text := lastEditText(send); !strings.HasPrefix(text, tc.receipt) || !strings.HasSuffix(strings.SplitN(text, "\n", 2)[0], "· ok") {
			t.Errorf("%s: %q, want receipt %q", tc.ask, text, tc.receipt)
		}
	}
}

// Stopping or restarting what remote access depends on takes a second
// Yes, on a screen that reads differently.
func TestServiceActionDoubleConfirm(t *testing.T) {
	for _, tc := range []struct {
		unit, verb string
		double     bool
	}{
		{"ssh.service", services.VerbStop, true},
		{"ssh.service", services.VerbRestart, true},
		{"ssh.service", services.VerbStart, false},
		{"docker.service", services.VerbRestart, true},
		{"docker.service", services.VerbStop, true},
		{"nginx.service", services.VerbStop, false},
		{"nginx.service", services.VerbRestart, false},
	} {
		a, send, r, _ := actionAgent(t)
		press(a, "ask", unitAsk(tc.verb, tc.unit))
		first := lastEditText(send)
		last := confirmThrough(t, a, send, unitAsk(tc.verb, tc.unit), 4)
		if want := map[bool]string{false: "yes1", true: "yes2"}[tc.double]; last != want {
			t.Errorf("%s %s: last Yes %s, want %s", tc.verb, tc.unit, last, want)
		}
		if len(r.queued()) != 1 {
			t.Errorf("%s %s: queued %v", tc.verb, tc.unit, r.queued())
		}
		if !tc.double {
			continue
		}
		var second string
		send.mu.Lock()
		for _, e := range send.edits {
			if strings.Contains(e.html, "Last check") {
				second = e.html
			}
		}
		send.mu.Unlock()
		if second == "" || strings.Contains(first, "Last check") {
			t.Errorf("%s %s: first %q, second %q; want different wording", tc.verb, tc.unit, first, second)
		}
	}
}

// One action at a time on an item: a Yes while one runs is answered
// "Already running" and runs nothing.
func TestServiceActionLock(t *testing.T) {
	a, send, r, engine := actionAgent(t)
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	a.audit = newAuditLog(path)
	key := "unit:" + callbackDigest("nginx.service")
	if !a.locks.tryLock(key) {
		t.Fatal("lock taken")
	}
	confirmThrough(t, a, send, unitAsk(services.VerbRestart, "nginx.service"), 4)
	if !slices.Contains(send.answered, "yes1:"+runningToast) || len(r.queued()) > 0 {
		t.Errorf("answered %v, queued %v; want Already running and nothing run", send.answered, r.queued())
	}
	// Other items are not held.
	confirmThrough(t, a, send, containerAsk(services.VerbRestart, webID), 4)
	if len(engine.posts) != 1 {
		t.Errorf("posts %v, want the container restarted", engine.posts)
	}
	a.locks.unlock(key)
	confirmThrough(t, a, send, unitAsk(services.VerbRestart, "nginx.service"), 4)
	if len(r.queued()) != 1 {
		t.Errorf("queued %v after the lock was released", r.queued())
	}
	if a.locks.tryLock(key) {
		a.locks.unlock(key)
	} else {
		t.Error("the action kept its lock")
	}
	want := []string{phaseRequested, phaseConfirmed, phaseDenied, phaseRequested, phaseConfirmed, phaseExecuted, phaseRequested, phaseConfirmed, phaseExecuted}
	if phases := auditPhases(t, path); !slices.Equal(phases, want) {
		t.Errorf("audit phases %v, want %v", phases, want)
	}
}

// Logs never show the bot token, raw or in a URL, and stay one message.
func TestServiceLogsRedacted(t *testing.T) {
	ctx := context.Background()
	a, _, r, engine := actionAgent(t)
	leak := "token=" + secretToken + " url=https://api.telegram.org/bot" + secretToken + "/getUpdates \x1b[31m<b>red</b>\x1b[0m &\x00\n"
	var long strings.Builder
	for i := range 400 {
		fmt.Fprintf(&long, "2026-10-15T14:03:00+0000 web-01 app[1]: line %d %s\n", i, strings.Repeat("x", 80))
	}
	r.logs = long.String() + leak
	engine.logs = leak + "last line\n"
	for _, c := range []tgui.Call{
		{Act: tgui.ActView, Args: []string{scrUnitLogs, callbackDigest("nginx.service")}},
		{Act: tgui.ActView, Args: []string{scrContainerLogs, webID[:shortIDLen]}},
	} {
		text, _ := a.screen(ctx, c)
		for _, secret := range []string{secretToken, "AAH-s3cret", "\x1b", "\x00", "<b>red"} {
			if strings.Contains(text, secret) {
				t.Errorf("%s: logs show %q:\n%s", c.Args[0], secret, text)
			}
		}
		if !strings.Contains(text, "&lt;b&gt;red") {
			t.Errorf("%s: logs lost the escaped line:\n%s", c.Args[0], text)
		}
		if fitted := telegram.FitEdit(text); fitted != text || checkTelegramHTML(text) != nil {
			t.Errorf("%s: %d bytes, cut or invalid", c.Args[0], len(text))
		}
	}
	text, _ := a.screen(ctx, tgui.Call{Act: tgui.ActView, Args: []string{scrUnitLogs, callbackDigest("nginx.service")}})
	if strings.Contains(text, "line 0 ") || !strings.Contains(text, "line 399") {
		t.Error("logs keep the oldest lines instead of the newest")
	}
}

// The audit log records each phase of an action, with its command.
func TestServiceActionAudit(t *testing.T) {
	a, send, _, _ := actionAgent(t)
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	a.audit = newAuditLog(path)
	confirmThrough(t, a, send, unitAsk(services.VerbRestart, "nginx.service"), 4)
	confirmThrough(t, a, send, containerAsk(services.VerbStop, webID), 4)
	press(a, "c", unitAsk(services.VerbStop, "nginx.service"))
	press(a, "cancel", tokenData(lastEditKB(send), tgui.ActNo))
	press(a, "denied", unitAsk(services.VerbStop, "statix-agent.service"))
	recs := auditRecords(t, path)
	var got []string
	for _, r := range recs {
		got = append(got, r.Phase+" "+r.Action)
	}
	want := []string{
		"requested unit_restart", "confirmed unit_restart", "executed unit_restart",
		"requested container_stop", "confirmed container_stop", "executed container_stop",
		"requested unit_stop", "cancelled unit_stop", "denied unit_stop",
	}
	if !slices.Equal(got, want) {
		t.Fatalf("audit %v, want %v", got, want)
	}
	if r := recs[2]; r.Target != "unit nginx.service" || !slices.Equal(r.Argv, []string{"systemctl", "--no-ask-password", "--no-block", "restart", "--", "nginx.service"}) ||
		r.ExitCode == nil || *r.ExitCode != 0 || r.OutputHead != "ActiveState=active" {
		t.Errorf("unit record %+v", r)
	}
	if r := recs[5]; r.Target != "container web" || !slices.Equal(r.Argv, []string{"POST", "/containers/" + webID + "/stop?t=10"}) {
		t.Errorf("container record %+v", r)
	}
	if r := recs[8]; r.Target != callbackDigest("statix-agent.service") || r.ActorID != 42 {
		t.Errorf("denied record %+v", r)
	}
}
