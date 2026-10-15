package agent

import (
	"context"
	"fmt"
	"regexp"
	"slices"
	"strings"
	"sync"
	"time"
	"unicode"

	"github.com/eliau2005/statixagent/internal/dockermon"
	"github.com/eliau2005/statixagent/internal/services"
	"github.com/eliau2005/statixagent/internal/telegram"
	"github.com/eliau2005/statixagent/internal/tgui"
)

// Service actions (docs/telegram-ux-redesign.md §3.3, §6; Decisions 5
// and 6): start, stop and restart of a unit or container, and its logs,
// from its detail screen. They are off until [actions] enabled is set,
// and then offered only for the items [actions] allow names (by default
// the watched units). A few targets are always refused, offered or not:
// the agent itself, D-Bus, systemd's own units and targets, and the
// agent's own container.
//
// Every action is an ask act that opens a confirm token; the Yes runs it
// only after the item is found again in a fresh listing and passes the
// same checks. Stopping or restarting a unit that remote access depends
// on is confirmed twice. One action at a time runs on each item.

// Ask acts of the service actions; the verb is services.VerbStart, Stop
// or Restart.
const (
	askUnitAct      = "ua" // ua|<verb>|<unit name digest>
	askContainerAct = "ca" // ca|<verb>|<short container ID>
)

// svVerbs are the actions, in button order.
var svVerbs = []string{services.VerbStart, services.VerbRestart, services.VerbStop}

// verbText is how one verb reads on buttons and screens.
type verbText struct {
	button, title, yes, done, failed string
	// effect is what the confirm screen warns of.
	effect string
}

var verbTexts = map[string]verbText{
	services.VerbStart: {button: "▶️ Start", title: "▶️ <b>Start %s?</b>", yes: "✅ Yes, start",
		done: "Started", failed: "Start failed", effect: "It starts with its current configuration."},
	services.VerbRestart: {button: "🔁 Restart", title: "⚠️ <b>Restart %s?</b>", yes: "✅ Yes, restart",
		done: "Restarted", failed: "Restart failed", effect: "Active connections will drop."},
	services.VerbStop: {button: "⏹ Stop", title: "⚠️ <b>Stop %s?</b>", yes: "✅ Yes, stop",
		done: "Stopped", failed: "Stop failed", effect: "It stays down until started again, and whatever uses it fails."},
}

// Answers and texts of the service actions.
const (
	expiresLine   = "Expires in 2 min."
	notAllowed    = "Not allowed any more, refreshed"
	actionsOffMsg = "Service actions are off. Turn them on with <code>[actions] enabled = true</code> in the config."
	// logChars bounds the log text shown, newest lines kept (docs §6:
	// about 3,000 characters, before escaping and wrapping).
	logChars = 2500
)

// svTarget is a unit or container an action names, found again in a
// fresh listing.
type svTarget struct {
	it svItem
	// full is a container's full ID; "" for a unit.
	full string
}

// actKind is what the actions need to know of units or containers.
type actKind struct {
	kind         string // watchUnit or svDocker
	noun         string // "unit", "container", for the audit target
	list, detail string // screens
	logs         string // the logs screen
	ask          string // the ask act
	// find lists the items afresh and returns the one with ID id.
	find func(a *Agent, ctx context.Context, id string) (svTarget, bool)
	// act runs verb on t; the trace is for the audit log.
	act func(a *Agent, ctx context.Context, t svTarget, verb string) (*cmdTrace, error)
	// logText reads t's recent logs.
	logText func(a *Agent, ctx context.Context, t svTarget) (string, error)
}

var (
	unitActs = actKind{kind: watchUnit, noun: "unit", list: scrUnits, detail: scrUnit, logs: scrUnitLogs, ask: askUnitAct,
		find: (*Agent).findUnit, act: (*Agent).actUnit, logText: (*Agent).unitLogs}
	containerActs = actKind{kind: svDocker, noun: "container", list: scrDocker, detail: scrContainer, logs: scrContainerLogs,
		ask: askContainerAct, find: (*Agent).findContainer, act: (*Agent).actContainer, logText: (*Agent).containerLogs}
)

// actionID is the confirm action of verb on k, as the audit log records
// it: "unit_restart", "container_stop".
func (k actKind) actionID(verb string) string { return k.noun + "_" + verb }

// detailCall opens the detail screen of the item with ID id, from list.
func (k actKind) detailCall(id, list string) tgui.Call {
	return tgui.Call{Act: tgui.ActView, Args: []string{k.detail, id}, From: listFrom(list)}
}

// listFrom is from when it is one of the lists a detail screen opens
// from, else "". A logs screen carries its detail's From, so that its
// Back returns to the detail as it was opened.
func listFrom(from string) string {
	if slices.Contains([]string{scrUnits, scrUnitsWatched, scrFailing, scrDocker}, from) {
		return from
	}
	return ""
}

// ---- policy ----

// allowed reports whether [actions] allow names it; an empty list means
// the watched units and no container.
func (a *Agent) allowed(it svItem) bool {
	allow := a.cfg.Actions.Allow
	if len(allow) == 0 {
		return it.kind == watchUnit && it.watched
	}
	return slices.ContainsFunc(allow, func(e string) bool {
		if it.kind == watchUnit {
			return unitName(e) == it.name
		}
		return e == it.name
	})
}

// selfContainer reports whether full is the agent's own container.
func (a *Agent) selfContainer(full string) bool {
	self := a.src.SelfContainer
	return self != "" && full != "" && (strings.HasPrefix(self, full) || strings.HasPrefix(full, self))
}

// refusal says why t cannot be acted on, as HTML, or "" when it can.
// logs asks for its logs only, which only reads: the always-denied list
// does not apply.
func (a *Agent) refusal(t svTarget, logs bool) string {
	it := t.it
	switch {
	case !a.cfg.Actions.Enabled:
		return actionsOffMsg
	case it.kind == watchUnit && (it.status == "not found" || !services.ValidUnitName(it.name)):
		return "systemd has no unit by this name the bot can act on."
	case it.kind == svDocker && t.full == "":
		return "This container has no ID the bot can act on."
	case !logs && it.kind == watchUnit && services.ActionDenied(it.name):
		return "The bot never acts on itself, D-Bus or systemd's own units."
	case !logs && it.kind == svDocker && a.selfContainer(t.full):
		return "This is the agent's own container."
	case !a.allowed(it) && len(a.cfg.Actions.Allow) == 0 && it.kind == watchUnit:
		return "Only watched units can be acted on. Watch it, or name it in <code>[actions] allow</code>."
	case !a.allowed(it):
		return "It is not named in <code>[actions] allow</code>."
	}
	return ""
}

// actionRows are the Logs and action buttons of an item's detail screen
// (§3.3), opened by c; none unless actions are enabled and allow it. extra
// joins the last row.
func (a *Agent) actionRows(k actKind, t svTarget, c tgui.Call, extra ...tgui.Button) [][]tgui.Button {
	if a.refusal(t, true) != "" {
		return nil
	}
	logs := tgui.Button{Label: "📄 Logs", Call: tgui.Call{Act: tgui.ActView, Args: []string{k.logs, t.it.id}, From: listFrom(c.From)}}
	if a.refusal(t, false) != "" {
		return [][]tgui.Button{append([]tgui.Button{logs}, extra...)}
	}
	btn := func(verb string) tgui.Button {
		return tgui.Button{Label: verbTexts[verb].button, Call: tgui.Call{Act: k.ask, Args: []string{verb, t.it.id}}}
	}
	return [][]tgui.Button{
		{logs, btn(services.VerbStart), btn(services.VerbRestart)},
		append([]tgui.Button{btn(services.VerbStop)}, extra...),
	}
}

// ---- finding and acting ----

func (a *Agent) findUnit(ctx context.Context, id string) (svTarget, bool) {
	items, err := a.unitItems(ctx)
	if err != nil {
		return svTarget{}, false
	}
	i := slices.IndexFunc(items, func(it svItem) bool { return it.id == id })
	if i < 0 {
		return svTarget{}, false
	}
	return svTarget{it: items[i]}, true
}

func (a *Agent) findContainer(ctx context.Context, id string) (svTarget, bool) {
	cts, err := a.containers(ctx)
	if err != nil {
		return svTarget{}, false
	}
	items := containerItemsOf(cts)
	i := slices.IndexFunc(items, func(it svItem) bool { return it.id != "" && it.id == id })
	if i < 0 {
		return svTarget{}, false
	}
	return svTarget{it: items[i], full: cts[i].ID}, true
}

func (a *Agent) actUnit(ctx context.Context, t svTarget, verb string) (*cmdTrace, error) {
	start := time.Now()
	o, err := services.ActUnit(ctx, a.src.Runner, verb, t.it.name)
	trace := &cmdTrace{argv: o.Argv, out: o.Out, err: err, dur: time.Since(start)}
	if o.State != "" {
		trace.out = strings.TrimSpace(o.Out + "\nActiveState=" + o.State)
	}
	// systemctl's own words say more than "exit status 1".
	if out := strings.TrimSpace(o.Out); err != nil && out != "" {
		err = fmt.Errorf("%s (%w)", out, err)
	}
	return trace, err
}

func (a *Agent) actContainer(ctx context.Context, t svTarget, verb string) (*cmdTrace, error) {
	path, _ := dockermon.ActionPath(t.full, verb)
	start := time.Now()
	err := a.src.Docker.Act(ctx, t.full, verb)
	trace := &cmdTrace{argv: []string{"POST", path}, err: err, dur: time.Since(start)}
	if err != nil {
		trace.out = err.Error()
	}
	return trace, err
}

func (a *Agent) unitLogs(ctx context.Context, t svTarget) (string, error) {
	return services.UnitLogs(ctx, a.src.Runner, t.it.name)
}

func (a *Agent) containerLogs(ctx context.Context, t svTarget) (string, error) {
	return a.src.Docker.Logs(ctx, t.full)
}

// ---- the confirm actions ----

// serviceAsks registers the ask acts of the service actions. They only
// check the shape of the press: the item, the policy and the deny-list
// are checked by the confirm screen, from fresh state.
func (a *Agent) serviceAsks() map[string]askAction {
	ask := func(k actKind, idOK func(string) bool) askAction {
		return askAction{class: tgui.ClassMutate, resolve: func(args []string) (string, string, bool) {
			if len(args) != 2 || !services.ValidVerb(args[0]) || !idOK(args[1]) {
				return "", "", false
			}
			return k.actionID(args[0]), args[1], true
		}}
	}
	return map[string]askAction{
		askUnitAct:      ask(unitActs, func(id string) bool { return len(id) == fingerprint && isHex(id) }),
		askContainerAct: ask(containerActs, func(id string) bool { return len(id) == shortIDLen && isHex(id) }),
	}
}

// serviceConfirms registers a confirm action per kind and verb.
func (a *Agent) serviceConfirms() map[string]confirmAction {
	m := map[string]confirmAction{}
	for _, k := range []actKind{unitActs, containerActs} {
		for _, verb := range svVerbs {
			m[k.actionID(verb)] = a.serviceAction(k, verb)
		}
	}
	return m
}

// serviceAction is verb on an item of kind k; the confirm target is the
// item's ID.
func (a *Agent) serviceAction(k actKind, verb string) confirmAction {
	vt := verbTexts[verb]
	list := func(ctx context.Context) (string, telegram.Keyboard) { return a.screen(ctx, tgui.Open(k.list)) }
	detail := func(ctx context.Context, id string) (string, telegram.Keyboard) {
		return a.screen(ctx, k.detailCall(id, k.list))
	}
	// refused is the refusal screen: no Refresh, which would only refuse
	// again (principle 3).
	refused := func(name, id, why string) confirmPrompt {
		back := tgui.Open(k.list)
		head := "⛔ <b>Refused</b>"
		if name != "" {
			back, head = k.detailCall(id, k.list), "⛔ <b>Refused</b> · "+esc(truncate(name, 64))
		}
		text, kb := encodeView(tgui.View{Text: head + "\n" + why, Rows: [][]tgui.Button{{
			{Label: "⬅️ Back", Call: back}, {Label: "🏠 Home", Call: tgui.Open(scrHome)}}}})
		return confirmPrompt{text: text, kb: kb, toast: "Refused", denied: true}
	}
	return confirmAction{
		back: k.list, backLabel: map[string]string{watchUnit: "🧩 Units", svDocker: "🐳 Docker"}[k.kind],
		prompt: func(ctx context.Context, id string, final bool) confirmPrompt {
			if !a.cfg.Actions.Enabled {
				return refused("", id, actionsOffMsg)
			}
			t, ok := k.find(a, ctx, id)
			if !ok {
				text, kb := list(ctx)
				return confirmPrompt{text: text, kb: kb, toast: itemGoneToast}
			}
			if why := a.refusal(t, false); why != "" {
				return refused(t.it.name, id, why)
			}
			name := esc(truncate(t.it.name, 64))
			if final {
				return confirmPrompt{text: "⚠️ <b>Last check: " + verb + " " + name + "?</b>\n" +
					lockoutWarning(t.it.name) + "\n" + expiresLine, yes: "✅ Yes, " + verb + " it anyway"}
			}
			return confirmPrompt{text: fmt.Sprintf(vt.title, name) + "\n" + vt.effect + "\n" + expiresLine, yes: vt.yes}
		},
		double: func(ctx context.Context, id string) bool {
			if verb == services.VerbStart || k.kind != watchUnit {
				return false
			}
			t, ok := k.find(a, ctx, id)
			return ok && services.LockoutRisk(t.it.name)
		},
		run: func(ctx context.Context, id string) actionResult {
			t, ok := k.find(a, ctx, id)
			if !ok {
				text, kb := list(ctx)
				return actionResult{drift: true, driftToast: itemGoneToast, text: text, kb: kb}
			}
			if a.refusal(t, false) != "" {
				text, kb := detail(ctx, id)
				return actionResult{drift: true, driftToast: notAllowed, text: text, kb: kb}
			}
			trace, err := k.act(a, ctx, t, verb)
			res := actionResult{ok: err == nil, what: vt.done, target: k.noun + " " + t.it.name, trace: trace}
			res.text, res.kb = detail(ctx, id)
			if err != nil {
				res.what = vt.failed
				res.text = "❌ <b>" + vt.failed + "</b>\n<pre>" + esc(truncate(a.redactOutput(err.Error()), 300)) + "</pre>\n" + res.text
			}
			return res
		},
		cancel: list,
		view:   detail,
		lock:   func(id string) string { return k.noun + ":" + id },
	}
}

// lockoutWarning is the second confirm's consequence for a unit that
// remote access depends on.
func lockoutWarning(unit string) string {
	base, _, _ := strings.Cut(unit, ".")
	base, _, _ = strings.Cut(base, "@")
	switch base {
	case "ssh", "sshd":
		return "New SSH logins fail until it is back. If it does not come back, only this bot can start it again."
	case "docker", "containerd":
		return "Every container on this host goes down with it."
	}
	return "The server may drop off the network, and this bot with it, until it is back."
}

// ---- logs ----

// addLogScreens registers the logs screens. Their Back leads to the
// item's detail, which a plain footer cannot name: it carries the ID.
func (a *Agent) addLogScreens(r *tgui.Registry) {
	for _, k := range []actKind{unitActs, containerActs} {
		r.AddScreen(tgui.Screen{ID: k.logs, Parent: k.detail, Slow: true, Render: func(ctx context.Context, c tgui.Call) tgui.View {
			v, found := a.logsView(ctx, k, c)
			back := tgui.Open(k.list)
			if found {
				back = k.detailCall(c.Args[1], c.From)
			}
			refresh := c
			refresh.Act = tgui.ActView
			v.Rows = append(v.Rows, []tgui.Button{{Label: "⬅️ Back", Call: back},
				{Label: "🏠 Home", Call: tgui.Open(scrHome)}, {Label: "🔄 Refresh", Call: refresh}})
			return v
		}})
	}
}

// logsView is the last lines of the item c names (its second argument);
// found is false when no such item is listed.
func (a *Agent) logsView(ctx context.Context, k actKind, c tgui.Call) (v tgui.View, found bool) {
	if !a.cfg.Actions.Enabled {
		return tgui.View{Text: "⛔ <b>Logs</b>\n" + actionsOffMsg}, false
	}
	var t svTarget
	if len(c.Args) == 2 {
		t, found = k.find(a, ctx, c.Args[1])
	}
	if !found {
		return tgui.View{Text: itemGoneBanner}, false
	}
	head := "📄 <b>Logs · " + esc(truncate(t.it.name, 64)) + "</b>"
	if why := a.refusal(t, true); why != "" {
		return tgui.View{Text: "⛔ " + head + "\n" + why}, true
	}
	out, err := k.logText(a, ctx, t)
	if err != nil {
		return tgui.View{Text: head + "\nCould not read logs: " + esc(truncate(a.redactOutput(detail(out, err)), 200))}, true
	}
	return tgui.View{Text: head + "\n" + a.logBlock(out)}, true
}

// ansiRE matches terminal colour and cursor sequences.
var ansiRE = regexp.MustCompile(`\x1b\[[0-9;?]*[A-Za-z]`)

// logBlock renders log output for a screen: the bot token redacted,
// control characters dropped, the newest lines that fit in logChars kept,
// escaped and wrapped to a phone's width.
func (a *Agent) logBlock(out string) string {
	out = a.redactOutput(strings.ToValidUTF8(out, "?"))
	out = strings.Map(func(r rune) rune {
		switch {
		case r == '\n':
			return r
		case r == '\t':
			return ' '
		case unicode.IsControl(r):
			return -1
		}
		return r
	}, ansiRE.ReplaceAllString(out, ""))
	out = strings.TrimRight(out, "\n ")
	if strings.TrimSpace(out) == "" {
		return "<pre>(no output)</pre>"
	}
	lines := strings.Split(out, "\n")
	var kept []string
	n := 0
	for i := len(lines) - 1; i >= 0; i-- {
		line := truncate(lines[i], 300)
		if n += len(line) + 1; n > logChars && len(kept) > 0 {
			break
		}
		kept = append(kept, line)
	}
	slices.Reverse(kept)
	return pre(kept)
}

// targetLocks holds the resources actions run on, one action each.
type targetLocks struct {
	mu   sync.Mutex
	held map[string]bool
}

// tryLock takes key, or reports false when an action already holds it.
func (l *targetLocks) tryLock(key string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.held[key] {
		return false
	}
	if l.held == nil {
		l.held = map[string]bool{}
	}
	l.held[key] = true
	return true
}

func (l *targetLocks) unlock(key string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	delete(l.held, key)
}
