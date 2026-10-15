package agent

import (
	"context"
	"log"
	"slices"
	"strings"
	"time"

	"github.com/eliau2005/statixagent/internal/alert"
	"github.com/eliau2005/statixagent/internal/services"
	"github.com/eliau2005/statixagent/internal/telegram"
	"github.com/eliau2005/statixagent/internal/tgui"
)

// Alerts for watched checks (docs/telegram-ux-redesign.md PR 19): the
// watched units, ports, HTTP checks and processes were only shown when
// asked, so servicesLoop checks them once a minute and alerts when one
// starts failing and when it recovers, never while it stays as it was.
// The first look at a check only records its state, so a restart does
// not repeat every failure already known. Firing, cooldown and snooze
// are the alert engine's (Engine.Check).
//
// The alert keys are short and stable: svc:<unit>, port:<n>,
// http:<digest of the URL> and proc:<name>. An alert carries [🔍 Open],
// the item's detail or list as a new message, and for a unit that
// service actions allow, [🔁 Restart], which opens a confirm token in a
// new message: the alert itself stays as it was sent.

// Alert key prefixes of the watched checks.
const (
	keyUnit = "svc"
	keyPort = "port"
	keyHTTP = "http"
	keyProc = "proc"
)

// fromAlert is the From of an ask act pressed on an alert: its confirm
// opens in a new message replying to the alert.
const fromAlert = "al"

// servicesLoop checks the watched items while the agent runs.
func (a *Agent) servicesLoop(ctx context.Context) {
	tick := time.NewTicker(a.servicesPoll)
	defer tick.Stop()
	a.checkServices(ctx) // seed the baseline immediately
	for {
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
			a.checkServices(ctx)
		}
	}
}

// checkServices checks every watched item once and pushes the alerts of
// those that started failing or recovered. An item seen for the first
// time, after startup or since it was watched, is only recorded.
func (a *Agent) checkServices(ctx context.Context) {
	now := a.now()
	seen := map[string]bool{}
	for _, it := range a.watchedItems(ctx) {
		key := watchAlertKey(it)
		failing, known := isFailing(it)
		if !known {
			// Neither this time: keep what was known.
			seen[key] = a.svcSeen[key]
			continue
		}
		seen[key] = true
		if !a.svcSeen[key] {
			a.engine.Seed(key, failing)
			continue
		}
		fire, resolve := a.engine.Check(key, failing, now)
		if !fire && !resolve {
			continue
		}
		al := watchAlert(it, key, resolve, now)
		a.pushAlert(ctx, al)
	}
	a.svcSeen = seen
}

// watchedItems checks the watched units, ports, HTTP checks and
// processes. A kind that cannot be read this time is left out.
func (a *Agent) watchedItems(ctx context.Context) []svItem {
	var items []svItem
	if len(a.watchCopy().Services) > 0 {
		if units, err := a.unitItems(ctx); err == nil {
			items = append(items, watchedOnly(units)...)
		}
	}
	for _, load := range []func(*Agent, context.Context) ([]svItem, error){(*Agent).portItems, (*Agent).httpItems, (*Agent).procItems} {
		if more, err := load(a, ctx); err == nil {
			items = append(items, more...)
		}
	}
	return items
}

// isFailing reads an item's state as a pass or a fail; known is false
// when it says neither. A unit starting or stopping is in between, and
// a wrong HTTP status is a failure.
func isFailing(it svItem) (failing, known bool) {
	switch it.state {
	case services.StateOK:
		return false, true
	case services.StateDown:
		return true, true
	case services.StateDegraded:
		return true, it.kind == watchHTTP
	}
	return false, false
}

// watchAlertKey is the alert key of a watched item.
func watchAlertKey(it svItem) string {
	switch it.kind {
	case watchUnit:
		return keyUnit + ":" + it.name
	case watchPort:
		return keyPort + ":" + it.name
	case watchHTTP:
		return keyHTTP + ":" + callbackDigest(it.name)
	}
	return keyProc + ":" + it.name
}

// watchAlert is the alert of an item that started failing, or recovered.
func watchAlert(it svItem, key string, recovered bool, now time.Time) alert.Alert {
	name := it.name
	switch it.kind {
	case watchPort:
		// The label is "<port> <note>".
		name = "port " + it.name
		if f := strings.Fields(it.label); len(f) > 1 {
			name += " (" + strings.Join(f[1:], " ") + ")"
		}
	case watchHTTP:
		name = truncate(it.name, 200)
	}
	al := alert.Alert{Key: key, Severity: alert.Critical, At: now}
	title := map[string]string{watchUnit: "Unit", watchPort: "Port", watchHTTP: "HTTP check", watchProc: "Process"}[it.kind]
	switch {
	case recovered:
		al.Severity, al.Resolved, al.Title = alert.Info, true, title+" recovered"
		al.Body = name + " is " + recoveredState(it) + " again"
	default:
		if it.state == services.StateDegraded {
			al.Severity = alert.Warning
		}
		al.Title = title + " failing"
		al.Body = name + ": " + truncate(it.status, 200)
	}
	return al
}

// recoveredState is how a recovered item reads: "active", "listening".
func recoveredState(it svItem) string {
	switch it.kind {
	case watchUnit:
		return "active"
	case watchPort:
		return "listening"
	case watchProc:
		return "running"
	}
	return "OK"
}

// watchAlertRow is the first row of a watched item's alert, and ok is
// false for other keys: [🔍 Open], and [🔁 Restart] for a unit service
// actions are on for and allow.
func (a *Agent) watchAlertRow(key string) ([]telegram.Button, bool) {
	prefix, name, _ := strings.Cut(key, ":")
	open := func(c tgui.Call) []telegram.Button {
		return []telegram.Button{{Text: "🔍 Open", Data: callData(c)}}
	}
	switch prefix {
	case keyPort:
		return open(tgui.OpenNew(scrPorts)), true
	case keyHTTP:
		return open(tgui.OpenNew(scrHTTP)), true
	case keyProc:
		return open(tgui.OpenNew(scrProcs)), true
	case keyUnit:
		return a.unitAlertRow(name, open), true
	}
	return nil, false
}

// unitAlertRow is the first row of a unit's alert.
func (a *Agent) unitAlertRow(name string, open func(tgui.Call) []telegram.Button) []telegram.Button {
	// A unit name that is not one is never given to a screen or an act.
	if !services.ValidUnitName(name) {
		return open(tgui.OpenNew(scrUnits))
	}
	id := callbackDigest(name)
	row := open(tgui.Call{Act: tgui.ActOpen, Args: []string{scrUnit, id}})
	watched := slices.ContainsFunc(a.watchCopy().Services, func(s string) bool { return unitName(s) == name })
	if a.refusal(svTarget{it: svItem{kind: watchUnit, id: id, name: name, watched: watched}}, false) == "" {
		restart := tgui.Call{Act: askUnitAct, Args: []string{services.VerbRestart, id}, From: fromAlert}
		row = append(row, telegram.Button{Text: verbTexts[services.VerbRestart].button, Data: callData(restart)})
	}
	return row
}

// showConfirmReply is showConfirm for an ask act pressed on an alert:
// the confirm screen, or why there is none, goes out as a new message
// replying to the alert, and the token is bound to that message. The
// alert keeps its text and keyboard.
func (a *Agent) showConfirmReply(ctx context.Context, cb *telegram.Callback, id, target string) {
	p := a.confirms[id].prompt(ctx, target, false)
	if p.yes == "" {
		if p.denied {
			a.writeAudit(auditRecord{Phase: phaseDenied, Action: id, Target: target,
				ActorID: cb.FromID, ChatID: cb.ChatID, MessageID: cb.MessageID})
		}
		toast := p.toast
		if _, err := a.send.SendReplyKB(ctx, cb.ChatID, cb.MessageID, p.text, p.kb); err != nil {
			log.Printf("agent: opening confirm: %v", err)
			toast = openFailedToast
		}
		a.answer(ctx, cb, toast)
		return
	}
	// Bound to no message until the prompt is sent: no press matches it.
	in := tgui.Intent{Action: id, Target: target, ActorID: cb.FromID, ChatID: cb.ChatID}
	kb, nonce, err := a.mintConfirm(in, p.yes)
	if err != nil {
		log.Printf("agent: %v", err)
		a.answer(ctx, cb, mintFailedToast)
		return
	}
	msg, err := a.send.SendReplyKB(ctx, cb.ChatID, cb.MessageID, p.text, kb)
	if err != nil {
		log.Printf("agent: opening confirm: %v", err)
		a.answer(ctx, cb, openFailedToast)
		return
	}
	a.tokens.Rebind(nonce, msg)
	a.answer(ctx, cb, "")
}
