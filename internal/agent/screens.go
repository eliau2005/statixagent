package agent

import (
	"context"
	"fmt"
	"log"
	"strconv"

	"github.com/eliau2005/statixagent/internal/bot"
	"github.com/eliau2005/statixagent/internal/config"
	"github.com/eliau2005/statixagent/internal/sshwatch"
	"github.com/eliau2005/statixagent/internal/telegram"
	"github.com/eliau2005/statixagent/internal/tgui"
)

// The bot's screens (docs/telegram-ux-redesign.md §3): Home, three
// sections and the screens under them, each with the fixed footer. Every
// navigation button is "~1" data, so it survives restarts. Buttons that
// change the bot's settings are config acts carrying absolute values, and
// host changes open a confirm token through an ask act, both below; Live
// and trust on alerts still carry the legacy data their handlers decode.

// Screen IDs. A screen that is a Back target ("^from") needs 1-3 letters.
const (
	scrHome     = tgui.HomeID
	scrMetrics  = "met"
	scrCPU      = "cpu"
	scrMem      = "mem"
	scrDisk     = "dsk"
	scrNet      = "net"
	scrTemp     = "tmp"
	scrBattery  = "bat"
	scrTop      = "top"
	scrDigest   = "dig"
	scrServices = "svc"
	scrDocker   = "dk"
	scrSSL      = "ssl"
	scrHTTP     = "htp"
	scrSecurity = "sec"
	scrSessions = "ses"
	scrHistory  = "his"
	scrFailed   = "fai"
	scrFirewall = "fw"
	scrTrusted  = "tru"
	scrSettings = "set"
	scrUpdate   = "upd"
	scrHelp     = "hlp"
	scrWatching = "wat"
	// The scans open from Watching.
	scrScanServices = "scs"
	scrScanPorts    = "scp"
	// The services hub's other lists and its detail screens (svhub.go).
	scrFailing      = "svf"
	scrUnits        = "un"
	scrUnitsWatched = "uw"
	scrUnit         = "ud"
	scrContainer    = "cd"
	scrPorts        = "prt"
	scrProcs        = "prc"
	// Logs of a unit or container (svaction.go).
	scrUnitLogs      = "ul"
	scrContainerLogs = "cl"
)

// commandScreens are the typed commands (bare, or /start's deep-link
// payload) that open a screen, besides the screen IDs themselves.
var commandScreens = map[string]string{
	"start": scrHome, "status": scrHome, "metrics": scrMetrics, "cpu": scrCPU, "mem": scrMem,
	"disk": scrDisk, "net": scrNet, "temp": scrTemp, "battery": scrBattery, "top": scrTop,
	"digest": scrDigest, "services": scrServices, "docker": scrDocker, "ssl": scrSSL,
	"http": scrHTTP, "security": scrSecurity, "ssh": scrSessions, "ssh_history": scrHistory,
	"ssh_fails": scrFailed, "firewall": scrFirewall, "trusted": scrTrusted,
	"settings": scrSettings, "update": scrUpdate, "help": scrHelp, "watching": scrWatching,
	"services_scan": scrScanServices, "ports_scan": scrScanPorts,
}

// pageSize is how many items a list screen shows; lists page, they never
// grow (principle 6).
const pageSize = 8

// renderFailedToast answers a press whose screen could not be built.
const renderFailedToast = "Couldn't show this view. Send /status for a fresh one."

// buildScreens registers the screens.
func (a *Agent) buildScreens() *tgui.Registry {
	r := tgui.NewRegistry()
	// leaf is a screen whose text comes from text and whose only extra
	// rows are rows: the footer is appended.
	leaf := func(id, parent string, slow bool, text func(ctx context.Context) string, rows ...[]tgui.Button) {
		r.AddScreen(tgui.Screen{ID: id, Parent: parent, Slow: slow, Render: func(ctx context.Context, c tgui.Call) tgui.View {
			return tgui.View{Text: text(ctx), Rows: append(rows, r.Footer(id, c))}
		}})
	}
	view := func(id, parent string, slow bool, render func(ctx context.Context, c tgui.Call) tgui.View) {
		r.AddScreen(tgui.Screen{ID: id, Parent: parent, Slow: slow, Render: func(ctx context.Context, c tgui.Call) tgui.View {
			v := render(ctx, c)
			v.Rows = append(v.Rows, r.Footer(id, c))
			return v
		}})
	}
	r.AddScreen(tgui.Screen{ID: scrHome, Render: a.homeView})
	r.AddScreen(tgui.Screen{ID: scrHelp, Render: func(context.Context, tgui.Call) tgui.View {
		return tgui.View{Text: helpText, Rows: [][]tgui.Button{{{Label: "🏠 Home", Call: tgui.Open(scrHome)}}}}
	}})

	view(scrMetrics, scrHome, false, a.metricsView)
	top := func(from string) []tgui.Button {
		return []tgui.Button{{Label: "🔝 Top processes", Call: tgui.Call{Act: tgui.ActView, Args: []string{scrTop}, From: from}}}
	}
	leaf(scrCPU, scrMetrics, false, func(context.Context) string { return a.cpuText() }, top(scrCPU))
	leaf(scrMem, scrMetrics, false, func(context.Context) string { return a.memText() }, top(scrMem))
	leaf(scrDisk, scrMetrics, false, func(context.Context) string { return a.diskText() })
	leaf(scrNet, scrMetrics, false, func(context.Context) string { return a.netText() })
	leaf(scrTemp, scrMetrics, false, func(context.Context) string { return a.tempText() })
	leaf(scrBattery, scrMetrics, false, func(context.Context) string { return a.batteryText() })
	leaf(scrTop, scrMetrics, true, a.topText)
	leaf(scrDigest, scrMetrics, false, func(context.Context) string { return a.digestView(false) })

	// The services hub, its lists and their detail screens (svhub.go).
	// They read systemd, Docker or the network, so all but Processes are
	// slow.
	view(scrServices, scrHome, true, a.hubScreen)
	view(scrFailing, scrServices, true, a.failingScreen)
	view(scrUnits, scrServices, true, a.kindScreen(kindUnits))
	view(scrUnitsWatched, scrServices, true, a.watchedUnitsScreen)
	view(scrUnit, scrUnits, true, a.unitScreen)
	view(scrDocker, scrServices, true, a.kindScreen(kindDocker))
	view(scrContainer, scrDocker, true, a.containerScreen)
	view(scrHTTP, scrServices, true, a.kindScreen(kindHTTP))
	view(scrSSL, scrServices, true, a.kindScreen(kindCerts))
	view(scrPorts, scrServices, true, a.kindScreen(kindPorts))
	view(scrProcs, scrServices, false, a.kindScreen(kindProcs))
	// Logs of a unit or container, when service actions allow them.
	a.addLogScreens(r)

	view(scrSecurity, scrHome, false, a.securityView)
	view(scrSessions, scrSecurity, false, a.sessionsView)
	view(scrHistory, scrSecurity, false, a.historyView)
	view(scrFailed, scrSecurity, false, a.failedView)
	view(scrFirewall, scrSecurity, false, a.firewallScreen)
	view(scrTrusted, scrSecurity, false, a.trustedScreen)

	view(scrSettings, scrHome, false, a.settingsScreen)
	view(scrUpdate, scrSettings, true, a.updateView)
	// Watching opens from Settings and from Services, which passes itself
	// as From; the scans list systemd units (slow) and listening ports.
	view(scrWatching, scrSettings, false, a.watchingScreen)
	view(scrScanServices, scrWatching, true, a.scanServicesScreen)
	view(scrScanPorts, scrWatching, false, a.scanPortsScreen)
	return r
}

// callData encodes a call built from constants. It cannot fail for
// them, and the screen tests encode every one; a failure is a bug, so
// it panics rather than send a button that cannot work.
func callData(c tgui.Call) string {
	data, err := tgui.Encode(c)
	if err != nil {
		panic(fmt.Sprintf("agent: %v", err))
	}
	return data
}

// homeKeyboard is the fallback keyboard when a screen cannot be built.
func homeKeyboard() telegram.Keyboard {
	return telegram.Keyboard{{{Text: "🏠 Home", Data: callData(tgui.Open(scrHome))}}}
}

// screen renders what c opens, for a reply or an edit.
func (a *Agent) screen(ctx context.Context, c tgui.Call) (string, telegram.Keyboard) {
	res, err := a.ui.Show(ctx, c)
	if err != nil || res.Outcome != tgui.Shown {
		log.Printf("agent: rendering screen: %v", err)
		return renderFailedToast, homeKeyboard()
	}
	return res.Text, res.Keyboard
}

// encodeView turns a view built outside the registry into a message.
func encodeView(v tgui.View) (string, telegram.Keyboard) {
	kb, err := v.Keyboard()
	if err != nil {
		log.Printf("agent: rendering view: %v", err)
		return v.Text, homeKeyboard()
	}
	return v.Text, kb
}

// screenReply is a typed command's reply: screen id, with its buttons,
// which reply sends as a new message.
func (a *Agent) screenReply(ctx context.Context, id string) tgui.View {
	v, ok := a.ui.Render(ctx, tgui.Open(id))
	if !ok {
		log.Printf("agent: no screen %q", id)
		return tgui.View{Text: renderFailedToast, Rows: [][]tgui.Button{{{Label: "🏠 Home", Call: tgui.Open(scrHome)}}}}
	}
	return v
}

// screenCommand is the handler of a typed command that opens screen id.
func (a *Agent) screenCommand(id string) bot.Handler {
	return func(ctx context.Context, _ []string) tgui.View { return a.screenReply(ctx, id) }
}

// deepLink resolves /start's payload to a screen: a screen ID or a
// command name. Anything else opens Home.
func (a *Agent) deepLink(payload string) string {
	if id, ok := commandScreens[payload]; ok {
		return id
	}
	for _, id := range a.ui.Screens() {
		if id == payload {
			return id
		}
	}
	return scrHome
}

// Ask acts open a confirm screen: the press is authorized for its class,
// its arguments are re-validated, and the confirm token (confirm.go) is
// what may run the action. They never act themselves.
const (
	askKick     = "kk"
	askFwOpen   = "fo"
	askFwClose  = "fc"
	askUpdate   = "up"
	askClear    = "cc"
	askUntrust  = "ut"
	fingerprint = 16 // hex characters of a session fingerprint
)

// askAction is one ask act.
type askAction struct {
	class tgui.Class
	// resolve validates the press's arguments into the confirm action
	// and target it asks about; ok is false for forged or stale ones.
	resolve func(args []string) (action, target string, ok bool)
}

// buildAsks registers the ask acts.
func (a *Agent) buildAsks() map[string]askAction {
	fixed := func(action, target string) func([]string) (string, string, bool) {
		return func(args []string) (string, string, bool) { return action, target, len(args) == 0 }
	}
	return map[string]askAction{
		askKick: {tgui.ClassMutate, func(args []string) (string, string, bool) {
			if len(args) != 1 || len(args[0]) != fingerprint || !isHex(args[0]) {
				return "", "", false
			}
			return actKick, args[0], true
		}},
		askFwOpen:  {tgui.ClassMutate, fixed(actFwOpen, sshPort)},
		askFwClose: {tgui.ClassMutate, fixed(actFwClose, sshPort)},
		askUpdate:  {tgui.ClassMutate, fixed(actUpdate, "agent")},
		askClear:   {tgui.ClassMutate, fixed(actClear, "chat")},
		askUntrust: {tgui.ClassConfig, func(args []string) (string, string, bool) {
			if len(args) != 1 {
				return "", "", false
			}
			p, err := config.ParseTrustedIP(args[0])
			if err != nil || sshwatch.FormatPrefix(p) != args[0] {
				return "", "", false
			}
			return actUntrust, args[0], true
		}},
	}
}

// Config acts change the bot's own settings (ClassConfig): thresholds,
// the digest, the watch lists and alert snoozes. Their buttons carry the
// result, an absolute value or an item's stable ID, never a step or a
// list index, so a replayed press changes nothing. Each validates its
// arguments and shows its own outcome.
const (
	cfgThreshold = "th" // th|<key>|<target>, or th|<key> to explain the row
	cfgDigest    = "dg" // dg|on, dg|off
	cfgDigestAt  = "dh" // dh|<hour>, or dh to explain the row
	cfgUnwatch   = "wr" // wr|<kind>|<id>|<page>
	cfgWatch     = "wa" // wa|<kind>|<id>|<page>, from a scan
	cfgSnooze    = "sz" // sz|<duration>|<key ref>
	cfgUnsnooze  = "uz" // uz|<key ref>
)

// configAct runs one press of a config act, already authorized.
type configAct func(ctx context.Context, cb *telegram.Callback, c tgui.Call)

// buildActs registers the config acts.
func (a *Agent) buildActs() map[string]configAct {
	return map[string]configAct{
		cfgThreshold: a.thresholdPress,
		cfgDigest:    a.digestPress,
		cfgDigestAt:  a.digestAtPress,
		cfgUnwatch:   a.unwatchPress,
		cfgWatch:     a.watchPress,
		cfgSnooze:    a.snoozePress,
		cfgUnsnooze:  a.unsnoozePress,
	}
}

func isHex(s string) bool {
	for _, c := range s {
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return false
		}
	}
	return true
}

// handleCall runs a press whose data is in the tgui format. authorize
// runs first, through the gate, with the class of the registered action:
// foreign chats and impostors are ignored unanswered, as for legacy data.
// Every other press is answered exactly once.
func (a *Agent) handleCall(ctx context.Context, cb *telegram.Callback) {
	c, decErr := tgui.Decode(cb.Data)
	slow := decErr == nil && a.ui.Slow(c)
	answered := false
	gate := func(class tgui.Class) bool {
		v := a.authorize(ctx, sender{chatID: cb.ChatID, fromID: cb.FromID, chatType: cb.ChatType}, class == tgui.ClassView)
		switch {
		case v == ignored:
			return false
		case cb.Inaccessible:
			a.answer(ctx, cb, inaccessibleToast)
			return false
		case v == adminOnly:
			a.answer(ctx, cb, adminOnlyToast)
			return false
		}
		if slow {
			// Seconds of work ahead: stop the spinner first.
			a.answer(ctx, cb, "")
			answered = true
		}
		return true
	}
	if decErr == nil {
		// Yes and Cancel name a confirm token, ask acts a confirm to
		// open; neither names a screen. Decoding is pure, so the gate
		// still runs before anything else.
		if c.Act == tgui.ActYes || c.Act == tgui.ActNo {
			if gate(tgui.ClassMutate) {
				a.confirmPress(ctx, cb, c)
			}
			return
		}
		if ask, ok := a.asks[c.Act]; ok {
			if !gate(ask.class) {
				return
			}
			id, target, ok := ask.resolve(c.Args)
			if !ok {
				a.refuseCallback(ctx, cb, false)
				return
			}
			if c.From == fromAlert {
				a.showConfirmReply(ctx, cb, id, target)
				return
			}
			a.showConfirm(ctx, cb, false, id, target, false, "")
			return
		}
		if act, ok := a.acts[c.Act]; ok {
			if gate(tgui.ClassConfig) {
				act(ctx, cb, c)
			}
			return
		}
	}
	res, err := a.ui.Dispatch(ctx, cb.Data, gate)
	switch {
	case err != nil:
		log.Printf("agent: rendering callback: %v", err)
		if !answered {
			a.answer(ctx, cb, renderFailedToast)
		}
	case res.Outcome == tgui.Outdated:
		a.refuseCallback(ctx, cb, answered)
	case res.Outcome == tgui.Shown && res.New:
		a.openNew(ctx, cb, answered, res.Text, res.Keyboard)
	case res.Outcome == tgui.Shown:
		a.finishCallback(ctx, cb, answered, res.Text, res.Keyboard, "")
	}
}

// openNew sends a view as a new message replying to the pressed one,
// which stays exactly as it was: an alert remains a record.
func (a *Agent) openNew(ctx context.Context, cb *telegram.Callback, answered bool, text string, kb telegram.Keyboard) {
	toast := ""
	if _, err := a.send.SendReplyKB(ctx, cb.ChatID, cb.MessageID, text, kb); err != nil {
		log.Printf("agent: opening view: %v", err)
		toast = openFailedToast
	}
	if !answered {
		a.answer(ctx, cb, toast)
	}
}

// pageOf returns the 1-based page of n items that c asks for in its
// second argument, clamped to the pages there are.
func pageOf(c tgui.Call, n int) (page, pages int) {
	pages = max(1, (n+pageSize-1)/pageSize)
	page = 1
	if len(c.Args) > 1 {
		if p, err := strconv.Atoi(c.Args[1]); err == nil {
			page = min(max(p, 1), pages)
		}
	}
	return page, pages
}

// pageRow is a list's [◀️ Prev] [n/N] [Next ▶️] row; nil for one page.
// The middle button re-opens the page.
func pageRow(id string, c tgui.Call, page, pages int) []tgui.Button {
	if pages <= 1 {
		return nil
	}
	at := func(p int) tgui.Call {
		return tgui.Call{Act: tgui.ActView, Args: []string{id, strconv.Itoa(p)}, From: c.From}
	}
	var row []tgui.Button
	if page > 1 {
		row = append(row, tgui.Button{Label: "◀️ Prev", Call: at(page - 1)})
	}
	row = append(row, tgui.Button{Label: fmt.Sprintf("%d/%d", page, pages), Call: at(page)})
	if page < pages {
		row = append(row, tgui.Button{Label: "Next ▶️", Call: at(page + 1)})
	}
	return row
}

// pageSlice returns the items on page (1-based).
func pageSlice[T any](items []T, page int) []T {
	lo := min((page-1)*pageSize, len(items))
	return items[lo:min(lo+pageSize, len(items))]
}
