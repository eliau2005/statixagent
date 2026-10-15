package agent

import (
	"context"
	"fmt"
	"log"
	"net/netip"
	"slices"
	"time"

	"github.com/eliau2005/statixagent/internal/config"
	"github.com/eliau2005/statixagent/internal/sshwatch"
	"github.com/eliau2005/statixagent/internal/telegram"
	"github.com/eliau2005/statixagent/internal/tgui"
)

// Host-changing buttons (kick, firewall, update, clear chat, and the
// service actions of svaction.go) go through a confirm token
// (tgui.Tokens): the Yes button carries a single-use token bound to the
// action, its target, the user who asked and the message, never the
// action itself. On Yes the target is resolved again from fresh state
// before anything runs, and the message becomes a receipt. Every step is
// audited (audit.go).

// Confirm action IDs, as the audit log records them.
const (
	actKick    = "ssh_kick"
	actFwOpen  = "fw_open"
	actFwClose = "fw_close"
	actUpdate  = "update"
	actClear   = "clear_chat"
	actUntrust = "untrust"
)

// Answers to a confirm press that cannot run.
const (
	staleText        = "⌛ This button is from before a restart / has expired. Open the view again."
	staleToast       = "⌛ Expired. Open the view again"
	wrongActorToast  = "⛔ Only the person who asked can confirm this"
	runningToast     = "Already running"
	doneToast        = "Already done"
	reconfirmToast   = "Please confirm again"
	secondStepToast  = "One more confirmation"
	mintFailedToast  = "Couldn't prepare the confirmation. Try again."
	runningText      = "⏳ Running…"
	cancelledText    = "❌ Cancelled."
	sessionGoneToast = "Session changed, refreshed"
	trustGoneToast   = "No longer trusted from the bot, refreshed"
)

// confirmAction is one host-changing action behind a confirm token.
type confirmAction struct {
	// back is the screen a stale or cancelled confirm leads back to, and
	// backLabel its button's label.
	back, backLabel string
	// prompt renders the confirm screen for target from fresh state;
	// final selects the second screen of a double confirm.
	prompt func(ctx context.Context, target string, final bool) confirmPrompt
	// double reports, from fresh state, whether a first Yes needs a
	// second confirm because the action risks locking the user out.
	double func(ctx context.Context, target string) bool
	// run resolves target again from fresh state and acts on it.
	run func(ctx context.Context, target string) actionResult
	// cancel renders the view Cancel returns to.
	cancel func(ctx context.Context) (string, telegram.Keyboard)
	// view, when set, renders the target's own screen, which Cancel and
	// a busy lock return to instead of cancel's.
	view func(ctx context.Context, target string) (string, telegram.Keyboard)
	// lock, when set, names the resource run holds: one action at a time
	// runs on it, and a Yes that finds it held gets "Already running".
	lock func(target string) string
}

// confirmPrompt is a confirm screen. With no yes label it is a plain view
// shown instead, because the target is gone or the action unavailable.
type confirmPrompt struct {
	text  string
	yes   string // the Yes button's label
	kb    telegram.Keyboard
	toast string
	// denied: the view is a refusal (a target the bot never acts on, or
	// one not allowed), audited as such.
	denied bool
}

// actionResult is what a confirmed action did.
type actionResult struct {
	ok     bool
	what   string // receipt headline, plain text: "Port 22 closed"
	target string // receipt and audit target, plain text
	text   string // the view after the action, HTML
	kb     telegram.Keyboard
	trace  *cmdTrace
	// drift: the target changed before anything ran; text shows the
	// fresh view and driftToast says why.
	drift      bool
	driftToast string
	// refused: the action would not run (a disabled action, Keep without
	// evidence); like drift, text and driftToast say why.
	refused bool
	// newMessage: the pressed message is gone (clear chat), so the
	// outcome is sent rather than edited in.
	newMessage bool
	// rebind, when set, is told the message the outcome ended up in if
	// that is not the pressed one, so buttons bound to it follow.
	rebind func(messageID int64)
}

// buildConfirms registers the confirm actions.
func (a *Agent) buildConfirms() map[string]confirmAction {
	return map[string]confirmAction{
		actKick:    a.kickAction(),
		actFwOpen:  a.firewallAction(true),
		actFwClose: a.firewallAction(false),
		actUpdate:  a.updateAction(),
		actClear:   a.clearAction(),
		actUntrust: a.untrustAction(),
		actFwPlan:  a.planAction(),
		// A firewall trial's buttons: minted with the trial, never from
		// a confirm screen of their own.
		actFwKeep:     a.trialAction(a.keepTrial),
		actFwRollback: a.trialAction(a.rollbackTrial),
	}
}

// confirmRow is the Yes/Cancel row of a confirm screen for nonce. Yes
// is red, as decoration: its label already says what it does.
func (a *Agent) confirmRow(yesLabel, nonce string) []tgui.Button {
	return []tgui.Button{{Label: yesLabel, Call: a.tokens.Yes(nonce), Style: "danger"}, {Label: "❌ Cancel", Call: tgui.No(nonce)}}
}

// mintToken stores a token for in, audited as requested, and returns its
// nonce.
func (a *Agent) mintToken(in tgui.Intent) (string, error) {
	return a.mintTokenTTL(in, tgui.TokenTTL)
}

// mintTokenTTL is mintToken with its own lifetime, for a firewall plan.
func (a *Agent) mintTokenTTL(in tgui.Intent, ttl time.Duration) (string, error) {
	nonce, err := a.tokens.MintTTL(in, ttl)
	if err != nil {
		return "", err
	}
	a.writeAudit(auditRecord{Phase: phaseRequested, Action: in.Action, Target: in.Target,
		ActorID: in.ActorID, ChatID: in.ChatID, MessageID: in.MessageID, NonceHash: nonceHash(nonce)})
	return nonce, nil
}

// mintConfirm stores a token for in and returns its keyboard and nonce.
func (a *Agent) mintConfirm(in tgui.Intent, yesLabel string) (telegram.Keyboard, string, error) {
	nonce, err := a.mintToken(in)
	if err != nil {
		return nil, "", err
	}
	kb, err := tgui.View{Rows: [][]tgui.Button{a.confirmRow(yesLabel, nonce)}}.Keyboard()
	if err != nil {
		return nil, "", err
	}
	return kb, nonce, nil
}

// showConfirm edits action id's confirm screen for target into the
// pressed message, bound to its sender. toast says why it appears, such
// as a legacy Yes being asked again.
func (a *Agent) showConfirm(ctx context.Context, cb *telegram.Callback, answered bool, id, target string, final bool, toast string) {
	p := a.confirms[id].prompt(ctx, target, final)
	in := tgui.Intent{Action: id, Target: target, ActorID: cb.FromID, ChatID: cb.ChatID, MessageID: cb.MessageID, Final: final}
	if p.yes == "" {
		if p.denied {
			a.writeAudit(auditRecord{Phase: phaseDenied, Action: id, Target: target,
				ActorID: cb.FromID, ChatID: cb.ChatID, MessageID: cb.MessageID})
		}
		a.finishCallback(ctx, cb, answered, p.text, p.kb, p.toast)
		return
	}
	kb, nonce, err := a.mintConfirm(in, p.yes)
	if err != nil {
		log.Printf("agent: %v", err)
		if !answered {
			a.answer(ctx, cb, mintFailedToast)
		}
		return
	}
	if id := a.finishCallback(ctx, cb, answered, p.text, kb, toast); id != cb.MessageID {
		a.tokens.Rebind(nonce, id)
	}
}

// typedConfirm is showConfirm for a typed command: the prompt is the
// reply, and reply binds its token to the message once it is sent. The
// typed confirms (update, clear chat) fall back to text alone when the
// action is unavailable.
func (a *Agent) typedConfirm(ctx context.Context, id, target string) tgui.View {
	p := a.confirms[id].prompt(ctx, target, false)
	if p.yes == "" {
		return tgui.View{Text: p.text}
	}
	in := tgui.Intent{Action: id, Target: target, ActorID: actorFrom(ctx), ChatID: a.cfg.Telegram.ChatID}
	nonce, err := a.mintToken(in)
	if err != nil {
		log.Printf("agent: %v", err)
		return tgui.View{Text: mintFailedToast}
	}
	return tgui.View{Text: p.text, Rows: [][]tgui.Button{a.confirmRow(p.yes, nonce)}}
}

// confirmNonce is the nonce of the confirm token v's Yes button carries,
// or "".
func confirmNonce(v tgui.View) string {
	for _, row := range v.Rows {
		for _, b := range row {
			if b.Call.Act == tgui.ActYes && len(b.Call.Args) == 1 {
				return tgui.Nonce(b.Call.Args[0])
			}
		}
	}
	return ""
}

type actorKey struct{}

// withActor tags ctx with the user a text command came from, so a
// confirm it asks for is bound to them.
func withActor(ctx context.Context, userID int64) context.Context {
	return context.WithValue(ctx, actorKey{}, userID)
}

func actorFrom(ctx context.Context) int64 {
	id, _ := ctx.Value(actorKey{}).(int64)
	return id
}

// confirmPress handles a Yes or Cancel press, already authorized.
func (a *Agent) confirmPress(ctx context.Context, cb *telegram.Callback, c tgui.Call) {
	var arg string
	if len(c.Args) == 1 {
		arg = c.Args[0]
	}
	if c.Act == tgui.ActNo {
		a.cancelPress(ctx, cb, arg)
		return
	}
	nonce := tgui.Nonce(arg)
	in, check := a.tokens.Claim(arg, cb.FromID, cb.ChatID, cb.MessageID)
	rec := auditRecord{Action: in.Action, Target: in.Target, ActorID: cb.FromID, ChatID: cb.ChatID,
		MessageID: cb.MessageID, NonceHash: nonceHash(nonce)}
	if check != tgui.Confirmed {
		a.refuseConfirm(ctx, cb, in, check, rec)
		return
	}
	act := a.confirms[in.Action]
	rec.Phase = phaseConfirmed
	a.writeAudit(rec)
	if !in.Final && act.double != nil && act.double(ctx, in.Target) {
		a.tokens.Finish(nonce)
		a.showConfirm(ctx, cb, false, in.Action, in.Target, true, secondStepToast)
		return
	}
	if act.lock != nil {
		key := act.lock(in.Target)
		if !a.locks.tryLock(key) {
			a.tokens.Finish(nonce)
			rec.Phase = phaseDenied
			a.writeAudit(rec)
			text, kb := a.cancelView(ctx, in)
			a.finishCallback(ctx, cb, false, text, kb, runningToast)
			return
		}
		defer a.locks.unlock(key)
	}
	// Answer before the work, and take the buttons away while it runs.
	a.answer(ctx, cb, "Working…")
	if err := a.send.EditMessageKB(ctx, cb.ChatID, cb.MessageID, runningText, nil); err != nil {
		log.Printf("agent: confirm: %v", err)
	}
	start := time.Now()
	res := act.run(withIntent(ctx, in), in.Target)
	a.tokens.Finish(nonce)
	dur := time.Since(start)
	if res.drift || res.refused {
		rec.Phase = phaseStale
		if res.refused {
			rec.Phase = phaseDenied
		}
		a.writeAudit(rec)
		a.finishCallback(ctx, cb, true, res.text, res.kb, res.driftToast)
		return
	}
	rec.Phase, rec.Target = phaseExecuted, res.target
	if !res.ok {
		rec.Phase = phaseFailed
	}
	res.trace.record(&rec, a.redactOutput)
	if rec.DurationMS == 0 {
		rec.DurationMS = dur.Milliseconds()
	}
	a.writeAudit(rec)
	text := a.receipt(res, cb.FromID, dur)
	if res.text != "" {
		text += "\n" + res.text
	}
	if res.newMessage {
		if _, err := a.send.SendMessageKB(ctx, cb.ChatID, text, res.kb); err != nil {
			log.Printf("agent: confirm outcome: %v", err)
		}
		return
	}
	if id := a.finishCallback(ctx, cb, true, text, res.kb, ""); id != cb.MessageID && id != 0 && res.rebind != nil {
		res.rebind(id)
	}
}

// refuseConfirm answers a Yes that lost: it never runs anything.
func (a *Agent) refuseConfirm(ctx context.Context, cb *telegram.Callback, in tgui.Intent, check tgui.Check, rec auditRecord) {
	switch check {
	case tgui.WrongActor, tgui.Running, tgui.Done:
		rec.Phase = phaseDenied
		a.writeAudit(rec)
		toast := map[tgui.Check]string{tgui.WrongActor: wrongActorToast, tgui.Running: runningToast, tgui.Done: doneToast}[check]
		a.answer(ctx, cb, toast)
		return
	case tgui.Expired:
		rec.Phase = phaseExpired
	default:
		rec.Phase = phaseStale
	}
	a.writeAudit(rec)
	a.finishCallback(ctx, cb, false, staleText, a.confirmBack(in), staleToast)
}

// cancelPress handles a Cancel press.
func (a *Agent) cancelPress(ctx context.Context, cb *telegram.Callback, nonce string) {
	in, check := a.tokens.Cancel(nonce, cb.FromID, cb.ChatID, cb.MessageID)
	rec := auditRecord{Action: in.Action, Target: in.Target, ActorID: cb.FromID, ChatID: cb.ChatID,
		MessageID: cb.MessageID, NonceHash: nonceHash(nonce)}
	switch check {
	case tgui.Confirmed:
		rec.Phase = phaseCancelled
		a.writeAudit(rec)
		text, kb := a.cancelView(ctx, in)
		a.finishCallback(ctx, cb, false, text, kb, "Cancelled")
	case tgui.WrongActor, tgui.Running, tgui.Done:
		a.refuseConfirm(ctx, cb, in, check, rec)
	default:
		// Nothing is pending any more, so there is nothing to undo.
		a.finishCallback(ctx, cb, false, cancelledText, a.confirmBack(in), "")
	}
}

// cancelView is the view a confirm returns to without running.
func (a *Agent) cancelView(ctx context.Context, in tgui.Intent) (string, telegram.Keyboard) {
	act := a.confirms[in.Action]
	if act.view != nil {
		return act.view(ctx, in.Target)
	}
	return act.cancel(ctx)
}

// confirmBack is the keyboard of a confirm that ended without running:
// the action's own screen, when known, and Home.
func (a *Agent) confirmBack(in tgui.Intent) telegram.Keyboard {
	row := []telegram.Button{{Text: "🏠 Home", Data: callData(tgui.Open(scrHome))}}
	if act, ok := a.confirms[in.Action]; ok && act.back != scrHome {
		row = append([]telegram.Button{{Text: act.backLabel, Data: callData(tgui.Open(act.back))}}, row...)
	}
	return telegram.Keyboard{row}
}

// receipt is the one-line record a confirmed action leaves in its
// message: 🧾 Port 22 closed · port 22/tcp · by 123 · 14:02:11 UTC · 1.3s · ok
func (a *Agent) receipt(res actionResult, actor int64, dur time.Duration) string {
	status := "ok"
	if !res.ok {
		status = "failed"
	}
	return fmt.Sprintf("🧾 %s · %s · by %d · %s UTC · %.1fs · %s",
		esc(res.what), esc(res.target), actor, a.now().UTC().Format("15:04:05"), dur.Seconds(), status)
}

// ---- the actions ----

// kickAction disconnects one SSH session. Its target is the session's
// fingerprint, so a Yes can only reach the login it was drawn for.
func (a *Agent) kickAction() confirmAction {
	gone := func(ctx context.Context) confirmPrompt {
		text, kb := a.sshSessionsView(ctx)
		return confirmPrompt{text: text, kb: kb, toast: sessionGoneToast}
	}
	return confirmAction{
		back: scrSessions, backLabel: "👥 Sessions",
		prompt: func(ctx context.Context, fp string, final bool) confirmPrompt {
			s, _, ok := a.sessionByFingerprint(fp)
			switch {
			case !ok:
				return gone(ctx)
			case final:
				return confirmPrompt{text: kickOnlyText(s), yes: "✅ Yes, cut the only session"}
			}
			return confirmPrompt{text: kickConfirmText(s), yes: "✅ Yes, disconnect"}
		},
		// The only session listed may well be the user's own.
		double: func(_ context.Context, fp string) bool {
			_, n, ok := a.sessionByFingerprint(fp)
			return ok && n == 1
		},
		run: func(ctx context.Context, fp string) actionResult {
			s, _, ok := a.sessionByFingerprint(fp)
			if !ok {
				text, kb := a.sshSessionsView(ctx)
				return actionResult{drift: true, driftToast: sessionGoneToast, text: text, kb: kb}
			}
			what, errDetail, trace := a.kickSession(ctx, s)
			res := actionResult{ok: errDetail == "", what: what, target: s.User + " " + s.TTY + " from " + s.Host, trace: trace}
			res.text, res.kb = a.sshSessionsView(ctx)
			if errDetail != "" {
				res.what = "Disconnect failed"
				res.text = "❌ <b>Disconnect failed</b>\n<pre>" + esc(errDetail) + "</pre>\n" +
					kickSandboxHint(errDetail) + "\n" + res.text
			}
			return res
		},
		cancel: func(ctx context.Context) (string, telegram.Keyboard) { return a.sshSessionsView(ctx) },
	}
}

// firewallAction opens or closes SSH port 22, under the dead-man switch
// (fwdeadman.go). Closing is offered only with firewall.allow_close_ssh,
// and always double confirmed: it can lock the user out of SSH.
func (a *Agent) firewallAction(open bool) confirmAction {
	act := confirmAction{
		back: scrFirewall, backLabel: "🛡 Firewall",
		prompt: func(_ context.Context, _ string, final bool) confirmPrompt {
			trial := "\nTrial: the old rules return after " + mmss(a.trialWindow()) + " unless you tap Keep."
			switch {
			case open:
				return confirmPrompt{text: "<b>Open SSH port 22?</b>\nIncoming SSH connections will be allowed." + trial,
					yes: "✅ Yes, open it"}
			case !a.cfg.Firewall.AllowCloseSSH:
				return confirmPrompt{text: closeSSHOff, kb: fwBackKB(), toast: "Closing SSH is turned off"}
			case final:
				return confirmPrompt{text: "🔒 <b>Last check: refuse new SSH connections?</b>\n" +
					"If your SSH session drops after this, you cannot log in again over SSH " +
					"until port 22 is reopened from this bot." + trial +
					"\nKeep needs a new SSH connection seen after the change.", yes: "✅ Yes, refuse new SSH"}
			}
			return confirmPrompt{text: "⚠️ <b>Close SSH port 22?</b>\n" +
				"Active sessions stay up, but <b>new SSH connections will be refused</b>.\n" +
				"This bot keeps working and can reopen the port." + trial, yes: "✅ Yes, close it"}
		},
		// The trial probes ufw afresh and refuses any state the view
		// would not offer the change in.
		run: func(ctx context.Context, _ string) actionResult {
			return a.runFirewallTrial(ctx, open)
		},
		cancel: a.firewallView,
	}
	if !open {
		act.double = func(context.Context, string) bool { return true }
	}
	return act
}

// trialAction is a firewall trial's Keep or Roll back button; its target
// is the trial ID, checked against the pending trial before acting.
func (a *Agent) trialAction(run func(context.Context, string) actionResult) confirmAction {
	return confirmAction{
		back: scrFirewall, backLabel: "🛡 Firewall",
		prompt: func(ctx context.Context, _ string, _ bool) confirmPrompt {
			text, kb := a.firewallView(ctx)
			return confirmPrompt{text: text, kb: kb}
		},
		run:    run,
		cancel: a.firewallView,
	}
}

// updateAction installs the self-update; the agent restarts on success.
func (a *Agent) updateAction() confirmAction {
	configured := func() bool { return a.src.UpdateCheck != nil && a.src.UpdateApply != nil }
	return confirmAction{
		back: scrUpdate, backLabel: "⬇️ Update",
		prompt: func(context.Context, string, bool) confirmPrompt {
			switch {
			case !configured():
				return confirmPrompt{text: "Self-update is not configured in this build."}
			case a.FwTrialPending():
				return confirmPrompt{text: trialPendingText}
			}
			return confirmPrompt{text: "⬇️ <b>Install the update?</b>\nThe agent will restart.", yes: "✅ Yes, install"}
		},
		run: func(ctx context.Context, _ string) actionResult {
			res := actionResult{target: "agent"}
			switch {
			case !configured():
				res.what, res.text = "Update unavailable", "Self-update is not configured in this build."
			case a.FwTrialPending():
				// A trial started after the confirm screen was shown.
				return actionResult{refused: true, driftToast: "Update blocked", text: trialPendingText}
			default:
				if err := a.src.UpdateApply(ctx); err != nil {
					res.what, res.text = "Update failed", "Update failed: "+esc(err.Error())
				} else {
					res.ok, res.what, res.text = true, "Update installed", "Updating — the agent will restart."
				}
			}
			return res
		},
		cancel: func(context.Context) (string, telegram.Keyboard) {
			return "Update postponed — /update any time.", homeKeyboard()
		},
	}
}

// clearAction deletes the chat's recent messages, the prompt included,
// so its outcome arrives as a new message.
func (a *Agent) clearAction() confirmAction {
	return confirmAction{
		back: scrSettings, backLabel: "⚙️ Settings",
		prompt: func(context.Context, string, bool) confirmPrompt {
			return confirmPrompt{text: "🧹 <b>Delete recent messages?</b>\n" +
				"The last 300 messages in this chat are deleted (Telegram only allows it for messages under 48 hours old).",
				yes: "✅ Yes, clear"}
		},
		run: func(ctx context.Context, _ string) actionResult {
			res := actionResult{target: "last 300 messages", newMessage: true}
			if err := a.clearChat(ctx); err != nil {
				res.what, res.text = "Clear failed", "Could not clear: "+esc(err.Error())
			} else {
				res.ok, res.what, res.text = true, "Chat cleared", "🧹 cleared"
			}
			return res
		},
		cancel: func(context.Context) (string, telegram.Keyboard) { return "Chat left as it is.", homeKeyboard() },
	}
}

// untrustAction removes a bot-managed trusted source. It changes only the
// bot's own settings, but logins from that source alert again, so it is
// confirmed like a host change; the target is the canonical prefix.
func (a *Agent) untrustAction() confirmAction {
	trusted := func(ctx context.Context) (string, telegram.Keyboard) { return a.screen(ctx, tgui.Open(scrTrusted)) }
	// stored re-reads the bot-managed list: config entries, and entries
	// already removed, cannot be untrusted from here.
	stored := func(target string) (netip.Prefix, bool) {
		p, err := config.ParseTrustedIP(target)
		if err != nil || sshwatch.FormatPrefix(p) != target {
			return netip.Prefix{}, false
		}
		return p, slices.Contains(a.trustStore.Entries(), p)
	}
	return confirmAction{
		back: scrTrusted, backLabel: "🤝 Trusted IPs",
		prompt: func(ctx context.Context, target string, _ bool) confirmPrompt {
			if _, ok := stored(target); !ok {
				text, kb := trusted(ctx)
				return confirmPrompt{text: text, kb: kb, toast: trustGoneToast}
			}
			return confirmPrompt{text: "🤝 <b>Untrust <code>" + esc(target) + "</code>?</b>\n" +
				"Plain SSH logins from it will alert again.", yes: "✅ Yes, untrust"}
		},
		run: func(ctx context.Context, target string) actionResult {
			p, ok := stored(target)
			if !ok {
				text, kb := trusted(ctx)
				return actionResult{drift: true, driftToast: trustGoneToast, text: text, kb: kb}
			}
			msg := a.trustRemove(p)
			text, kb := trusted(ctx)
			return actionResult{ok: true, what: "Source untrusted", target: target, text: msg + "\n\n" + text, kb: kb}
		},
		cancel: trusted,
	}
}
