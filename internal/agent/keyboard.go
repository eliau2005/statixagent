package agent

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"hash/crc32"
	"log"
	"maps"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/eliau2005/statixagent/internal/alert"
	"github.com/eliau2005/statixagent/internal/bot"
	"github.com/eliau2005/statixagent/internal/telegram"
	"github.com/eliau2005/statixagent/internal/tgui"
)

// legacyViews maps the bare view tokens of the navigation keyboard older
// versions sent (and that still sit in chats) to the screens that replace
// them: an old button opens the new screen in place. It is also the
// allowlist of tokens that count as views when authorized; callback data
// never reaches the router, so forged data cannot run a typed command.
var legacyViews = map[string]string{
	"status": scrHome, "cpu": scrCPU, "mem": scrMem, "disk": scrDisk, "net": scrNet,
	"temp": scrTemp, "battery": scrBattery, "services": scrServices, "docker": scrDocker,
	"ssh": scrSessions, "top": scrTop, "digest": scrDigest, "ssl": scrSSL, "http": scrHTTP,
	"ssh_history": scrHistory, "ssh_fails": scrFailed,
}

// Yes and Cancel buttons of the update and clear-chat prompts of older
// versions. Today's prompts carry confirm tokens (confirm.go); these are
// still decoded, and a Yes among them only ever asks again.
const (
	cbUpdateYes = "upd_yes"
	cbClearYes  = "clr_yes"
	cbClearNo   = "clr_no"
)

// alertViews are the screens an alert's buttons open, by alert key prefix.
func alertViews(prefix string) []tgui.Button {
	home := tgui.Button{Label: "🏠 Home", Call: tgui.OpenNew(scrHome)}
	open := func(label, id string) tgui.Button { return tgui.Button{Label: label, Call: tgui.OpenNew(id)} }
	switch prefix {
	case "ssh-login", "ssh-newkey", "ssh-brute", "keys":
		return []tgui.Button{open("👥 Sessions", scrSessions), open("🚫 Failed", scrFailed), open("🛡 Firewall", scrFirewall)}
	case "cpu":
		return []tgui.Button{open("🔝 Top", scrTop), open("🖥 CPU", scrCPU), home}
	case "mem":
		return []tgui.Button{open("🔝 Top", scrTop), open("🧠 Memory", scrMem), home}
	case "disk":
		return []tgui.Button{open("💾 Disk", scrDisk), home}
	case "temp":
		return []tgui.Button{open("🌡 Temp", scrTemp), home}
	case "ssl":
		return []tgui.Button{open("📜 Certificates", scrSSL), home}
	case "docker", "docker-up", "docker-restart":
		return []tgui.Button{open("🐳 Docker", scrDocker), home}
	case "battery", "power-loss", "power-restored":
		return []tgui.Button{open("🔋 Battery", scrBattery), home}
	}
	return []tgui.Button{home}
}

// alertKeyboard maps an alert to one-tap context buttons. Views open in a
// new message replying to the alert (Decision 1a), so the alert keeps its
// text as a record; only snooze and trust touch it, and then only its
// keyboard. extra rows (a login's source) go above the snooze row.
func (a *Agent) alertKeyboard(key string, extra ...[]telegram.Button) telegram.Keyboard {
	kb := telegram.Keyboard{alertViewRow(key)}
	for _, row := range extra {
		if len(row) > 0 {
			kb = append(kb, row)
		}
	}
	return append(kb, a.snoozeRow(key))
}

// alertViewRow is the row of views an alert's key prefix calls for.
func alertViewRow(key string) []telegram.Button {
	prefix, _, _ := strings.Cut(key, ":")
	var row []telegram.Button
	for _, b := range alertViews(prefix) {
		row = append(row, telegram.Button{Text: b.Label, Data: callData(b.Call)})
	}
	return row
}

// pushAlert renders and sends an alert with its context buttons, returning
// the send error (already logged) for callers that act on delivery.
func (a *Agent) pushAlert(ctx context.Context, al alert.Alert) error {
	_, err := a.pushAlertKB(ctx, al, a.alertKeyboard(al.Key))
	return err
}

// pushAlertKB is pushAlert with a caller-built keyboard; it also returns
// the sent message's ID.
func (a *Agent) pushAlertKB(ctx context.Context, al alert.Alert, kb telegram.Keyboard) (int64, error) {
	a.noteAlert(al)
	html := bot.AlertMsg(a.src.Hostname, al)
	id, err := a.send.SendMessageKB(ctx, a.cfg.Telegram.ChatID, html, kb)
	if err != nil {
		log.Printf("agent: alert push failed: %v", err)
	}
	return id, err
}

// reply sends a typed command's view as a new message. A confirm
// prompt's token is bound to the message it went out in.
func (a *Agent) reply(ctx context.Context, cmd string, v tgui.View) {
	if len(v.Rows) == 0 {
		a.push(ctx, v.Text)
		return
	}
	text, kb := encodeView(v)
	id, err := a.send.SendMessageKB(ctx, a.cfg.Telegram.ChatID, text, kb)
	if err != nil {
		log.Printf("agent: reply to /%s: %v", cmd, err)
		return
	}
	if nonce := confirmNonce(v); nonce != "" {
		a.tokens.Rebind(nonce, id)
	}
}

// failedToast is the toast of a slow action whose failure is already shown
// as a banner in the edited message.
const failedToast = "failed — see message"

// editFailedToast tells the user why a fresh message appeared instead of
// the pressed one changing.
const editFailedToast = "Couldn't update; sent as new message"

// outdatedToast answers a press whose data no current button emits: a
// button from an older version, or forged data such as a bare clear_chat.
const outdatedToast = "This button is outdated. Send /status for a fresh view."

// openFailedToast answers a view button whose new message could not be
// sent.
const openFailedToast = "Couldn't open the view. Try again."

// buildLegacy is the table of legacy callback data: every button the bot
// sends today, and those of older versions still sitting in the chat.
// Rules are tried in order, most specific first; NewLegacyTable panics at
// startup if one shadows another. Slow rules (the Docker API) are
// answered with their Ack before the work starts, so the client spinner
// stops at once. Host-changing actions are not here: they run only from
// a confirm token (confirm.go), and their legacy Yes buttons (fw_open,
// fw_close, skk:, upd_yes, clr_yes) only ever ask again. Data no rule
// claims is outdated.
func (a *Agent) buildLegacy() *tgui.LegacyTable {
	views := slices.DeleteFunc(slices.Sorted(maps.Keys(legacyViews)), func(v string) bool {
		return v == "ssh" || v == "docker" // claimed by earlier rules
	})
	return tgui.NewLegacyTable(
		// The four snooze forms; a stale one is refused by its handler.
		tgui.LegacyRule{Name: "snooze", Prefixes: []string{"snz:"}, Handle: a.snoozeCallback},
		tgui.LegacyRule{Name: "trust", Prefixes: []string{cbTrustConfirm, cbTrustCancel, cbTrust},
			Handle: func(ctx context.Context, cb *telegram.Callback, _ bool) { a.handleTrustCallback(ctx, cb) }},
		tgui.LegacyRule{Name: "dismiss", Exact: []string{"dismiss"}, Handle: func(ctx context.Context, cb *telegram.Callback, _ bool) {
			a.finishCallback(ctx, cb, false, "Update postponed — /update any time.", nil, "")
		}},
		tgui.LegacyRule{Name: "live", Exact: []string{"live"}, Handle: func(ctx context.Context, cb *telegram.Callback, _ bool) {
			a.answer(ctx, cb, "Live mode active (tap Stop to exit)")
			a.startLive(ctx, cb.ChatID, cb.MessageID)
		}},
		tgui.LegacyRule{Name: "live_stop", Exact: []string{"live_stop"}, Handle: func(ctx context.Context, cb *telegram.Callback, _ bool) {
			a.answer(ctx, cb, "")
			if !a.stopLive(cb.MessageID) {
				// No session on this message (agent restarted, or a newer
				// session took over): restore Status instead of a dead end.
				a.finishLive(cb.ChatID, cb.MessageID)
			}
		}},
		tgui.LegacyRule{Name: "firewall-apply", Exact: []string{"fw_close", "fw_open"}, Handle: a.firewallCallback},
		tgui.LegacyRule{Name: "firewall", Exact: []string{"firewall", "fw_close_ask", "fw_open_ask"}, Handle: a.firewallCallback},
		tgui.LegacyRule{Name: "ssh-kick", Prefixes: []string{"skk:"}, Handle: a.sshCallback},
		tgui.LegacyRule{Name: "ssh", Exact: []string{"ssh"}, Prefixes: []string{"sk:"}, Handle: a.sshCallback},
		tgui.LegacyRule{Name: "settings", Exact: []string{"settings", "noop", "dg:toggle"}, Prefixes: []string{"dg:hour:", "th:"},
			Handle: a.viewCallback(a.handleSettingsCallback)},
		tgui.LegacyRule{Name: "watch", Exact: []string{"watching", "scan_svc", "scan_port"},
			Prefixes: []string{"sa:", "pa:", "sr:", "xr:", "cr:", "hr:", "pr:"},
			Handle:   a.viewCallback(a.handleWatchCallback)},
		// update_confirm is the Install button of an update offer.
		tgui.LegacyRule{Name: "update-yes", Exact: []string{cbUpdateYes}, Handle: a.askAgain(actUpdate, "agent")},
		tgui.LegacyRule{Name: "clear-yes", Exact: []string{cbClearYes}, Handle: a.askAgain(actClear, "chat")},
		tgui.LegacyRule{Name: "confirm", Exact: []string{cbClearNo, "update_confirm"},
			Handle: func(ctx context.Context, cb *telegram.Callback, answered bool) {
				if cb.Data == cbClearNo {
					a.finishCallback(ctx, cb, answered, "Chat left as it is.", nil, "")
					return
				}
				a.showConfirm(ctx, cb, answered, actUpdate, "agent", false, "")
			}},
		// The Docker API can take seconds: stop the spinner first.
		tgui.LegacyRule{Name: "docker", Exact: []string{"docker"}, Slow: true, Handle: a.navCallback},
		// Old navigation buttons open the screens that replaced them;
		// anything else, including a forged clear_chat, is left unclaimed
		// and refused.
		tgui.LegacyRule{Name: "view", Exact: views, Handle: a.navCallback},
	)
}

// handleCallback routes a button press: the callback data is a command
// name, executed and rendered into the message the button lives on. Every
// press that authorize does not ignore is answered exactly once.
func (a *Agent) handleCallback(ctx context.Context, cb *telegram.Callback) {
	if tgui.IsCall(cb.Data) {
		a.handleCall(ctx, cb)
		return
	}
	// Foreign chats and impostors are ignored entirely, not even answered.
	// A press counts as a view only for the navigation views.
	_, view := legacyViews[cb.Data]
	v := a.authorize(ctx, sender{chatID: cb.ChatID, fromID: cb.FromID, chatType: cb.ChatType}, view)
	if v == ignored {
		return
	}
	if cb.Inaccessible {
		a.answer(ctx, cb, inaccessibleToast)
		return
	}
	if v == adminOnly {
		a.answer(ctx, cb, adminOnlyToast)
		return
	}
	rule, ok := a.legacy.Lookup(cb.Data)
	if !ok {
		a.refuseCallback(ctx, cb, false)
		return
	}
	if rule.Slow {
		a.answer(ctx, cb, rule.Ack)
	}
	rule.Handle(ctx, cb, rule.Slow)
}

// refuseCallback answers data no button emits with the outdated toast,
// unless a slow rule answered it already.
func (a *Agent) refuseCallback(ctx context.Context, cb *telegram.Callback, answered bool) {
	log.Printf("agent: refusing callback data of %d bytes that no button emits", len(cb.Data))
	if !answered {
		a.answer(ctx, cb, outdatedToast)
	}
}

// snoozeCallback snoozes the alert a 🔕 button of an older version
// names for an hour.
func (a *Agent) snoozeCallback(ctx context.Context, cb *telegram.Callback, _ bool) {
	key, ok := a.resolveSnoozeKey(cb.Data)
	if !ok {
		a.answer(ctx, cb, staleSnoozeToast)
		return
	}
	a.engine.Snooze(key, a.now().Add(time.Hour))
	a.answer(ctx, cb, "Snoozed for 1h")
}

// viewCallback adapts a handler that renders a view for data into a
// legacy rule handler that edits it into the pressed message.
func (a *Agent) viewCallback(h func(context.Context, string) (string, telegram.Keyboard, string, bool)) tgui.LegacyHandler {
	return func(ctx context.Context, cb *telegram.Callback, answered bool) {
		text, kb, toast, handled := h(ctx, cb.Data)
		if !handled {
			a.refuseCallback(ctx, cb, answered)
			return
		}
		a.finishCallback(ctx, cb, answered, text, kb, toast)
	}
}

// navCallback opens the screen an old navigation token stands for.
func (a *Agent) navCallback(ctx context.Context, cb *telegram.Callback, answered bool) {
	id, ok := legacyViews[cb.Data]
	if !ok {
		a.refuseCallback(ctx, cb, answered)
		return
	}
	text, kb := a.screen(ctx, tgui.Open(id))
	a.finishCallback(ctx, cb, answered, text, kb, "")
}

// askAgain is the rule of a legacy Yes button: it carries the action
// itself, so it never runs it, only opens a fresh confirm screen.
func (a *Agent) askAgain(id, target string) tgui.LegacyHandler {
	return func(ctx context.Context, cb *telegram.Callback, answered bool) {
		a.showConfirm(ctx, cb, answered, id, target, false, reconfirmToast)
	}
}

// finishCallback is the one edit path for button presses. It renders text
// into the pressed message (the client fits it to Telegram's limit) and
// answers the callback unless answered says that already happened. A fast
// view is answered after the edit so a failed edit can say so; slow work
// was answered before it ran, so its outcome toast becomes a line above
// the view instead. A failed edit falls back to a new message: the press
// is never silently lost. It returns the message the view is in now: the
// pressed one, the fallback, or 0 when none.
func (a *Agent) finishCallback(ctx context.Context, cb *telegram.Callback, answered bool, text string, kb telegram.Keyboard, toast string) int64 {
	id := cb.MessageID
	if text != "" {
		if answered && toast != "" && toast != failedToast {
			text = esc(toast) + "\n" + text
		}
		// "Message is not modified" is already success in the client.
		if err := a.send.EditMessageKB(ctx, cb.ChatID, cb.MessageID, text, kb); err != nil {
			log.Printf("agent: edit failed, sending as new message: %v", err)
			var sendErr error
			if id, sendErr = a.send.SendMessageKB(ctx, cb.ChatID, text, kb); sendErr != nil {
				log.Printf("agent: edit fallback: %v", sendErr)
				id = 0
			}
			if toast == "" {
				toast = editFailedToast
			}
		}
	}
	if !answered {
		a.answer(ctx, cb, toast)
	}
	return id
}

// answer acknowledges a button press, stopping the client spinner; a
// non-empty toast shows briefly.
func (a *Agent) answer(ctx context.Context, cb *telegram.Callback, toast string) {
	if err := a.send.AnswerCallback(ctx, cb.ID, toast); err != nil {
		log.Printf("agent: answerCallback: %v", err)
	}
}

// callbackDigest returns a fixed-size hex fingerprint of s for Telegram
// callback_data payloads (truncated SHA-256, 8 bytes → 16 hex chars).
func callbackDigest(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:8])
}

// resolveSnoozeKey reads the alert key of the snooze buttons of older
// versions: snz:d:<key> and snz:h:<digest>, and before them snz:<key> and
// snz:h<crc32>. The hashed forms resolve only while the process that sent
// them runs.
func (a *Agent) resolveSnoozeKey(data string) (string, bool) {
	// New namespaced forms (preferred).
	if key, ok := strings.CutPrefix(data, "snz:d:"); ok {
		return key, key != ""
	}
	if digest, ok := strings.CutPrefix(data, "snz:h:"); ok {
		if digest == "" {
			return "", false
		}
		a.mu.Lock()
		key, found := a.snoozeKeys[digest]
		a.mu.Unlock()
		return key, found
	}
	// Legacy forms from #64: snz:<key> and snz:h<8-hex CRC32>.
	value, ok := strings.CutPrefix(data, "snz:")
	if !ok || value == "" {
		return "", false
	}
	if hexDigits, hashed := strings.CutPrefix(value, "h"); hashed && len(hexDigits) == 8 {
		if _, err := strconv.ParseUint(hexDigits, 16, 32); err == nil {
			a.mu.Lock()
			key, found := a.snoozeKeys[hexDigits]
			a.mu.Unlock()
			return key, found
		}
	}
	return value, true
}

// legacyCRC32Hex returns the 8-char lowercase CRC32 hex used by pre-SHA-256 callbacks.
func legacyCRC32Hex(s string) string {
	return fmt.Sprintf("%08x", crc32.ChecksumIEEE([]byte(s)))
}
