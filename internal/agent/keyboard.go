package agent

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"hash/crc32"
	"log"
	"strconv"
	"strings"
	"time"

	"github.com/eliau2005/statixagent/internal/alert"
	"github.com/eliau2005/statixagent/internal/bot"
	"github.com/eliau2005/statixagent/internal/telegram"
	"github.com/eliau2005/statixagent/internal/tgui"
)

// navViews are the commands reachable from the navigation keyboard. A reply
// to any of them carries the keyboard, and pressing a button edits the same
// message into the chosen view — the chat stays a single live dashboard
// instead of a scroll of stale reports. It is also the allowlist of router
// commands a button may run: callback data is never handed to the router
// otherwise, so forged data cannot reach a command meant to be typed.
var navViews = map[string]bool{
	"status": true, "cpu": true, "mem": true, "disk": true, "net": true,
	"temp": true, "battery": true, "services": true, "docker": true, "ssh": true,
	"top": true, "digest": true, "ssl": true, "http": true,
	// Alert-button views: the keyboard's Refresh re-runs the same view.
	"ssh_history": true, "ssh_fails": true,
}

// navKeyboard renders the navigation rows; the active view is highlighted.
func navKeyboard(active string) telegram.Keyboard {
	rows := [][]struct{ label, cmd string }{
		{{"📊 Status", "status"}, {"🖥 CPU", "cpu"}, {"🧠 Mem", "mem"}},
		{{"💾 Disk", "disk"}, {"🌐 Net", "net"}, {"🌡 Temp", "temp"}},
		{{"🔋 Power", "battery"}, {"🧩 Svc", "services"}, {"🐳 Dock", "docker"}},
		{{"🔐 SSH", "ssh"}, {"▶️ Live", "live"}, {"🔄 Refresh", active}},
		{{"🔝 Top", "top"}, {"👁 Watching", "watching"}, {"⚙️ Settings", "settings"}},
	}
	var kb telegram.Keyboard
	for _, row := range rows {
		var btns []telegram.Button
		for _, b := range row {
			label := b.label
			if b.cmd == active && b.cmd != "" && !strings.HasPrefix(label, "🔄") {
				label = "• " + label
			}
			btns = append(btns, telegram.Button{Text: label, Data: b.cmd})
		}
		kb = append(kb, btns)
	}
	return kb
}

// Confirm buttons of the update and clear-chat prompts. Each Yes press is
// authorized again on its own, like any other button.
const (
	cbUpdateYes = "upd_yes"
	cbClearYes  = "clr_yes"
	cbClearNo   = "clr_no"
)

// updateKeyboard is attached to "new version available" messages: the
// offer itself is the confirm, so Install runs the update.
func updateKeyboard() telegram.Keyboard {
	return telegram.Keyboard{{
		{Text: "⬇️ Install now", Data: cbUpdateYes},
		{Text: "Later", Data: "dismiss"},
	}}
}

// updateConfirmKeyboard answers a typed /update_confirm.
func updateConfirmKeyboard() telegram.Keyboard {
	return telegram.Keyboard{{
		{Text: "✅ Yes, install", Data: cbUpdateYes},
		{Text: "❌ Cancel", Data: "dismiss"},
	}}
}

// clearConfirmKeyboard answers a typed /clear_chat.
func clearConfirmKeyboard() telegram.Keyboard {
	return telegram.Keyboard{{
		{Text: "✅ Yes, clear", Data: cbClearYes},
		{Text: "❌ Cancel", Data: cbClearNo},
	}}
}

// alertKeyboard maps an alert to one-tap context actions: the alert message
// itself becomes the relevant view when a button is pressed.
func (a *Agent) alertKeyboard(key string) telegram.Keyboard {
	prefix, _, _ := strings.Cut(key, ":")
	var row []telegram.Button
	switch prefix {
	case "ssh-login", "ssh-newkey", "ssh-brute", "keys":
		row = []telegram.Button{
			{Text: "👥 Sessions", Data: "ssh"},
			{Text: "🚫 Fails", Data: "ssh_fails"},
			{Text: "🛡 Firewall", Data: "firewall"},
		}
	case "cpu":
		row = []telegram.Button{
			{Text: "🔝 Top", Data: "top"},
			{Text: "🖥 CPU", Data: "cpu"},
			{Text: "📊 Status", Data: "status"},
		}
	case "mem":
		row = []telegram.Button{
			{Text: "🔝 Top", Data: "top"},
			{Text: "🧠 Memory", Data: "mem"},
			{Text: "📊 Status", Data: "status"},
		}
	case "disk":
		row = []telegram.Button{{Text: "💾 Disk", Data: "disk"}, {Text: "📊 Status", Data: "status"}}
	case "temp":
		row = []telegram.Button{{Text: "🌡 Temp", Data: "temp"}, {Text: "📊 Status", Data: "status"}}
	case "ssl":
		row = []telegram.Button{{Text: "🔒 Certs", Data: "ssl"}, {Text: "📊 Status", Data: "status"}}
	case "docker", "docker-up", "docker-restart":
		row = []telegram.Button{{Text: "🐳 Containers", Data: "docker"}, {Text: "📊 Status", Data: "status"}}
	case "battery", "power-loss", "power-restored":
		row = []telegram.Button{{Text: "🔋 Power", Data: "battery"}, {Text: "📊 Status", Data: "status"}}
	default:
		row = []telegram.Button{{Text: "📊 Status", Data: "status"}}
	}
	row = append(row, telegram.Button{Text: "🔕 1h", Data: a.snoozeCallbackData(key)})
	return telegram.Keyboard{row}
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

// stashKB lets a handler attach a custom keyboard to its pending reply.
func (a *Agent) stashKB(kb telegram.Keyboard) {
	a.mu.Lock()
	a.pendingKB = kb
	a.mu.Unlock()
}

func (a *Agent) popKB() telegram.Keyboard {
	a.mu.Lock()
	defer a.mu.Unlock()
	kb := a.pendingKB
	a.pendingKB = nil
	return kb
}

// reply sends a command reply, attaching the handler's stashed keyboard,
// the navigation keyboard for view commands, or the install button for
// update offers.
func (a *Agent) reply(ctx context.Context, cmd, html string) {
	chatID := a.cfg.Telegram.ChatID
	kb := a.popKB()
	switch {
	case kb != nil:
	case navViews[cmd]:
		kb = navKeyboard(cmd)
	case cmd == "update" && strings.Contains(html, "/update_confirm"):
		kb = updateKeyboard()
	}
	if kb == nil {
		a.push(ctx, html)
		return
	}
	if _, err := a.send.SendMessageKB(ctx, chatID, html, kb); err != nil {
		log.Printf("agent: reply: %v", err)
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

// slowCallback reports presses whose work can take seconds (ufw, pkill,
// the Docker API, the updater) and the toast to answer them with before
// that work starts, so the client spinner stops at once.
func slowCallback(data string) (toast string, slow bool) {
	switch {
	case data == "fw_close", data == "fw_open", strings.HasPrefix(data, "skk:"):
		return "Working…", true
	case data == "docker":
		return "", true
	case data == cbUpdateYes:
		return "Updating…", true
	case data == cbClearYes:
		return "Clearing…", true
	}
	return "", false
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
	v := a.authorize(ctx, sender{chatID: cb.ChatID, fromID: cb.FromID, chatType: cb.ChatType}, navViews[cb.Data])
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
	if key, ok := a.resolveSnoozeKey(cb.Data); ok {
		a.engine.Snooze(key, time.Now().Add(time.Hour))
		a.answer(ctx, cb, "Snoozed for 1h")
		return
	}
	if strings.HasPrefix(cb.Data, "snz:") {
		a.answer(ctx, cb, "stale snooze")
		return
	}
	if a.handleTrustCallback(ctx, cb) {
		return
	}
	switch cb.Data {
	case "dismiss":
		a.finishCallback(ctx, cb, false, "Update postponed — /update any time.", nil, "")
		return
	case "live":
		a.answer(ctx, cb, "Live mode active (tap Stop to exit)")
		a.startLive(ctx, cb.ChatID, cb.MessageID)
		return
	case "live_stop":
		a.answer(ctx, cb, "")
		if !a.stopLive(cb.MessageID) {
			// No session on this message (agent restarted, or a newer
			// session took over): restore Status instead of a dead end.
			a.finishLive(cb.ChatID, cb.MessageID)
		}
		return
	}
	toast, answered := slowCallback(cb.Data)
	if answered {
		a.answer(ctx, cb, toast)
	}
	handlers := []func(context.Context, string) (string, telegram.Keyboard, string, bool){
		a.handleFirewallCallback, a.handleSSHCallback, a.handleSettingsCallback, a.handleWatchCallback,
		a.handleConfirmCallback,
	}
	for _, h := range handlers {
		if text, kb, toast, handled := h(ctx, cb.Data); handled {
			a.finishCallback(ctx, cb, answered, text, kb, toast)
			return
		}
	}
	// Only the views a button emits reach the router; anything else,
	// including the old update_confirm and a forged clear_chat, is refused.
	reply, ok := "", navViews[cb.Data]
	if ok {
		reply, ok = a.router.Invoke(ctx, cb.Data, nil)
	}
	if !ok {
		log.Printf("agent: refusing callback data of %d bytes that no button emits", len(cb.Data))
		if !answered {
			a.answer(ctx, cb, outdatedToast)
		}
		return
	}
	a.finishCallback(ctx, cb, answered, reply, navKeyboard(cb.Data), "")
}

// handleConfirmCallback runs the Yes and Cancel buttons of the update and
// clear-chat prompts.
func (a *Agent) handleConfirmCallback(ctx context.Context, data string) (string, telegram.Keyboard, string, bool) {
	switch data {
	case cbUpdateYes:
		return a.applyUpdate(ctx), nil, "", true
	case cbClearYes:
		// The sweep deletes the prompt too, so the outcome is a new
		// message rather than an edit.
		a.push(ctx, a.clearChat(ctx))
		return "", nil, "", true
	case cbClearNo:
		return "Chat left as it is.", nil, "", true
	case "update_confirm":
		// The Install button of an older version: ask again rather than
		// refuse, so an update offer already in the chat still works, but
		// never install from it directly.
		if a.src.UpdateCheck == nil || a.src.UpdateApply == nil {
			return "Self-update is not configured in this build.", nil, "", true
		}
		return "⬇️ <b>Install the update?</b>\nThe agent will restart.", updateConfirmKeyboard(), "Please confirm again", true
	}
	return "", nil, "", false
}

// finishCallback is the one edit path for button presses. It renders text
// into the pressed message (the client fits it to Telegram's limit) and
// answers the callback unless answered says that already happened. A fast
// view is answered after the edit so a failed edit can say so; slow work
// was answered before it ran, so its outcome toast becomes a line above
// the view instead. A failed edit falls back to a new message: the press
// is never silently lost.
func (a *Agent) finishCallback(ctx context.Context, cb *telegram.Callback, answered bool, text string, kb telegram.Keyboard, toast string) {
	if text != "" {
		if answered && toast != "" && toast != failedToast {
			text = esc(toast) + "\n" + text
		}
		// "Message is not modified" is already success in the client.
		if err := a.send.EditMessageKB(ctx, cb.ChatID, cb.MessageID, text, kb); err != nil {
			log.Printf("agent: edit failed, sending as new message: %v", err)
			if _, err := a.send.SendMessageKB(ctx, cb.ChatID, text, kb); err != nil {
				log.Printf("agent: edit fallback: %v", err)
			}
			if toast == "" {
				toast = editFailedToast
			}
		}
	}
	if !answered {
		a.answer(ctx, cb, toast)
	}
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

// snoozeCallbackData keeps ordinary alert keys in callback_data so buttons
// remain valid across restarts. Only oversized keys use the in-memory hash map.
// Namespaces: snz:d:<key> (direct) and snz:h:<digest> (hashed) never collide.
func (a *Agent) snoozeCallbackData(key string) string {
	direct := "snz:d:" + key
	if len(direct) <= 64 {
		return direct
	}
	digest := callbackDigest(key)
	a.mu.Lock()
	a.snoozeKeys[digest] = key
	a.mu.Unlock()
	return "snz:h:" + digest
}

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
