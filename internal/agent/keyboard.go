package agent

import (
	"context"
	"log"
	"strings"

	"github.com/eliau2005/statixagent/internal/alert"
	"github.com/eliau2005/statixagent/internal/bot"
	"github.com/eliau2005/statixagent/internal/telegram"
)

// navViews are the commands reachable from the navigation keyboard. A reply
// to any of them carries the keyboard, and pressing a button edits the same
// message into the chosen view — the chat stays a single live dashboard
// instead of a scroll of stale reports.
var navViews = map[string]bool{
	"status": true, "cpu": true, "mem": true, "disk": true, "net": true,
	"temp": true, "battery": true, "services": true, "docker": true, "ssh": true,
}

// navKeyboard renders the navigation rows; the active view is highlighted.
func navKeyboard(active string) telegram.Keyboard {
	rows := [][]struct{ label, cmd string }{
		{{"📊 Status", "status"}, {"🖥 CPU", "cpu"}, {"🧠 Mem", "mem"}},
		{{"💾 Disk", "disk"}, {"🌐 Net", "net"}, {"🌡 Temp", "temp"}},
		{{"🔋 Power", "battery"}, {"🧩 Svc", "services"}, {"🐳 Dock", "docker"}},
		{{"🔐 SSH", "ssh"}, {"▶️ Live", "live"}, {"🔄 Refresh", active}},
		{{"👁 Watching", "watching"}, {"⚙️ Settings", "settings"}},
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

// updateKeyboard is attached to "new version available" messages.
func updateKeyboard() telegram.Keyboard {
	return telegram.Keyboard{{
		{Text: "⬇️ Install now", Data: "update_confirm"},
		{Text: "Later", Data: "dismiss"},
	}}
}

// alertKeyboard maps an alert to one-tap context actions: the alert message
// itself becomes the relevant view when a button is pressed.
func alertKeyboard(key string) telegram.Keyboard {
	prefix, _, _ := strings.Cut(key, ":")
	var row []telegram.Button
	switch prefix {
	case "ssh-login", "ssh-brute", "keys":
		row = []telegram.Button{
			{Text: "👥 Sessions", Data: "ssh"},
			{Text: "🚫 Fails", Data: "ssh_fails"},
			{Text: "🛡 Firewall", Data: "firewall"},
		}
	case "cpu":
		row = []telegram.Button{{Text: "🖥 CPU", Data: "cpu"}, {Text: "📊 Status", Data: "status"}}
	case "mem":
		row = []telegram.Button{{Text: "🧠 Memory", Data: "mem"}, {Text: "📊 Status", Data: "status"}}
	case "disk":
		row = []telegram.Button{{Text: "💾 Disk", Data: "disk"}, {Text: "📊 Status", Data: "status"}}
	case "temp":
		row = []telegram.Button{{Text: "🌡 Temp", Data: "temp"}, {Text: "📊 Status", Data: "status"}}
	case "battery", "power-loss", "power-restored":
		row = []telegram.Button{{Text: "🔋 Power", Data: "battery"}, {Text: "📊 Status", Data: "status"}}
	default:
		row = []telegram.Button{{Text: "📊 Status", Data: "status"}}
	}
	return telegram.Keyboard{row}
}

// pushAlert renders and sends an alert with its context buttons.
func (a *Agent) pushAlert(ctx context.Context, al alert.Alert) {
	html := bot.AlertMsg(a.src.Hostname, al)
	if _, err := a.send.SendMessageKB(ctx, a.cfg.Telegram.ChatID, html, alertKeyboard(al.Key)); err != nil {
		log.Printf("agent: alert push failed: %v", err)
	}
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

// handleCallback routes a button press: the callback data is a command
// name, executed and rendered into the message the button lives on.
func (a *Agent) handleCallback(ctx context.Context, cb *telegram.Callback) {
	if cb.ChatID != a.cfg.Telegram.ChatID {
		return // foreign chat: ignore entirely, do not even answer
	}
	switch cb.Data {
	case "dismiss":
		a.send.AnswerCallback(ctx, cb.ID, "")
		a.send.EditMessageKB(ctx, cb.ChatID, cb.MessageID, "Update postponed — /update any time.", nil)
		return
	case "live":
		a.send.AnswerCallback(ctx, cb.ID, "Live for 30s")
		a.startLive(ctx, cb.ChatID, cb.MessageID)
		return
	case "live_stop":
		a.send.AnswerCallback(ctx, cb.ID, "")
		a.stopLive()
		return
	}
	if text, kb, toast, handled := a.handleFirewallCallback(ctx, cb.Data); handled {
		a.send.AnswerCallback(ctx, cb.ID, toast)
		if text != "" {
			if err := a.send.EditMessageKB(ctx, cb.ChatID, cb.MessageID, text, kb); err != nil {
				log.Printf("agent: edit: %v", err)
			}
		}
		return
	}
	if text, kb, toast, handled := a.handleSettingsCallback(ctx, cb.Data); handled {
		a.send.AnswerCallback(ctx, cb.ID, toast)
		if text != "" {
			if err := a.send.EditMessageKB(ctx, cb.ChatID, cb.MessageID, text, kb); err != nil {
				log.Printf("agent: edit: %v", err)
			}
		}
		return
	}
	if text, kb, toast, handled := a.handleWatchCallback(ctx, cb.Data); handled {
		a.send.AnswerCallback(ctx, cb.ID, toast)
		if text != "" {
			if err := a.send.EditMessageKB(ctx, cb.ChatID, cb.MessageID, text, kb); err != nil {
				log.Printf("agent: edit: %v", err)
			}
		}
		return
	}
	reply, ok := a.router.Invoke(ctx, cb.Data, nil)
	if !ok {
		a.send.AnswerCallback(ctx, cb.ID, "unknown action")
		return
	}
	toast := ""
	if cb.Data == "update_confirm" {
		toast = "Updating…"
	}
	if err := a.send.AnswerCallback(ctx, cb.ID, toast); err != nil {
		log.Printf("agent: answerCallback: %v", err)
	}
	var kb telegram.Keyboard
	if navViews[cb.Data] {
		kb = navKeyboard(cb.Data)
	}
	if err := a.send.EditMessageKB(ctx, cb.ChatID, cb.MessageID, reply, kb); err != nil {
		log.Printf("agent: edit: %v", err)
	}
}
