package agent

import (
	"context"
	"log"
	"strings"

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
		{{"🔐 SSH", "ssh"}, {"🔄 Refresh", active}},
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

// reply sends a command reply, attaching the navigation keyboard to view
// commands and the install button to update offers.
func (a *Agent) reply(ctx context.Context, cmd, html string) {
	chatID := a.cfg.Telegram.ChatID
	var kb telegram.Keyboard
	switch {
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
	if cb.Data == "dismiss" {
		a.send.AnswerCallback(ctx, cb.ID, "")
		a.send.EditMessageKB(ctx, cb.ChatID, cb.MessageID, "Update postponed — /update any time.", nil)
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
