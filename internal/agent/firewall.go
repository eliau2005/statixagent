package agent

import (
	"context"
	"strings"

	"github.com/eliau2005/statixagent/internal/telegram"
)

// Firewall control: open/close the SSH port through ufw. This is the
// agent's first remediation action, so it follows MVP §7 strictly — every
// state change goes through an explicit confirmation screen, and closing
// SSH warns that shell access will be lost (the bot remains the way back).

const sshPort = "22/tcp"

// sshPortState is the parsed ufw view of port 22.
type sshPortState int

const (
	fwUnavailable sshPortState = iota // ufw missing or inactive
	fwOpen                            // explicit ALLOW rule
	fwClosed                          // explicit DENY rule
	fwUnmanaged                       // active, but no rule for 22
)

// parseUFWStatus reads `ufw status` output.
func parseUFWStatus(out string) sshPortState {
	lines := strings.Split(out, "\n")
	if len(lines) == 0 || !strings.Contains(strings.ToLower(lines[0]), "status: active") {
		return fwUnavailable
	}
	state := fwUnmanaged
	for _, line := range lines[1:] {
		f := strings.Fields(line)
		if len(f) < 2 || (f[0] != "22" && f[0] != "22/tcp") {
			continue
		}
		switch strings.ToUpper(f[1]) {
		case "ALLOW":
			if state == fwUnmanaged {
				state = fwOpen
			}
		case "DENY", "REJECT":
			state = fwClosed // an explicit block wins the summary
		}
	}
	return state
}

// firewallView renders the 🛡 screen with the appropriate action button.
func (a *Agent) firewallView(ctx context.Context) (string, telegram.Keyboard) {
	back := []telegram.Button{{Text: "⬅️ Status", Data: "status"}, {Text: "🔐 SSH", Data: "ssh"}}
	if a.src.Runner == nil {
		return "🛡 Firewall control unavailable in this build.", telegram.Keyboard{back}
	}
	out, err := a.src.Runner.Run(ctx, "ufw", "status")
	if err != nil {
		return "🛡 <b>Firewall</b>\nufw is not available: " + esc(err.Error()), telegram.Keyboard{back}
	}
	switch parseUFWStatus(out) {
	case fwUnavailable:
		return "🛡 <b>Firewall</b>\nufw is installed but <b>inactive</b> — all ports are open.\nEnable it on the server first: <code>ufw enable</code>", telegram.Keyboard{back}
	case fwOpen:
		return "🛡 <b>Firewall</b>\nSSH port 22: 🔓 <b>open</b> (ALLOW rule)",
			telegram.Keyboard{{{Text: "🔒 Close port 22", Data: "fw_close_ask"}}, back}
	case fwClosed:
		return "🛡 <b>Firewall</b>\nSSH port 22: 🔒 <b>closed</b> (DENY rule)",
			telegram.Keyboard{{{Text: "🔓 Open port 22", Data: "fw_open_ask"}}, back}
	default: // fwUnmanaged
		return "🛡 <b>Firewall</b>\nSSH port 22: no explicit rule (ufw default policy applies)",
			telegram.Keyboard{
				{{Text: "🔓 Open port 22", Data: "fw_open_ask"}, {Text: "🔒 Close port 22", Data: "fw_close_ask"}},
				back,
			}
	}
}

// handleFirewallCallback processes 🛡 buttons; same contract as the other
// callback handlers.
func (a *Agent) handleFirewallCallback(ctx context.Context, data string) (string, telegram.Keyboard, string, bool) {
	switch data {
	case "firewall":
		text, kb := a.firewallView(ctx)
		return text, kb, "", true

	case "fw_close_ask":
		return "⚠️ <b>Close SSH port 22?</b>\n" +
				"Active sessions stay up, but <b>new SSH connections will be refused</b>.\n" +
				"This bot keeps working and can reopen the port.",
			telegram.Keyboard{
				{{Text: "✅ Yes, close it", Data: "fw_close"}, {Text: "❌ Cancel", Data: "firewall"}},
			}, "", true

	case "fw_open_ask":
		return "<b>Open SSH port 22?</b>\nIncoming SSH connections will be allowed.",
			telegram.Keyboard{
				{{Text: "✅ Yes, open it", Data: "fw_open"}, {Text: "❌ Cancel", Data: "firewall"}},
			}, "", true

	case "fw_close":
		toast := a.setSSHPort(ctx, false)
		text, kb := a.firewallView(ctx)
		return text, kb, toast, true

	case "fw_open":
		toast := a.setSSHPort(ctx, true)
		text, kb := a.firewallView(ctx)
		return text, kb, toast, true
	}
	return "", nil, "", false
}

// setSSHPort applies the rule change: the opposite rule is removed first so
// ufw's first-match ordering cannot mask the new rule.
func (a *Agent) setSSHPort(ctx context.Context, open bool) string {
	if a.src.Runner == nil {
		return "unavailable"
	}
	oldRule, newRule := "deny", "allow"
	if !open {
		oldRule, newRule = "allow", "deny"
	}
	// Delete may fail when no such rule exists — that is fine.
	a.src.Runner.Run(ctx, "ufw", "--force", "delete", oldRule, sshPort)
	if out, err := a.src.Runner.Run(ctx, "ufw", newRule, sshPort); err != nil {
		return "ufw failed: " + firstLine(out, err.Error())
	}
	// Re-apply the ruleset: rule edits alone do not reliably reach the
	// live iptables state on all setups (observed in the field).
	if out, err := a.src.Runner.Run(ctx, "ufw", "reload"); err != nil {
		return "rule saved but reload failed: " + firstLine(out, err.Error())
	}
	if open {
		return "🔓 port 22 opened"
	}
	return "🔒 port 22 closed"
}

func firstLine(s, fallback string) string {
	s = strings.TrimSpace(s)
	if s == "" {
		return fallback
	}
	if i := strings.IndexByte(s, '\n'); i > 0 {
		return s[:i]
	}
	return s
}
