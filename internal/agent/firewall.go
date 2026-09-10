package agent

import (
	"context"
	"errors"
	"io/fs"
	"os/exec"
	"strings"

	"github.com/eliau2005/statixagent/internal/telegram"
)

// Firewall control: open/close the SSH port through ufw. This is the
// agent's first remediation action, so it follows MVP §7 strictly — every
// state change goes through an explicit confirmation screen, and closing
// SSH warns that shell access will be lost (the bot remains the way back).
//
// ufw is optional, and absent more often than not: Alpine, Arch, Debian
// netinst/cloud images and containers ship without it, and the RHEL family
// firewalls with firewalld. A firewall view is a security control, so each
// state below is reported for exactly what it is — saying "I cannot manage
// the firewall here" is far better than guessing that the host is open.

const sshPort = "22/tcp"

// ufwPaths are tried in order: the service PATH first, then the usual sbin
// locations, so a PATH without sbin is not mistaken for a missing package.
var ufwPaths = []string{"ufw", "/usr/sbin/ufw", "/sbin/ufw"}

// sshPortState is the parsed ufw view of port 22.
type sshPortState int

const (
	fwMissing   sshPortState = iota // binary not resolvable anywhere
	fwUnusable                      // present, but the probe failed (not root, blocked, timeout)
	fwInactive                      // present, `Status: inactive`
	fwUnparsed                      // exit 0, unrecognised output (wrapper, non-ufw binary)
	fwOpen                          // explicit ALLOW rule
	fwClosed                        // explicit DENY rule
	fwUnmanaged                     // active, but no rule for 22
)

// parseUFWStatus reads `ufw status` output. It stays pure — whether ufw
// exists at all is probeUFW's job — and only says what the text says.
//
// The status line is not necessarily the first: the runner merges stderr
// into the output, so an interpreter warning or one of ufw's own WARN
// lines can precede it. Anchoring on line 0 would read a healthy firewall
// as unparseable and silently withdraw every action button.
func parseUFWStatus(out string) sshPortState {
	lines := strings.Split(out, "\n")
	head := -1
	for i, line := range lines {
		if strings.Contains(strings.ToLower(line), "status:") {
			head = i
			break
		}
	}
	if head < 0 {
		return fwUnparsed
	}
	if !strings.Contains(strings.ToLower(lines[head]), "status: active") {
		return fwInactive
	}
	state := fwUnmanaged
	for _, line := range lines[head+1:] {
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

// ufwProbe is the outcome of one `ufw status` attempt. out and err stay
// separate all the way to the display layer: flattening them here would
// feed an exec-level message ("permission denied" on the binary) to
// sandboxHint, which only knows how to fix ufw's own file writes.
type ufwProbe struct {
	bin   string // the binary that answered; empty when none did
	state sshPortState
	out   string // ufw's own combined output
	err   error  // the underlying exec error, if any
}

// detail renders the probe outcome for display.
func (p ufwProbe) detail() string { return detail(p.out, p.err) }

// probeUFW resolves ufw and classifies its status. Availability lives here
// rather than in the parser because "not installed", "refused to run" and
// "answered with something I cannot read" need different words and
// different advice — collapsing them is what made the view lie.
func (a *Agent) probeUFW(ctx context.Context) ufwProbe {
	var lastErr error
	for _, bin := range ufwPaths {
		out, err := a.src.Runner.Run(ctx, bin, "status")
		switch {
		case err == nil:
			return ufwProbe{bin: bin, state: parseUFWStatus(out), out: out}
		case notFound(err):
			lastErr = err // try the next candidate path
		default:
			return ufwProbe{bin: bin, state: fwUnusable, out: out, err: err}
		}
	}
	return ufwProbe{state: fwMissing, err: lastErr}
}

// notFound reports whether the command could not be located. A PATH lookup
// fails with exec.ErrNotFound; an absolute path that does not exist gets
// past the lookup and fails in Start with fs.ErrNotExist.
func notFound(err error) bool {
	return errors.Is(err, exec.ErrNotFound) || errors.Is(err, fs.ErrNotExist)
}

// firewallView renders the 🛡 screen with the appropriate action button.
// Rule-changing buttons appear only in the states the agent can actually
// act on: open, closed, and active-but-unmanaged.
func (a *Agent) firewallView(ctx context.Context) (string, telegram.Keyboard) {
	back := []telegram.Button{{Text: "⬅️ Status", Data: "status"}, {Text: "🔐 SSH", Data: "ssh"}}
	if a.src.Runner == nil {
		return "🛡 Firewall control unavailable in this build.", telegram.Keyboard{back}
	}
	p := a.probeUFW(ctx)
	switch p.state {
	case fwMissing:
		return "🛡 <b>Firewall</b>\n" +
			"<code>ufw</code> is not installed (or not on the agent's PATH) — the agent cannot manage this host's firewall.\n" +
			"That does not mean the host is open: firewalld, nftables or iptables may be enforcing rules, and containers are usually filtered by the host.\n" +
			"To let the agent manage port 22, install ufw on the server: " + a.ufwInstallHint(), telegram.Keyboard{back}
	case fwUnusable:
		return "🛡 <b>Firewall</b>\n<code>ufw</code> is installed but the agent could not query it:\n" +
			preBlock(p.detail()), telegram.Keyboard{back}
	case fwInactive:
		return "🛡 <b>Firewall</b>\nufw is installed but <b>inactive</b> — all ports are open.\nEnable it on the server first: <code>ufw enable</code>", telegram.Keyboard{back}
	case fwUnparsed:
		return "🛡 <b>Firewall</b>\n<code>ufw status</code> returned output the agent could not read — " +
			"the firewall state is <b>unknown</b>, so no changes are offered.\n" +
			preBlock(p.out), telegram.Keyboard{back}
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

// ufwInstallHint names the package-manager command for this host's distro,
// falling back to the common ones when /etc/os-release is unavailable.
func (a *Agent) ufwInstallHint() string {
	if a.src.OSRelease == nil {
		return ufwInstallHint(nil)
	}
	return ufwInstallHint(a.src.OSRelease())
}

// preBlock renders command output for display, clipped so a chatty tool
// cannot push the rest of the view out of the message.
func preBlock(out string) string {
	out = strings.TrimSpace(out)
	if out == "" {
		return "<pre>(no output)</pre>"
	}
	return "<pre>" + esc(truncate(out, 300)) + "</pre>"
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
		return a.applyAndRender(ctx, false)

	case "fw_open":
		return a.applyAndRender(ctx, true)
	}
	return "", nil, "", false
}

// applyAndRender runs the rule change and re-renders the firewall view. On
// failure it prepends a persistent error banner (with the raw ufw output)
// so the cause stays visible instead of vanishing as a toast.
func (a *Agent) applyAndRender(ctx context.Context, open bool) (string, telegram.Keyboard, string, bool) {
	okMsg, fail := a.setSSHPort(ctx, open)
	text, kb := a.firewallView(ctx)
	if fail != nil {
		banner := "❌ <b>Change failed</b>\n<pre>" + esc(fail.display()) + "</pre>\n"
		if hint := sandboxHint(fail); hint != "" {
			banner += hint + "\n"
		}
		return banner + text, kb, "failed — see message", true
	}
	return text, kb, okMsg, true
}

// fwFailure describes a failed rule change. ufw's own output is kept apart
// from the exec error on purpose: only the former is worth showing verbatim,
// and only the former can be fixed by the sandbox hint below.
type fwFailure struct {
	cmd    string // the ufw invocation that failed
	out    string // ufw's own combined output
	err    error  // the underlying exec error, if any
	reason string // pre-formatted message when no command was run at all
}

// display is the text shown in the "Change failed" block.
func (f *fwFailure) display() string {
	if f.reason != "" {
		return f.reason
	}
	return f.cmd + "\n" + detail(f.out, f.err)
}

// sandboxHint detects the read-only-filesystem failure (the service's
// systemd hardening blocking ufw's rule writes) and returns the one-time
// fix to run on the server. It matches ufw's *own* output only: an
// exec-level failure — a missing binary, or `exec: "ufw": permission
// denied` from a noexec mount or MAC policy — is a different problem that
// ReadWritePaths cannot fix. Empty for unrelated errors.
func sandboxHint(f *fwFailure) string {
	if f == nil || f.out == "" || notFound(f.err) {
		return ""
	}
	low := strings.ToLower(f.out)
	if !strings.Contains(low, "not writeable") && !strings.Contains(low, "read-only") &&
		!strings.Contains(low, "permission denied") {
		return ""
	}
	return "The agent's sandbox is blocking ufw. Run this once on the server, then retry:\n" +
		"<pre>sudo mkdir -p /etc/systemd/system/statix-agent.service.d\n" +
		"printf '[Service]\\nReadWritePaths=-/etc/ufw -/lib/ufw\\n' | \\\n" +
		"  sudo tee /etc/systemd/system/statix-agent.service.d/ufw.conf\n" +
		"sudo systemctl daemon-reload\n" +
		"sudo systemctl restart statix-agent</pre>"
}

// setSSHPort applies the rule change: the opposite rule is removed first so
// ufw's first-match ordering cannot mask the new rule. Returns a success
// toast and, on failure, the structured reason for display.
func (a *Agent) setSSHPort(ctx context.Context, open bool) (okMsg string, fail *fwFailure) {
	if a.src.Runner == nil {
		return "", &fwFailure{reason: "firewall control unavailable in this build"}
	}
	// A Telegram inline keyboard stays live on older messages, so a change
	// can arrive long after the view that offered it — after ufw was
	// removed, or from a replayed callback. Re-check before touching
	// anything, so the answer is a sentence rather than an exec error.
	p := a.probeUFW(ctx)
	// The action path refuses in exactly the states the view offers no
	// button for, so a replayed callback can never outrun a change on the
	// server. Writing a rule into a disabled ufw would "succeed" and report
	// port 22 closed while nothing is enforced.
	switch p.state {
	case fwMissing:
		return "", &fwFailure{reason: "ufw is not installed on this host — the agent cannot change firewall rules here"}
	case fwUnusable:
		return "", &fwFailure{cmd: p.bin + " status", out: p.out, err: p.err}
	case fwInactive:
		return "", &fwFailure{reason: "ufw is installed but inactive — a rule added now would not be enforced. Enable it on the server first: ufw enable"}
	case fwUnparsed:
		return "", &fwFailure{reason: "the agent could not read this host's ufw state, so it will not change rules blindly"}
	}
	oldRule, newRule := "deny", "allow"
	if !open {
		oldRule, newRule = "allow", "deny"
	}
	// Delete may fail when no such rule exists — that is fine.
	a.src.Runner.Run(ctx, p.bin, "--force", "delete", oldRule, sshPort)
	if out, err := a.src.Runner.Run(ctx, p.bin, newRule, sshPort); err != nil {
		return "", &fwFailure{cmd: "ufw " + newRule + " " + sshPort, out: out, err: err}
	}
	// Re-apply the ruleset: rule edits alone do not reliably reach the
	// live iptables state on all setups (observed in the field).
	if out, err := a.src.Runner.Run(ctx, p.bin, "reload"); err != nil {
		return "", &fwFailure{cmd: "ufw reload", out: out, err: err}
	}
	if open {
		return "🔓 port 22 opened", nil
	}
	return "🔒 port 22 closed", nil
}

// detail combines command output and error for a readable failure message.
// The tool's own words win: they say more than "exit status 1". err may be
// nil — a probe failure is carried as text by the time it reaches here.
func detail(out string, err error) string {
	switch out = strings.TrimSpace(out); {
	case out != "":
		return out
	case err != nil:
		return err.Error()
	}
	return "no output"
}
