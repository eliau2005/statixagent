package agent

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"net/netip"
	"os/exec"
	"slices"
	"strconv"
	"strings"

	"github.com/eliau2005/statixagent/internal/services"
	"github.com/eliau2005/statixagent/internal/telegram"
	"github.com/eliau2005/statixagent/internal/tgui"
)

// Firewall control: open/close the SSH port through ufw. This is the
// agent's first remediation action, so it follows MVP §7 strictly — every
// state change goes through a confirm token (confirm.go), and closing SSH
// is confirmed twice, warning that shell access will be lost (the bot
// remains the way back).
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
	fwOpen                          // the first matching rule allows (ALLOW or LIMIT)
	fwClosed                        // the first matching rule blocks (DENY or REJECT)
	fwUnmanaged                     // active, but no rule matches 22 (default policy decides)
)

// parseUFWStatus reads `ufw status` output. It stays pure — whether ufw
// exists at all is probeUFW's job — and only says what the text says: the
// first-match verdict for port 22 from an arbitrary IPv4 host.
//
// The status line is not necessarily the first: the runner merges stderr
// into the output, so an interpreter warning or one of ufw's own WARN
// lines can precede it. Anchoring on line 0 would read a healthy firewall
// as unparseable and silently withdraw every action button.
func parseUFWStatus(out string) sshPortState {
	s := parseUFWOutput(out)
	switch {
	case !s.found:
		return fwUnparsed
	case !s.active:
		return fwInactive
	}
	return s.verdict(22, false, netip.Addr{}).state
}

// ufwProbe is the outcome of one `ufw status` attempt. out and err stay
// separate all the way to the display layer: flattening them here would
// feed an exec-level message ("permission denied" on the binary) to
// sandboxHint, which only knows how to fix ufw's own file writes.
type ufwProbe struct {
	bin   string // the binary that answered; empty when none did
	state sshPortState
	out   string    // ufw's own combined output
	err   error     // the underlying exec error, if any
	fw    ufwStatus // parsed rules; from `status verbose` when it answered
}

// manageable reports whether ufw is active and its rules were read.
func (p ufwProbe) manageable() bool {
	return p.state == fwOpen || p.state == fwClosed || p.state == fwUnmanaged
}

// detail renders the probe outcome for display.
func (p ufwProbe) detail() string { return detail(p.out, p.err) }

// probeUFW resolves ufw and classifies its status. Availability lives here
// rather than in the parser because "not installed", "refused to run" and
// "answered with something I cannot read" need different words and
// different advice — collapsing them is what made the view lie.
func (a *Agent) probeUFW(ctx context.Context) ufwProbe { return probeUFW(ctx, a.src.Runner) }

// probeUFW is the probe with an explicit runner, for the backend.
func probeUFW(ctx context.Context, run services.Runner) ufwProbe {
	var lastErr error
	for _, bin := range ufwPaths {
		out, err := run.Run(ctx, bin, "status")
		switch {
		case err == nil:
			p := ufwProbe{bin: bin, state: parseUFWStatus(out), out: out, fw: parseUFWOutput(out)}
			if p.manageable() {
				probeUFWVerbose(ctx, run, &p)
			}
			return p
		case notFound(err):
			lastErr = err // try the next candidate path
		default:
			return ufwProbe{bin: bin, state: fwUnusable, out: out, err: err}
		}
	}
	return ufwProbe{state: fwMissing, err: lastErr}
}

// probeUFWVerbose refines an active probe with `ufw status verbose`, which
// adds the default policy and expands app profiles to their ports
// ("22/tcp (OpenSSH)"). Plain status prints only "OpenSSH", so without
// this an app-profile ALLOW cannot be matched to port 22. Any failure
// keeps the plain-status result.
func probeUFWVerbose(ctx context.Context, run services.Runner, p *ufwProbe) {
	out, err := run.Run(ctx, p.bin, "status", "verbose")
	if err != nil {
		return
	}
	if s := parseUFWOutput(out); s.active {
		p.fw = s
		p.state = s.verdict(22, false, netip.Addr{}).state
	}
}

// notFound reports whether the command could not be located. A PATH lookup
// fails with exec.ErrNotFound; an absolute path that does not exist gets
// past the lookup and fails in Start with fs.ErrNotExist.
func notFound(err error) bool {
	return errors.Is(err, exec.ErrNotFound) || errors.Is(err, fs.ErrNotExist)
}

// firewallView renders the 🛡 Firewall screen as a message.
func (a *Agent) firewallView(ctx context.Context) (string, telegram.Keyboard) {
	return a.screen(ctx, tgui.Open(scrFirewall))
}

// firewallScreen is the 🛡 screen, with the action buttons the probed
// state allows.
func (a *Agent) firewallScreen(ctx context.Context, _ tgui.Call) tgui.View {
	if a.src.Runner == nil {
		return tgui.View{Text: "🛡 Firewall control unavailable in this build."}
	}
	return a.firewallFor(ctx, a.detectFw(ctx))
}

// firewallFor renders what detection found. Rule-changing buttons appear
// only in the states the agent can actually act on: ufw or firewalld
// with port 22 open, closed, or active-but-unmanaged, and no conflict.
// They open a confirm screen; the token on its Yes is what changes the
// rules.
func (a *Agent) firewallFor(ctx context.Context, f fwFound) tgui.View {
	open := tgui.Button{Label: "🔓 Open port 22", Call: tgui.Call{Act: askFwOpen}}
	closeBtn := tgui.Button{Label: "🔒 Close port 22", Call: tgui.Call{Act: askFwClose}, Style: "danger"}
	p := f.ufw
	switch {
	case f.kind == fwKindNft || f.kind == fwKindIptables:
		return readOnlyFwView(f)
	case f.kind == fwKindFirewalld && !f.p.manageable():
		return tgui.View{Text: "🛡 <b>Firewall</b> · firewalld\n" + esc(upperFirst(firewalldRefusal(f.p).display())) +
			"\n" + preBlock(f.p.detail())}
	case f.b != nil:
		p = f.p
	}
	switch p.state {
	case fwMissing:
		return tgui.View{Text: "🛡 <b>Firewall</b>\n" +
			"<code>ufw</code> is not installed (or not on the agent's PATH) — the agent cannot manage this host's firewall.\n" +
			"That does not mean the host is open: firewalld, nftables or iptables may be enforcing rules, and containers are usually filtered by the host.\n" +
			"To let the agent manage port 22, install ufw on the server: " + a.ufwInstallHint()}
	case fwUnusable:
		return tgui.View{Text: "🛡 <b>Firewall</b>\n<code>ufw</code> is installed but the agent could not query it:\n" +
			preBlock(p.detail())}
	case fwInactive:
		return tgui.View{Text: "🛡 <b>Firewall</b>\nufw is installed but <b>inactive</b> — all ports are open.\nEnable it on the server first: <code>ufw enable</code>"}
	case fwUnparsed:
		return tgui.View{Text: "🛡 <b>Firewall</b>\n<code>ufw status</code> returned output the agent could not read — " +
			"the firewall state is <b>unknown</b>, so no changes are offered.\n" +
			preBlock(p.out)}
	}
	// The rules and the ways to change them (fwrules.go), then port 22.
	// Closing SSH is offered only when the owner opted in (Decision 15).
	// Restoring a snapshot is ufw's: firewalld's own way back is its
	// permanent configuration.
	rules := tgui.Button{Label: "📋 Rules", Call: tgui.Open(scrFwRules)}
	if f.conflict {
		return tgui.View{Text: a.firewallState(ctx, f) + "\n⚠️ " + esc(upperFirst(fwConflictText)) + ".",
			Rows: [][]tgui.Button{{rules}}}
	}
	var row []tgui.Button
	if f.kind == fwKindUFW {
		row = append(row, tgui.Button{Label: "↩️ Restore previous", Call: tgui.Open(scrFwRestore)})
	}
	if p.state != fwOpen {
		row = append(row, open)
	}
	if p.state != fwClosed && a.cfg.Firewall.AllowCloseSSH {
		row = append(row, closeBtn)
	}
	rows := [][]tgui.Button{{rules, {Label: "➕ Open port", Call: tgui.Open(scrFwAdd)},
		{Label: "🧱 Presets", Call: tgui.Open(scrFwPresets)}}}
	if len(row) > 0 {
		rows = append(rows, row)
	}
	return tgui.View{Text: a.firewallState(ctx, f), Rows: rows}
}

// firewallSummary is the one-line firewall state of the Security screen.
func (a *Agent) firewallSummary(ctx context.Context) string {
	if a.src.Runner == nil {
		return "unavailable"
	}
	f := a.detectFw(ctx)
	switch {
	case f.conflict:
		return "ufw + firewalld conflict"
	case f.kind == fwKindNft || f.kind == fwKindIptables:
		return f.kind + " (read-only)"
	case f.kind == fwKindFirewalld:
		switch f.p.state {
		case fwOpen:
			return "firewalld · SSH open"
		case fwClosed:
			return "firewalld · SSH closed"
		case fwUnmanaged:
			return "firewalld · SSH by target"
		}
		return "firewalld unreadable"
	}
	switch f.ufw.state {
	case fwMissing:
		return "no ufw"
	case fwUnusable:
		return "ufw unreadable"
	case fwInactive:
		return "ufw inactive"
	case fwUnparsed:
		return "ufw unknown"
	case fwOpen:
		return "ufw · SSH open"
	case fwClosed:
		return "ufw · SSH closed"
	}
	return "ufw · SSH by policy"
}

// closeSSHOff is the answer to a Close SSH press while
// firewall.allow_close_ssh is off.
const closeSSHOff = "⛔ <b>Closing the SSH port from Telegram is turned off.</b>\n" +
	"Close it from a shell, or set <code>allow_close_ssh = true</code> under <code>[firewall]</code> " +
	"in the agent's config.toml and restart the agent."

// firewallState describes an active ufw or firewalld: the first-match
// verdict for port 22 (the port the buttons act on), any other port sshd
// accepts on, and Docker-published ports, which bypass the firewall's
// INPUT rules altogether.
func (a *Agent) firewallState(ctx context.Context, f fwFound) string {
	p := f.p
	var b strings.Builder
	if fwd, ok := f.b.(*firewalldBackend); ok {
		b.WriteString("🛡 <b>Firewall</b> · firewalld · zone <b>" + esc(fwd.zone) + "</b>\n" +
			"Changes go to the running rules; Keep makes them permanent.\n")
	} else {
		b.WriteString("🛡 <b>Firewall</b> · ufw active\n")
	}
	if p.fw.policy != "" {
		b.WriteString("Default incoming policy: <b>" + esc(p.fw.policy) + "</b>\n")
	}
	v4 := p.fw.verdict(22, false, netip.Addr{})
	b.WriteString("SSH port 22: " + describeVerdict(v4))
	if v6 := p.fw.verdict(22, true, netip.Addr{}); p.fw.hasV6() && v6.state != v4.state {
		b.WriteString("\nIPv6: " + describeVerdict(v6))
	}
	ports := a.sshPorts(ctx)
	if !slices.Contains(ports, 22) {
		b.WriteString("\n⚠️ sshd does not appear to accept connections on 22; the buttons below still act on port 22.")
	}
	for _, port := range ports {
		if port != 22 {
			b.WriteString("\nSSH port " + strconv.Itoa(port) + ": " + describeVerdict(p.fw.verdict(port, false, netip.Addr{})))
		}
	}
	if peers := a.adminPeers(ctx, ports); len(peers) > 0 {
		var names []string
		for i, p := range peers {
			if i == 3 {
				names = append(names, fmt.Sprintf("+%d more", len(peers)-3))
				break
			}
			names = append(names, p.String())
		}
		label := "Your SSH peer: "
		if len(peers) > 1 {
			label = "Your SSH peers: "
		}
		b.WriteString("\n" + label + esc(strings.Join(names, ", ")))
	}
	v6 := 0
	for _, r := range p.fw.rules {
		if r.V6 {
			v6++
		}
	}
	fmt.Fprintf(&b, "\nRules: %d (v4 %d · v6 %d)", len(p.fw.rules), len(p.fw.rules)-v6, v6)
	if w := a.dockerPortsWarning(ctx, f.kind); w != "" {
		b.WriteString("\n" + w)
	}
	return b.String()
}

// describeVerdict renders a port verdict with the rule that decided it, so
// the user can see *why* a port is open, not just that it is.
func describeVerdict(v portVerdict) string {
	var s string
	switch {
	case v.state == fwOpen:
		s = "🔓 <b>open</b> (rule " + ruleRef(*v.rule) + ")"
	case v.state == fwClosed:
		s = "🔒 <b>closed</b> (rule " + ruleRef(*v.rule) + ")"
	case v.policy == "allow":
		s = "no explicit rule — default incoming policy <b>allow</b> applies (🔓 open)"
	case v.policy != "":
		s = "no explicit rule — default incoming policy <b>" + esc(v.policy) + "</b> applies (🔒 blocked)"
	default:
		s = "no explicit rule (ufw default policy applies)"
	}
	// Narrower allows only matter when the port is otherwise blocked.
	if v.state != fwOpen && v.policy != "allow" {
		for i, r := range v.except {
			if i == 3 {
				s += "\n  …"
				break
			}
			s += "\n  still allowed by rule " + ruleRef(r)
		}
	}
	for i, r := range v.unsure {
		if i == 3 {
			break
		}
		s += "\n  ⚠️ rule " + ruleRef(r) + " is an app profile whose ports are unknown; it may match first"
	}
	return s
}

// ruleRef is "N: <row as ufw printed it>", escaped for HTML.
func ruleRef(r fwRule) string {
	return strconv.Itoa(r.Num) + ": " + esc(truncate(r.Raw, 80))
}

// dockerPortsWarning names the ports Docker publishes. They are forwarded
// before the INPUT chain of fw (ufw or firewalld) sees them, so its rules
// — including a DENY shown above — do not apply. Empty when Docker is not
// monitored or unreachable.
func (a *Agent) dockerPortsWarning(ctx context.Context, fw string) string {
	if a.src.Docker == nil || !a.cfg.Monitors.Docker {
		return ""
	}
	pp, err := a.src.Docker.PublishedPorts(ctx)
	if err != nil || len(pp) == 0 {
		return ""
	}
	var names []string
	for i, p := range pp {
		if i == 8 {
			names = append(names, "…")
			break
		}
		names = append(names, esc(fmt.Sprintf("%d/%s (%s)", p.Port, p.Proto, p.Container)))
	}
	return "⚠️ Docker publishes " + strings.Join(names, ", ") + " — " + fw + " does not filter these."
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
// cannot push the rest of the view out of the message, and wrapped to a
// phone's width.
func preBlock(out string) string {
	out = strings.TrimSpace(out)
	if out == "" {
		return "<pre>(no output)</pre>"
	}
	return pre(strings.Split(truncate(out, 300), "\n"))
}

// firewallCallback handles the legacy 🛡 buttons: the view, and the Open
// and Close buttons, which open a confirm screen. fw_open and fw_close are the Yes
// buttons of older versions: they carry the action itself, so they only
// ever ask again, bound to a fresh token.
func (a *Agent) firewallCallback(ctx context.Context, cb *telegram.Callback, answered bool) {
	switch cb.Data {
	case "firewall":
		text, kb := a.firewallView(ctx)
		a.finishCallback(ctx, cb, answered, text, kb, "")
	case "fw_open_ask":
		a.showConfirm(ctx, cb, answered, actFwOpen, sshPort, false, "")
	case "fw_open":
		a.showConfirm(ctx, cb, answered, actFwOpen, sshPort, false, reconfirmToast)
	case "fw_close_ask", "fw_close":
		// The close prompt itself refuses while the opt-in is off.
		toast := ""
		if cb.Data == "fw_close" {
			toast = reconfirmToast
		}
		a.showConfirm(ctx, cb, answered, actFwClose, sshPort, false, toast)
	default:
		a.refuseCallback(ctx, cb, answered)
	}
}

// verifySSHPort checks a post-change probe against the intended state of
// port 22, in both families when ufw holds IPv6 rules. A mismatch is a
// failure, never a success toast.
func verifySSHPort(p ufwProbe, open bool) *fwFailure {
	want, word := fwClosed, "closed"
	if open {
		want, word = fwOpen, "open"
	}
	if !p.manageable() {
		return &fwFailure{reason: "the firewall accepted the change, but the agent could not read the rules back to confirm port 22 is " + word}
	}
	for _, v6 := range []bool{false, true} {
		if v6 && !p.fw.hasV6() {
			continue
		}
		v := p.fw.verdict(22, v6, netip.Addr{})
		if v.state == want {
			continue
		}
		family := ""
		if v6 {
			family = " for IPv6"
		}
		reason := "the firewall accepted the change, but port 22 is not " + word + family
		if v.rule != nil {
			reason += ": rule " + strconv.Itoa(v.rule.Num) + " (" + v.rule.Raw + ") matches first"
		} else {
			reason += ": no rule matches, so the default policy decides"
		}
		return &fwFailure{reason: reason}
	}
	return nil
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

// probeRefusal is why a rule change cannot run in the probed state, nil
// when it can. A Telegram inline keyboard stays live on older messages,
// so a change can arrive long after the view that offered it: after ufw
// was removed or disabled, or from a replayed callback. The action path
// refuses in exactly the states the view offers no button for. Writing a
// rule into a disabled ufw would "succeed" while nothing is enforced.
func probeRefusal(p ufwProbe) *fwFailure {
	switch p.state {
	case fwMissing:
		return &fwFailure{reason: "ufw is not installed on this host — the agent cannot change firewall rules here"}
	case fwUnusable:
		return &fwFailure{cmd: p.bin + " status", out: p.out, err: p.err}
	case fwInactive:
		return &fwFailure{reason: "ufw is installed but inactive — a rule added now would not be enforced. Enable it on the server first: ufw enable"}
	case fwUnparsed:
		return &fwFailure{reason: "the agent could not read this host's ufw state, so it will not change rules blindly"}
	}
	return nil
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
