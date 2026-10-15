package agent

import (
	"context"
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/eliau2005/statixagent/internal/bot"
	"github.com/eliau2005/statixagent/internal/sshwatch"
	"github.com/eliau2005/statixagent/internal/telegram"
)

// SSH session control: the 👥 view carries one disconnect button per live
// session. Like the firewall, every kick goes through an explicit
// confirmation screen (MVP §7); the kill is SIGKILL on the session's tty.

// ttyPattern guards pkill's argv: utmp bytes come from the wire in
// principle, so a tty must never look like a flag or shell text.
var ttyPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9/._-]*$`)

func validTTY(tty string) bool {
	return ttyPattern.MatchString(tty)
}

// sshSessionsView renders the 👥 screen. Kick buttons carry the index plus
// an identity fingerprint, and sk:/skk: re-resolve them against a fresh
// Sessions() call, so a shifted list can never retarget a kick.
func (a *Agent) sshSessionsView(ctx context.Context) (string, telegram.Keyboard) {
	if a.src.Sessions == nil {
		return "Session listing unavailable.", navKeyboard("ssh")
	}
	sessions, err := a.src.Sessions()
	if err != nil {
		return "Could not read sessions: " + esc(err.Error()), navKeyboard("ssh")
	}
	geo := map[string]sshwatch.GeoInfo{}
	for _, s := range sessions {
		geo[s.Host] = a.geo.Lookup(ctx, s.Host)
	}
	var kb telegram.Keyboard
	if a.src.Runner != nil {
		for i, s := range sessions {
			if !validTTY(s.TTY) {
				continue // no terminal to signal (or suspicious bytes)
			}
			kb = append(kb, []telegram.Button{{
				Text: "🚫 Kick " + truncate(s.User+" "+s.TTY, 24),
				Data: sessionCallbackData("sk:", i+1, s),
			}})
		}
	}
	kb = append(kb, navKeyboard("ssh")...)
	return bot.Sessions(sessions, geo, time.Now()), kb
}

// handleSSHCallback processes 👥 buttons; same contract as the other
// callback handlers.
func (a *Agent) handleSSHCallback(ctx context.Context, data string) (string, telegram.Keyboard, string, bool) {
	switch {
	case data == "ssh":
		text, kb := a.sshSessionsView(ctx)
		return text, kb, "", true

	case strings.HasPrefix(data, "sk:"):
		n, fp, ok := parseSessionData(strings.TrimPrefix(data, "sk:"))
		if !ok || fp == "" {
			// Legacy sk:<n> or garbage: an index alone names no session.
			text, kb := a.sshSessionsView(ctx)
			return text, kb, "List refreshed", true
		}
		s, ok := a.sessionByIdentity(n, fp)
		if !ok {
			text, kb := a.sshSessionsView(ctx)
			return text, kb, "Session changed, refreshed", true
		}
		text, kb := kickConfirm(n, s)
		return text, kb, "", true

	case strings.HasPrefix(data, "skk:"):
		n, fp, ok := parseSessionData(strings.TrimPrefix(data, "skk:"))
		if ok && fp == "" {
			// Legacy skk:<n> from an old keyboard: re-prompt for whatever
			// sits at that index now, bound to its identity. Never execute.
			if s, found := a.sessionAt(n); found {
				text, kb := kickConfirm(n, s)
				return text, kb, "Please confirm again", true
			}
			ok = false
		}
		var s sshwatch.Session
		if ok {
			s, ok = a.sessionByIdentity(n, fp)
		}
		if !ok {
			text, kb := a.sshSessionsView(ctx)
			return text, kb, "Session changed, refreshed", true
		}
		okMsg, errDetail := a.kickSession(ctx, s)
		text, kb := a.sshSessionsView(ctx)
		if errDetail != "" {
			banner := "❌ <b>Disconnect failed</b>\n<pre>" + esc(errDetail) + "</pre>\n"
			banner += kickSandboxHint(errDetail) + "\n"
			return banner + text, kb, "failed — see message", true
		}
		return text, kb, okMsg, true
	}
	return "", nil, "", false
}

// kickConfirm renders the disconnect confirmation for session s at 1-based
// index n; the Yes button is bound to s's identity, not just its position.
func kickConfirm(n int, s sshwatch.Session) (string, telegram.Keyboard) {
	return "⚠️ <b>Disconnect SSH session?</b>\n" +
			"<b>" + esc(s.User) + "</b> on <code>" + esc(s.TTY) + "</code> from " + esc(s.Host) +
			" — connected " + bot.Dur(time.Since(s.Since)) + "\n" +
			"All processes on this terminal get SIGKILL.\n" +
			"⚠️ If this is <b>your own session</b>, your shell will be cut off. " +
			"The bot keeps running and you can reconnect (unless port 22 is closed).",
		telegram.Keyboard{
			{{Text: "✅ Yes, disconnect", Data: sessionCallbackData("skk:", n, s)}, {Text: "❌ Cancel", Data: "ssh"}},
		}
}

// sessionFingerprint identifies one login: a later session on the same tty
// differs at least in start time, so a stale button cannot reach it.
func sessionFingerprint(s sshwatch.Session) string {
	return callbackDigest(s.User + "|" + s.TTY + "|" + s.Host + "|" + strconv.FormatInt(s.Since.Unix(), 10))
}

// sessionCallbackData encodes <prefix><n>:<fp16>; at most ~25 bytes.
func sessionCallbackData(prefix string, n int, s sshwatch.Session) string {
	return prefix + strconv.Itoa(n) + ":" + sessionFingerprint(s)
}

// parseSessionData splits "<n>:<fp16>", or the legacy bare "<n>" with an
// empty fp.
func parseSessionData(arg string) (int, string, bool) {
	idx, fp, hasFP := strings.Cut(arg, ":")
	n, err := strconv.Atoi(idx)
	if err != nil || n < 1 {
		return 0, "", false
	}
	if !hasFP {
		return n, "", true
	}
	if len(fp) != 16 {
		return 0, "", false
	}
	for _, c := range fp {
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return 0, "", false
		}
	}
	return n, fp, true
}

// sessionAt reads a fresh listing and returns its 1-based nth session.
func (a *Agent) sessionAt(n int) (sshwatch.Session, bool) {
	if a.src.Sessions == nil {
		return sshwatch.Session{}, false
	}
	sessions, err := a.src.Sessions()
	if err != nil || n < 1 || n > len(sessions) {
		return sshwatch.Session{}, false
	}
	return sessions[n-1], true
}

// sessionByIdentity re-reads the live sessions and returns the nth one only
// if it is still the login the button was drawn for.
func (a *Agent) sessionByIdentity(n int, fp string) (sshwatch.Session, bool) {
	s, ok := a.sessionAt(n)
	if !ok || sessionFingerprint(s) != fp {
		return sshwatch.Session{}, false
	}
	return s, true
}

// kickSession sends SIGKILL to every process on the session's terminal.
// pkill exits non-zero both when nothing matched and when signaling failed;
// empty output means the former — the session is already gone.
func (a *Agent) kickSession(ctx context.Context, s sshwatch.Session) (okMsg, errDetail string) {
	if a.src.Runner == nil {
		return "", "session control unavailable in this build"
	}
	if !validTTY(s.TTY) {
		return "", "refusing to signal suspicious tty " + s.TTY
	}
	out, err := a.src.Runner.Run(ctx, "pkill", "-KILL", "-t", s.TTY)
	switch {
	case err == nil:
		return "👢 " + s.User + " disconnected", ""
	case strings.TrimSpace(out) == "":
		return "session already gone", ""
	default:
		return "", fmt.Sprintf("pkill -KILL -t %s\n%s", s.TTY, detail(out, err))
	}
}

// kickSandboxHint explains a permission failure: the service must run as
// root (or keep CAP_KILL) to signal other users' processes. Empty for
// unrelated errors.
func kickSandboxHint(errDetail string) string {
	low := strings.ToLower(errDetail)
	if !strings.Contains(low, "operation not permitted") && !strings.Contains(low, "permission denied") {
		return ""
	}
	return "The agent lacks permission to signal that session's processes. " +
		"Check the service runs as root and no drop-in sets <code>User=</code> " +
		"or strips <code>CAP_KILL</code> via <code>CapabilityBoundingSet=</code>."
}
