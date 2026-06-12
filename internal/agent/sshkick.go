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

// sshSessionsView renders the 👥 screen. The rendered list is snapshotted
// under a.mu so sk:/skk: callbacks resolve indexes against exactly what the
// user saw (same pattern as lastServiceScan).
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
	a.mu.Lock()
	a.lastSessions = append([]sshwatch.Session(nil), sessions...)
	a.mu.Unlock()

	var kb telegram.Keyboard
	if a.src.Runner != nil {
		for i, s := range sessions {
			if !validTTY(s.TTY) {
				continue // no terminal to signal (or suspicious bytes)
			}
			kb = append(kb, []telegram.Button{{
				Text: "🚫 Kick " + truncate(s.User+" "+s.TTY, 24),
				Data: "sk:" + strconv.Itoa(i+1),
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
		idx := strings.TrimPrefix(data, "sk:")
		s, ok := a.sessionByIndex(idx)
		if !ok {
			text, kb := a.sshSessionsView(ctx)
			return text, kb, "list changed — refreshed", true
		}
		return "⚠️ <b>Disconnect SSH session?</b>\n" +
				"<b>" + esc(s.User) + "</b> on <code>" + esc(s.TTY) + "</code> from " + esc(s.Host) +
				" — connected " + bot.Dur(time.Since(s.Since)) + "\n" +
				"All processes on this terminal get SIGKILL.\n" +
				"⚠️ If this is <b>your own session</b>, your shell will be cut off. " +
				"The bot keeps running and you can reconnect (unless port 22 is closed).",
			telegram.Keyboard{
				{{Text: "✅ Yes, disconnect", Data: "skk:" + idx}, {Text: "❌ Cancel", Data: "ssh"}},
			}, "", true

	case strings.HasPrefix(data, "skk:"):
		s, ok := a.sessionByIndex(strings.TrimPrefix(data, "skk:"))
		if !ok {
			text, kb := a.sshSessionsView(ctx)
			return text, kb, "list changed — refreshed", true
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

// sessionByIndex resolves a 1-based index against the last rendered list;
// the world may have changed since the buttons were drawn.
func (a *Agent) sessionByIndex(arg string) (sshwatch.Session, bool) {
	n, err := strconv.Atoi(arg)
	a.mu.Lock()
	defer a.mu.Unlock()
	if err != nil || n < 1 || n > len(a.lastSessions) {
		return sshwatch.Session{}, false
	}
	return a.lastSessions[n-1], true
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
