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
// session. Like the firewall, every kick goes through a confirm token
// (confirm.go), and a second one when it is the only session listed; the
// kill is SIGKILL on the session's tty.

// ttyPattern guards pkill's argv: utmp bytes come from the wire in
// principle, so a tty must never look like a flag or shell text.
var ttyPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9/._-]*$`)

func validTTY(tty string) bool {
	return ttyPattern.MatchString(tty)
}

// sshSessionsView renders the 👥 screen. Kick buttons carry the index plus
// an identity fingerprint, re-resolved against a fresh Sessions() call
// when pressed and again on Yes, so a shifted list can never retarget a
// kick.
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
	return bot.Sessions(sessions, geo, a.now()), kb
}

// sshCallback handles 👥 buttons: the list, and sk: (Kick), which opens
// the confirm screen for the session it was drawn for. A skk: button of
// an older version carries the action itself, so it only ever asks
// again, bound to a fresh token.
func (a *Agent) sshCallback(ctx context.Context, cb *telegram.Callback, answered bool) {
	data := cb.Data
	var s sshwatch.Session
	var ok bool
	toast := ""
	switch {
	case data == "ssh":
		text, kb := a.sshSessionsView(ctx)
		a.finishCallback(ctx, cb, answered, text, kb, "")
		return

	case strings.HasPrefix(data, "sk:"):
		n, fp, valid := parseSessionData(strings.TrimPrefix(data, "sk:"))
		if !valid || fp == "" {
			// Legacy sk:<n> or garbage: an index alone names no session.
			text, kb := a.sshSessionsView(ctx)
			a.finishCallback(ctx, cb, answered, text, kb, "List refreshed")
			return
		}
		s, ok = a.sessionByIdentity(n, fp)

	case strings.HasPrefix(data, "skk:"):
		n, fp, valid := parseSessionData(strings.TrimPrefix(data, "skk:"))
		switch {
		case !valid:
		case fp == "":
			// skk:<n> predates fingerprints: ask about whatever sits at
			// that index now.
			s, ok = a.sessionAt(n)
		default:
			s, ok = a.sessionByIdentity(n, fp)
		}
		toast = reconfirmToast
	}
	if !ok {
		text, kb := a.sshSessionsView(ctx)
		a.finishCallback(ctx, cb, answered, text, kb, sessionGoneToast)
		return
	}
	a.showConfirm(ctx, cb, answered, actKick, sessionFingerprint(s), false, toast)
}

// kickConfirmText asks before disconnecting session s.
func kickConfirmText(s sshwatch.Session) string {
	return "⚠️ <b>Disconnect SSH session?</b>\n" +
		"<b>" + esc(s.User) + "</b> on <code>" + esc(s.TTY) + "</code> from " + esc(s.Host) +
		" — connected " + bot.Dur(time.Since(s.Since)) + "\n" +
		"All processes on this terminal get SIGKILL.\n" +
		"⚠️ If this is <b>your own session</b>, your shell will be cut off. " +
		"The bot keeps running and you can reconnect (unless port 22 is closed)."
}

// kickOnlyText is the second confirm for the only session listed, which
// is likely the user's own.
func kickOnlyText(s sshwatch.Session) string {
	return "⚠️ <b>This is the only SSH session.</b>\n" +
		"<b>" + esc(s.User) + "</b> on <code>" + esc(s.TTY) + "</code> from " + esc(s.Host) +
		" is probably <b>you</b>: your shell will be cut off and nobody stays logged in over SSH.\n" +
		"The bot keeps running and you can reconnect (unless port 22 is closed)."
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

// sessionByFingerprint re-reads the live sessions and returns the one
// with fingerprint fp, wherever it sits now, and how many are listed.
func (a *Agent) sessionByFingerprint(fp string) (sshwatch.Session, int, bool) {
	if a.src.Sessions == nil {
		return sshwatch.Session{}, 0, false
	}
	sessions, err := a.src.Sessions()
	if err != nil {
		return sshwatch.Session{}, 0, false
	}
	for _, s := range sessions {
		if sessionFingerprint(s) == fp {
			return s, len(sessions), true
		}
	}
	return sshwatch.Session{}, len(sessions), false
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
// empty output means the former — the session is already gone. what is
// the plain-text outcome; trace is the command, for the audit log.
func (a *Agent) kickSession(ctx context.Context, s sshwatch.Session) (what, errDetail string, trace *cmdTrace) {
	if a.src.Runner == nil {
		return "", "session control unavailable in this build", nil
	}
	if !validTTY(s.TTY) {
		return "", "refusing to signal suspicious tty " + s.TTY, nil
	}
	trace = &cmdTrace{argv: []string{"pkill", "-KILL", "-t", s.TTY}}
	start := time.Now()
	out, err := a.src.Runner.Run(ctx, trace.argv[0], trace.argv[1:]...)
	trace.out, trace.err, trace.dur = out, err, time.Since(start)
	switch {
	case err == nil:
		return s.User + " disconnected", "", trace
	case strings.TrimSpace(out) == "":
		return "Session already gone", "", trace
	default:
		return "", fmt.Sprintf("pkill -KILL -t %s\n%s", s.TTY, detail(out, err)), trace
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
