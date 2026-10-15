package agent

import (
	"context"
	"fmt"
	"log"
	"net/netip"
	"slices"
	"strings"

	"github.com/eliau2005/statixagent/internal/bot"
	"github.com/eliau2005/statixagent/internal/config"
	"github.com/eliau2005/statixagent/internal/sshwatch"
	"github.com/eliau2005/statixagent/internal/telegram"
	"github.com/eliau2005/statixagent/internal/tgui"
)

// Trusted SSH sources managed from the bot. config.toml's ssh.trusted_ips
// stays the static baseline; /trust, /untrust and the "Trust this IP"
// button on plain SSH login alerts edit a separate state file
// (sshwatch.TrustStore). Both are merged into one matcher that is swapped
// in on every change, so a change applies to the very next login.
//
// The button is confirmation-gated like a session kick or a firewall
// change: the first tap swaps the alert's keyboard for a confirm screen,
// and only "Yes, trust" acts. Only the keyboard is ever edited, so the
// alert text (user, source, geo) stays as sent.

// maxTelegramTrusted caps the bot-managed list: it is meant for a handful
// of home or office addresses, not a firewall.
const maxTelegramTrusted = 64

// Callback namespaces for the trust button: tip: opens the confirm
// screen, tipk: trusts, tipc: cancels. The payload is always the source
// address in canonical form, re-parsed and checked on every press.
const (
	cbTrust        = "tip:"
	cbTrustConfirm = "tipk:"
	cbTrustCancel  = "tipc:"
)

// Trust sources, as shown to the user.
const (
	srcConfig   = "config.toml"
	srcTelegram = "Telegram"
)

// maxTrustAlerts bounds the message → alert-key map used to restore a
// login alert's keyboard on Cancel; past it the map starts over.
const maxTrustAlerts = 256

// rebuildTrust merges the config baseline with the bot-managed entries and
// swaps in a new matcher. known_keys is loaded the first time the merged
// list is non-empty, before the matcher that needs it is published.
// Callers other than New hold a.trustMu.
func (a *Agent) rebuildTrust() {
	merged := append(slices.Clone(a.configTrusted), a.trustStore.Entries()...)
	m := sshwatch.NewTrustedIPs(merged)
	if !m.Empty() && a.knownKeys.Load() == nil {
		known, err := sshwatch.LoadKnownKeys(a.src.KnownKeysPath)
		if err != nil {
			// Keep what was read: bad lines are skipped (and kept on disk),
			// so at worst a known key alerts once more as new.
			log.Printf("agent: %v", err)
		}
		a.knownKeys.Store(known)
	}
	a.trusted.Store(m)
}

// trustMatch is an existing entry that equals or covers a prefix.
type trustMatch struct {
	entry  netip.Prefix
	source string // srcConfig or srcTelegram
	exact  bool
}

// findTrust returns the entry equal to p or, failing that, the first one
// covering it. Config entries are checked first.
func (a *Agent) findTrust(p netip.Prefix) (trustMatch, bool) {
	var covered *trustMatch
	check := func(entries []netip.Prefix, source string) bool {
		for _, q := range entries {
			if q == p {
				covered = &trustMatch{q, source, true}
				return true
			}
			if covered == nil && q.Bits() <= p.Bits() && q.Contains(p.Addr()) {
				covered = &trustMatch{entry: q, source: source}
			}
		}
		return false
	}
	if !check(a.configTrusted, srcConfig) {
		check(a.trustStore.Entries(), srcTelegram)
	}
	if covered == nil {
		return trustMatch{}, false
	}
	return *covered, true
}

// trustResult is the outcome of a trust change: html for a command reply,
// line for the short label that replaces an alert's keyboard.
type trustResult struct {
	html string
	line string
}

// trustAdd adds p to the bot-managed list unless it is already trusted or
// the list is full, and applies it immediately.
func (a *Agent) trustAdd(p netip.Prefix) trustResult {
	a.trustMu.Lock()
	defer a.trustMu.Unlock()
	shown := sshwatch.FormatPrefix(p)
	if m, ok := a.findTrust(p); ok {
		if m.exact {
			return trustResult{
				html: fmt.Sprintf("☑️ <code>%s</code> is already trusted (%s).", esc(shown), m.source),
				line: "☑️ Already trusted (" + m.source + ")",
			}
		}
		other := sshwatch.FormatPrefix(m.entry)
		return trustResult{
			html: fmt.Sprintf("☑️ <code>%s</code> is already covered by <code>%s</code> (%s).", esc(shown), esc(other), m.source),
			line: "☑️ Already trusted via " + other,
		}
	}
	if a.trustStore.Len() >= maxTelegramTrusted {
		return trustResult{
			html: fmt.Sprintf("⚠️ Limit of %d Telegram-trusted entries reached; /untrust one first.", maxTelegramTrusted),
			line: fmt.Sprintf("⚠️ Not trusted: limit of %d reached", maxTelegramTrusted),
		}
	}
	_, err := a.trustStore.Add(p)
	a.rebuildTrust()
	log.Printf("agent: SSH source %s trusted from Telegram", shown)
	r := trustResult{
		html: fmt.Sprintf("✅ Trusted <code>%s</code>. Its SSH logins no longer alert.\n"+
			"Root logins, logins with a new key and logins right after failed attempts still do.\n"+
			"/untrust %s to undo.", esc(shown), esc(shown)),
		line: "✅ Trusted " + shown,
	}
	if err != nil {
		log.Printf("agent: %v", err)
		r.html += "\n(⚠️ not saved, it will not survive a restart: " + esc(err.Error()) + ")"
		r.line += " (not saved)"
	}
	return r
}

// trustRemove removes p from the bot-managed list. Config entries cannot
// be removed from here; the reply says where they come from.
func (a *Agent) trustRemove(p netip.Prefix) string {
	a.trustMu.Lock()
	defer a.trustMu.Unlock()
	shown := sshwatch.FormatPrefix(p)
	if slices.Contains(a.trustStore.Entries(), p) {
		_, err := a.trustStore.Remove(p)
		a.rebuildTrust()
		log.Printf("agent: SSH source %s untrusted from Telegram", shown)
		msg := fmt.Sprintf("🗑 Removed <code>%s</code>. Its SSH logins alert again.", esc(shown))
		if m, ok := a.findTrust(p); ok {
			msg = fmt.Sprintf("🗑 Removed <code>%s</code>, but it is still covered by <code>%s</code> (%s).",
				esc(shown), esc(sshwatch.FormatPrefix(m.entry)), m.source)
		}
		if err != nil {
			log.Printf("agent: %v", err)
			msg += "\n(⚠️ not saved, it will be trusted again after a restart: " + esc(err.Error()) + ")"
		}
		return msg
	}
	m, ok := a.findTrust(p)
	switch {
	case ok && m.exact:
		return fmt.Sprintf("🔒 <code>%s</code> comes from %s (ssh.trusted_ips). Edit the file and restart the agent to remove it.",
			esc(shown), srcConfig)
	case ok:
		other := sshwatch.FormatPrefix(m.entry)
		return fmt.Sprintf("<code>%s</code> is not an entry itself; it is covered by <code>%s</code> (%s).",
			esc(shown), esc(other), m.source)
	default:
		return fmt.Sprintf("<code>%s</code> is not trusted.", esc(shown))
	}
}

// parseTrustArg parses the single argument of /trust or /untrust.
func parseTrustArg(cmd string, args []string) (netip.Prefix, string) {
	if len(args) != 1 {
		return netip.Prefix{}, fmt.Sprintf("Usage: /%s &lt;ip-or-cidr&gt;, e.g. /%s 203.0.113.7 or /%s 10.0.0.0/8", cmd, cmd, cmd)
	}
	p, err := config.ParseTrustedIP(args[0])
	if err != nil {
		return netip.Prefix{}, "❌ " + esc(err.Error())
	}
	return p, ""
}

// trustedScreen is the 🤝 Trusted IPs screen: both sources, paged, with
// a 🗑 button per bot-managed entry that opens the untrust confirm.
// Config entries can only be removed by editing the file.
func (a *Agent) trustedScreen(_ context.Context, c tgui.Call) tgui.View {
	type entry struct {
		p   netip.Prefix
		bot bool
	}
	var all []entry
	for _, p := range a.configTrusted {
		all = append(all, entry{p, false})
	}
	stored := a.trustStore.Entries()
	for _, p := range stored {
		all = append(all, entry{p, true})
	}
	page, pages := pageOf(c, len(all))
	shown := pageSlice(all, page)
	var b strings.Builder
	fmt.Fprintf(&b, "🤝 <b>Trusted IPs</b> · %d\nPlain SSH logins from these do not alert.\n", len(all))
	// group lists the entries of one source on this page under its
	// heading; an empty source says so, a source on other pages is left
	// out.
	group := func(bot bool, heading string, total int) {
		var lines []string
		for _, e := range shown {
			if e.bot == bot {
				lines = append(lines, "  <code>"+esc(sshwatch.FormatPrefix(e.p))+"</code>\n")
			}
		}
		switch {
		case total == 0:
			lines = []string{"  (none)\n"}
		case len(lines) == 0:
			return
		}
		b.WriteString("\n" + heading + "\n" + strings.Join(lines, ""))
	}
	group(false, "<b>"+srcConfig+"</b> (edit ssh.trusted_ips and restart to change):", len(a.configTrusted))
	group(true, fmt.Sprintf("<b>%s</b> (%d/%d, 🗑 or /untrust to remove):", srcTelegram, len(stored), maxTelegramTrusted), len(stored))
	b.WriteString("\nRoot logins, logins with a new key and logins right after failed attempts always alert.\n" +
		"/trust ip-or-cidr to add.")

	var rows [][]tgui.Button
	var row []tgui.Button
	for _, e := range shown {
		if !e.bot {
			continue
		}
		p := sshwatch.FormatPrefix(e.p)
		row = append(row, tgui.Button{Label: "🗑 " + truncate(p, 24), Call: tgui.Call{Act: askUntrust, Args: []string{p}}})
		if len(row) == 2 {
			rows, row = append(rows, row), nil
		}
	}
	rows = append(rows, row, pageRow(scrTrusted, c, page, pages))
	return tgui.View{Text: b.String(), Rows: rows}
}

// registerTrustHandlers adds /trust and /untrust; /trusted opens the
// Trusted IPs screen.
func (a *Agent) registerTrustHandlers(r *bot.Router) {
	r.Handle("trust", bot.Text(func(ctx context.Context, args []string) string {
		p, errMsg := parseTrustArg("trust", args)
		if errMsg != "" {
			return errMsg
		}
		return a.trustAdd(p).html
	}))
	r.Handle("untrust", bot.Text(func(ctx context.Context, args []string) string {
		p, errMsg := parseTrustArg("untrust", args)
		if errMsg != "" {
			return errMsg
		}
		return a.trustRemove(p)
	}))
}

// trustButton returns the "Trust this IP" row for a plain login alert, or
// nil when the source is not a single IP literal (e.g. a hostname under
// UseDNS) or is already trusted.
func (a *Agent) trustButton(ip string) []telegram.Button {
	p, err := config.ParseTrustedIP(ip)
	if err != nil || !p.IsSingleIP() || a.trusted.Load().Contains(ip) {
		return nil
	}
	data := cbTrust + sshwatch.FormatPrefix(p)
	if len(data) > 64 {
		return nil
	}
	return []telegram.Button{{Text: "🤝 Trust this IP", Data: data}}
}

// loginKeyboard is the keyboard of a plain login alert: the usual SSH
// actions, the source row, then snooze.
func (a *Agent) loginKeyboard(key, ip string) telegram.Keyboard {
	return a.alertKeyboard(key, a.sourceRow(ip))
}

// sourceRow is a login alert's row for its source: Trust this IP when
// that applies, and Copy IP, which needs no round trip.
func (a *Agent) sourceRow(ip string) []telegram.Button {
	row := a.trustButton(ip)
	if ip != "" {
		row = append(row, telegram.Button{Text: "📋 Copy IP", Copy: ip})
	}
	return row
}

// restoreLoginKeyboard rebuilds the keyboard a login alert in message id
// was sent with, so a trust press leaves it as it was (minus Trust once
// trusted), and extra rows below it. An alert sent before a restart gets
// the same buttons minus the snooze, which needs the original alert key.
func (a *Agent) restoreLoginKeyboard(id int64, ip string, extra ...[]telegram.Button) telegram.Keyboard {
	a.mu.Lock()
	key, known := a.trustAlerts[id]
	a.mu.Unlock()
	var kb telegram.Keyboard
	if known {
		// The key is "ssh-login:user@ip": it names the source even when
		// the pressed button no longer does.
		if at := strings.LastIndex(key, "@"); at >= 0 {
			ip = key[at+1:]
		}
		kb = a.loginKeyboard(key, ip)
	} else {
		kb = telegram.Keyboard{alertViewRow("ssh-login")}
		if row := a.sourceRow(ip); row != nil {
			kb = append(kb, row)
		}
	}
	return append(kb, extra...)
}

// rememberTrustAlert records which alert key a sent login alert carries,
// so Cancel can restore its exact keyboard (snooze button included).
func (a *Agent) rememberTrustAlert(messageID int64, key string) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.trustAlerts == nil || len(a.trustAlerts) >= maxTrustAlerts {
		a.trustAlerts = map[int64]string{}
	}
	a.trustAlerts[messageID] = key
}

// parseTrustCallback validates a trust callback payload: a single address
// in exactly the canonical form trustButton writes. Anything else is stale
// or forged.
func parseTrustCallback(raw string) (netip.Prefix, bool) {
	p, err := config.ParseTrustedIP(raw)
	if err != nil || !p.IsSingleIP() || sshwatch.FormatPrefix(p) != raw {
		return netip.Prefix{}, false
	}
	return p, true
}

// handleTrustCallback processes the tip:/tipk:/tipc: buttons. It reports
// false for other data. Every outcome edits only the alert's keyboard.
func (a *Agent) handleTrustCallback(ctx context.Context, cb *telegram.Callback) bool {
	var prefix string
	for _, p := range []string{cbTrustConfirm, cbTrustCancel, cbTrust} {
		if strings.HasPrefix(cb.Data, p) {
			prefix = p
			break
		}
	}
	if prefix == "" {
		return false
	}
	label := func(line string) []telegram.Button {
		return []telegram.Button{{Text: line, Data: "noop"}}
	}
	p, ok := parseTrustCallback(strings.TrimPrefix(cb.Data, prefix))
	var kb telegram.Keyboard
	toast := ""
	switch {
	case !ok:
		kb, toast = a.restoreLoginKeyboard(cb.MessageID, "", label("⚠️ Not trusted: invalid button")), "rejected"

	case prefix == cbTrust:
		shown := sshwatch.FormatPrefix(p)
		if m, found := a.findTrust(p); found {
			// Stale button: trusted since the alert went out.
			kb = a.restoreLoginKeyboard(cb.MessageID, shown, label("☑️ Already trusted via "+sshwatch.FormatPrefix(m.entry)))
			break
		}
		kb = telegram.Keyboard{
			{{Text: "Trust " + shown + "? Its plain logins stop alerting.", Data: "noop"}},
			{{Text: "✅ Yes, trust", Data: cbTrustConfirm + shown}, {Text: "❌ Cancel", Data: cbTrustCancel + shown}},
		}

	case prefix == cbTrustConfirm:
		// The alert keeps its buttons; Trust is gone once it took.
		r := a.trustAdd(p)
		kb, toast = a.restoreLoginKeyboard(cb.MessageID, sshwatch.FormatPrefix(p), label(r.line)), r.line

	case prefix == cbTrustCancel:
		kb = a.restoreLoginKeyboard(cb.MessageID, sshwatch.FormatPrefix(p))
	}
	a.send.AnswerCallback(ctx, cb.ID, toast)
	if err := a.send.EditMessageMarkup(ctx, cb.ChatID, cb.MessageID, kb); err != nil {
		log.Printf("agent: edit: %v", err)
	}
	return true
}
