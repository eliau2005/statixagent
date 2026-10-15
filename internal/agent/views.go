package agent

import (
	"cmp"
	"context"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/eliau2005/statixagent/internal/bot"
	"github.com/eliau2005/statixagent/internal/services"
	"github.com/eliau2005/statixagent/internal/sshwatch"
	"github.com/eliau2005/statixagent/internal/tgui"
)

// Screen renderers (screens.go registers them). They only read state:
// views run for any authorized chat member.

// pre renders rows as a <pre> block, escaped, each wrapped to fit a phone.
func pre(rows []string) string {
	var out []string
	for _, r := range rows {
		out = append(out, bot.Wrap(r)...)
	}
	return "<pre>" + esc(strings.Join(out, "\n")) + "</pre>"
}

// plural is "1 session" / "2 sessions".
func plural(n int, word string) string {
	if n == 1 {
		return fmt.Sprintf("%d %s", n, word)
	}
	return fmt.Sprintf("%d %ss", n, word)
}

// homeView is the dashboard (§3.2): the headline numbers, what needs
// attention, and the way into every section.
func (a *Agent) homeView(ctx context.Context, c tgui.Call) tgui.View {
	a.mu.Lock()
	s := a.snap
	a.mu.Unlock()
	var b strings.Builder
	fmt.Fprintf(&b, "🏠 <b>%s</b> · up %s · %s\n", esc(a.src.Hostname), bot.Dur(s.Uptime), a.now().Format("15:04"))
	rows := []string{
		fmt.Sprintf("CPU  %3.0f%%  load %.2f", s.CPUTotal.Percent, s.Load.Load1),
		fmt.Sprintf("Mem  %3.0f%%  %s / %s", s.Mem.UsedPercent(), bot.BytesShort(s.Mem.Total-s.Mem.Available), bot.BytesShort(s.Mem.Total)),
	}
	const maxMounts = 4
	for i, m := range s.Mounts {
		if i == maxMounts {
			rows = append(rows, fmt.Sprintf("     +%d more", len(s.Mounts)-maxMounts))
			break
		}
		label := ""
		if i == 0 {
			label = "Disk"
		}
		rows = append(rows, bot.Clip(fmt.Sprintf("%-4s %3.0f%%  %s", label, m.UsedPercent, m.MountPoint), bot.PreCols))
	}
	rx, tx := bot.NetTrendVals(s.Net)
	rows = append(rows, fmt.Sprintf("Net   ↓%s ↑%s", bot.Rate(rx), bot.Rate(tx)))
	b.WriteString(pre(rows))

	failing := a.failingCount(ctx)
	var notes []string
	if failing > 0 {
		notes = append(notes, fmt.Sprintf("❌ %d failing", failing))
	}
	if a.src.Sessions != nil {
		if sessions, err := a.src.Sessions(); err == nil {
			notes = append(notes, "👥 "+plural(len(sessions), "SSH session"))
		}
	}
	if len(notes) > 0 {
		b.WriteString("\n" + strings.Join(notes, " · "))
	}

	var kb [][]tgui.Button
	if failing > 0 {
		// The hub's Failing list: everything not OK, failing first.
		kb = append(kb, []tgui.Button{{Label: fmt.Sprintf("❌ %d failing", failing), Call: tgui.Open(scrFailing)}})
	}
	kb = append(kb,
		[]tgui.Button{{Label: "📈 Metrics", Call: tgui.Open(scrMetrics)}, {Label: "🧩 Services", Call: tgui.Open(scrServices)}},
		[]tgui.Button{{Label: "🔐 Security", Call: tgui.Open(scrSecurity)}, {Label: "⚙️ Settings", Call: tgui.Open(scrSettings)}},
		[]tgui.Button{{Label: "▶️ Live", Legacy: "live"}, {Label: "🔄 Refresh", Call: c}},
	)
	return tgui.View{Text: b.String(), Rows: kb}
}

// watchResults checks the watched units, processes and ports. HTTP and
// certificate checks go over the network, so Home leaves them to the
// services hub.
func (a *Agent) watchResults(ctx context.Context) []services.Result {
	watch := a.watchCopy()
	var results []services.Result
	if a.src.Runner != nil && len(watch.Services) > 0 {
		results = append(results, services.CheckSystemdUnits(ctx, a.src.Runner, watch.Services)...)
	}
	if a.src.ProcFS != nil && len(watch.Processes) > 0 {
		if procResults, err := a.src.ProcFS(watch.Processes); err == nil {
			results = append(results, procResults...)
		}
	}
	if len(watch.Ports) > 0 {
		specs := make([]services.PortSpec, len(watch.Ports))
		for i, p := range watch.Ports {
			specs[i] = services.PortSpec{Port: p.Port, Label: p.Label}
		}
		results = append(results, services.CheckPorts(ctx, defaultDialer(), specs)...)
	}
	return results
}

// failingCount is how many local watched checks are not OK.
func (a *Agent) failingCount(ctx context.Context) int {
	n := 0
	for _, r := range a.watchResults(ctx) {
		if r.State != services.StateOK {
			n++
		}
	}
	return n
}

// metricsView is the Metrics section: one line per reading, a button
// per metric screen.
func (a *Agent) metricsView(_ context.Context, _ tgui.Call) tgui.View {
	a.mu.Lock()
	s, th, pw := a.snap, a.thermal, a.power
	a.mu.Unlock()
	disk := 0.0
	for _, m := range s.Mounts {
		disk = max(disk, m.UsedPercent)
	}
	rows := []string{
		fmt.Sprintf("CPU  %3.0f%%   Load %.2f", s.CPUTotal.Percent, s.Load.Load1),
		fmt.Sprintf("Mem  %3.0f%%", s.Mem.UsedPercent()),
		fmt.Sprintf("Disk %3.0f%%   (fullest mount)", disk),
	}
	if len(th.Sensors) > 0 {
		rows[1] += fmt.Sprintf("   Temp %.0f°C", th.MaxCelsius())
	}
	if pw.HasBattery && len(pw.Batteries) > 0 {
		rows = append(rows, fmt.Sprintf("Batt %3.0f%%", pw.Batteries[0].Percent))
	}
	rx, tx := bot.NetTrendVals(s.Net)
	rows = append(rows, fmt.Sprintf("Net   ↓%s ↑%s", bot.Rate(rx), bot.Rate(tx)))
	return tgui.View{
		Text: "📈 <b>Metrics</b>\n" + pre(rows),
		Rows: [][]tgui.Button{
			{{Label: "🖥 CPU", Call: tgui.Open(scrCPU)}, {Label: "🧠 Memory", Call: tgui.Open(scrMem)}, {Label: "💾 Disk", Call: tgui.Open(scrDisk)}},
			{{Label: "📶 Network", Call: tgui.Open(scrNet)}, {Label: "🌡 Temp", Call: tgui.Open(scrTemp)}, {Label: "🔋 Battery", Call: tgui.Open(scrBattery)}},
			{{Label: "🔝 Top", Call: tgui.Open(scrTop)}, {Label: "📰 Digest", Call: tgui.Open(scrDigest)}},
		},
	}
}

// sparkPoints is how much trend history a sparkline shows: it shares a
// <pre> row with a label, within 32 columns.
const sparkPoints = 24

func (a *Agent) cpuText() string {
	a.mu.Lock()
	defer a.mu.Unlock()
	return bot.CPU(a.snap, bot.Spark(a.trendVals(func(p trendPoint) float64 { return p.cpu }), 100))
}

func (a *Agent) memText() string {
	a.mu.Lock()
	defer a.mu.Unlock()
	return bot.Mem(a.snap, bot.Spark(a.trendVals(func(p trendPoint) float64 { return p.mem }), 100))
}

func (a *Agent) diskText() string {
	a.mu.Lock()
	defer a.mu.Unlock()
	return bot.Disk(a.snap)
}

func (a *Agent) netText() string {
	a.mu.Lock()
	defer a.mu.Unlock()
	// Autoscaled to each series' own peak: traffic has no natural 100%.
	rx := bot.Spark(a.trendVals(func(p trendPoint) float64 { return p.rx }), 0)
	tx := bot.Spark(a.trendVals(func(p trendPoint) float64 { return p.tx }), 0)
	return bot.Net(a.snap, rx, tx)
}

func (a *Agent) tempText() string {
	a.mu.Lock()
	defer a.mu.Unlock()
	return bot.Temp(a.thermal)
}

func (a *Agent) batteryText() string {
	a.mu.Lock()
	defer a.mu.Unlock()
	return bot.Battery(a.power)
}

func (a *Agent) topText(ctx context.Context) string {
	if a.src.TopProcs == nil {
		return "Process inspection is not available in this build."
	}
	procs, err := a.src.TopProcs(ctx)
	if err != nil {
		return "Could not read processes: " + esc(err.Error())
	}
	a.mu.Lock()
	memTotal := a.snap.Mem.Total
	a.mu.Unlock()
	return bot.Top(procs, memTotal)
}

// failedWindow is how far back the Failed logins screen and the Security
// summary count.
const failedWindow = 24 * time.Hour

func isFailure(e sshwatch.Event) bool {
	return e.Kind == sshwatch.EventFailed || e.Kind == sshwatch.EventInvalidUser
}

// recentFailures returns the failed attempts of the last failedWindow,
// newest first.
func (a *Agent) recentFailures() []sshwatch.Event {
	since := a.now().Add(-failedWindow)
	return a.hist.Recent(1<<30, func(e sshwatch.Event) bool { return isFailure(e) && e.At.After(since) })
}

// securityView is the Security section (§3.9).
func (a *Agent) securityView(ctx context.Context, _ tgui.Call) tgui.View {
	sessions := "unavailable"
	if a.src.Sessions != nil {
		if list, err := a.src.Sessions(); err == nil {
			sessions = fmt.Sprintf("%d open", len(list))
		} else {
			sessions = "unreadable"
		}
	}
	rows := []string{
		"Sessions  " + sessions,
		fmt.Sprintf("Failed    %d in 24h", len(a.recentFailures())),
		"Firewall  " + a.firewallSummary(ctx),
		fmt.Sprintf("Trusted   %d entries", len(a.configTrusted)+a.trustStore.Len()),
	}
	return tgui.View{
		Text: "🔐 <b>Security</b>\n" + pre(rows),
		Rows: [][]tgui.Button{
			{{Label: "👥 Sessions", Call: tgui.Open(scrSessions)}, {Label: "🕘 History", Call: tgui.Open(scrHistory)}},
			{{Label: "🚫 Failed", Call: tgui.Open(scrFailed)}, {Label: "🛡 Firewall", Call: tgui.Open(scrFirewall)}},
			{{Label: "🤝 Trusted IPs", Call: tgui.Open(scrTrusted)}},
		},
	}
}

// sessionsView lists live SSH sessions (§3.9). Kick buttons carry the
// session's fingerprint, re-resolved against a fresh listing on the
// press and again on Yes, so a shifted list can never retarget a kick.
func (a *Agent) sessionsView(ctx context.Context, _ tgui.Call) tgui.View {
	more := []tgui.Button{
		{Label: "🕘 History", Call: tgui.Call{Act: tgui.ActView, Args: []string{scrHistory}, From: scrSessions}},
		{Label: "🚫 Failed", Call: tgui.Call{Act: tgui.ActView, Args: []string{scrFailed}, From: scrSessions}},
	}
	if a.src.Sessions == nil {
		return tgui.View{Text: "👥 Session listing unavailable.", Rows: [][]tgui.Button{more}}
	}
	sessions, err := a.src.Sessions()
	if err != nil {
		return tgui.View{Text: "👥 Could not read sessions: " + esc(err.Error()), Rows: [][]tgui.Button{more}}
	}
	geo := map[string]sshwatch.GeoInfo{}
	for _, s := range sessions {
		geo[s.Host] = a.geo.Lookup(ctx, s.Host)
	}
	var rows [][]tgui.Button
	if a.src.Runner != nil {
		var row []tgui.Button
		for _, s := range sessions {
			if !validTTY(s.TTY) {
				continue // no terminal to signal (or suspicious bytes)
			}
			row = append(row, tgui.Button{
				Label: "🚫 Kick " + truncate(s.User+" "+s.TTY, 24),
				Call:  tgui.Call{Act: askKick, Args: []string{sessionFingerprint(s)}},
				Style: "danger",
			})
			if len(row) == 2 {
				rows, row = append(rows, row), nil
			}
		}
		rows = append(rows, row)
	}
	rows = append(rows, more)
	return tgui.View{Text: bot.Sessions(sessions, geo, a.now()), Rows: rows}
}

// historyView pages the SSH log events held in memory, newest first.
func (a *Agent) historyView(_ context.Context, c tgui.Call) tgui.View {
	events := a.hist.Recent(1<<30, nil)
	page, pages := pageOf(c, len(events))
	if len(events) == 0 {
		return tgui.View{Text: "🕘 <b>SSH history</b>\nNothing recorded yet."}
	}
	icons := map[sshwatch.EventKind]string{
		sshwatch.EventLogin:       "✅",
		sshwatch.EventFailed:      "❌",
		sshwatch.EventInvalidUser: "🚫",
		sshwatch.EventDisconnect:  "👋",
	}
	var rows []string
	for _, e := range pageSlice(events, page) {
		detail := e.Method
		if e.InvalidUser {
			detail = "invalid user"
		}
		rows = append(rows,
			bot.Clip(fmt.Sprintf("%s %s %s", icons[e.Kind], e.At.Format("Jan02 15:04"), e.User), bot.PreCols),
			strings.TrimRight("   "+e.IP+" "+detail, " "))
	}
	title := fmt.Sprintf("🕘 <b>SSH history</b> · %s", plural(len(events), "event"))
	return tgui.View{Text: title + "\n" + pre(rows), Rows: [][]tgui.Button{pageRow(scrHistory, c, page, pages)}}
}

// failSource is the failed attempts from one address.
type failSource struct {
	ip   string
	n    int
	user string // the last user tried
	last time.Time
}

// failedView pages the last 24 hours of failed attempts, grouped by
// source address, busiest first.
func (a *Agent) failedView(_ context.Context, c tgui.Call) tgui.View {
	events := a.recentFailures()
	by := map[string]*failSource{}
	var srcs []*failSource
	for _, e := range events { // newest first: the first seen is the last tried
		f, ok := by[e.IP]
		if !ok {
			f = &failSource{ip: e.IP, user: e.User, last: e.At}
			by[e.IP] = f
			srcs = append(srcs, f)
		}
		f.n++
	}
	slices.SortStableFunc(srcs, func(x, y *failSource) int { return cmp.Compare(y.n, x.n) })
	title := fmt.Sprintf("🚫 <b>Failed logins</b> · %d in 24h", len(events))
	if len(events) == 0 {
		return tgui.View{Text: title + "\nNo failed attempts."}
	}
	page, pages := pageOf(c, len(srcs))
	var rows []string
	for _, f := range pageSlice(srcs, page) {
		rows = append(rows,
			fmt.Sprintf("%3d× %s", f.n, f.ip),
			bot.Clip(fmt.Sprintf("     %s · last %s", f.user, f.last.Format("15:04")), bot.PreCols))
	}
	return tgui.View{Text: title + "\n" + pre(rows), Rows: [][]tgui.Button{pageRow(scrFailed, c, page, pages)}}
}

// updateView checks for a new version (§3.12); its button opens the
// existing install confirm.
func (a *Agent) updateView(ctx context.Context, _ tgui.Call) tgui.View {
	const title = "⬇️ <b>Update</b>\n"
	if a.src.UpdateCheck == nil {
		return tgui.View{Text: title + "Self-update is not configured in this build."}
	}
	ver, available, err := a.src.UpdateCheck(ctx)
	switch {
	case err != nil:
		return tgui.View{Text: title + "Update check failed: " + esc(err.Error())}
	case !available:
		return tgui.View{Text: title + "Already up to date (" + esc(ver) + ")."}
	}
	return tgui.View{
		Text: title + "New version available: <b>" + esc(ver) + "</b>\nInstalling restarts the agent. Tap below or send /update_confirm.",
		Rows: [][]tgui.Button{{{Label: "⬇️ Update to " + truncate(ver, 24), Call: tgui.Call{Act: askUpdate}}}},
	}
}

// helpText is /help: the commands, grouped by section.
const helpText = "🏠 <b>Home</b>\n" +
	"/status — dashboard · /start view — open a screen\n\n" +
	"📈 <b>Metrics</b>\n" +
	"/metrics — overview\n" +
	"/cpu /mem /disk /net — one metric\n" +
	"/temp /battery — hardware\n" +
	"/top — heaviest processes\n" +
	"/digest — daily summary (auto-sent each morning)\n\n" +
	"🧩 <b>Services</b>\n" +
	"/services — hub: units, containers, checks, ports\n" +
	"/docker — containers\n" +
	"/http — endpoint checks (/http add url)\n" +
	"/ssl — certificate expiry (/ssl add host)\n" +
	"/ping host — TCP latency from this server\n\n" +
	"🔐 <b>Security</b>\n" +
	"/security — overview\n" +
	"/ssh — live sessions (disconnect buttons)\n" +
	"/ssh history — recent logins · /ssh fails — failed attempts\n" +
	"/firewall — open/close SSH port 22\n" +
	"/trusted — trusted SSH sources (/trust ip · /untrust ip)\n\n" +
	"⚙️ <b>Settings</b>\n" +
	"/settings — thresholds &amp; digest\n" +
	"/watching — manage everything watched\n" +
	"/services_scan /ports_scan — find candidates\n" +
	"(/services_add, /ports_add, /procs_add … still work typed)\n" +
	"/update — check for a new version\n" +
	"/clear_chat — wipe recent messages"
