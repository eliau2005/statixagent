// Package agent wires every subsystem into the running daemon (MVP §2):
// a sampler loop, an SSH log watcher, a keys watcher, and the bot listener
// run as goroutines over shared state. All OS access arrives through the
// Sources struct, so the orchestration is testable on any platform; the
// linux build of cmd/statix-agent supplies the real sources.
package agent

import (
	"context"
	"fmt"
	"log"
	"runtime/debug"
	"strings"
	"sync"
	"time"

	"github.com/eliau2005/statixagent/internal/alert"
	"github.com/eliau2005/statixagent/internal/bot"
	"github.com/eliau2005/statixagent/internal/collect"
	"github.com/eliau2005/statixagent/internal/config"
	"github.com/eliau2005/statixagent/internal/dockermon"
	"github.com/eliau2005/statixagent/internal/netcheck"
	"github.com/eliau2005/statixagent/internal/services"
	"github.com/eliau2005/statixagent/internal/sshwatch"
	"github.com/eliau2005/statixagent/internal/sysfs"
	"github.com/eliau2005/statixagent/internal/telegram"
)

// Sender is the outbound Telegram surface; *telegram.Client implements it.
type Sender interface {
	SendMessage(ctx context.Context, chatID int64, html string) error
	SendMessageID(ctx context.Context, chatID int64, html string) (int64, error)
	SendMessageKB(ctx context.Context, chatID int64, html string, kb telegram.Keyboard) (int64, error)
	EditMessageKB(ctx context.Context, chatID, messageID int64, html string, kb telegram.Keyboard) error
	AnswerCallback(ctx context.Context, callbackID, text string) error
	DeleteMessages(ctx context.Context, chatID int64, ids []int64) error
	SetMyCommands(ctx context.Context, commands []telegram.BotCommand) error
}

// Updates is the inbound Telegram surface; *telegram.Client implements it.
type Updates interface {
	GetUpdates(ctx context.Context, offset int64, timeout time.Duration) ([]telegram.Update, error)
}

// Sources supplies every OS-dependent reading. Nil fields disable that
// subsystem (e.g. no Docker socket on the machine).
type Sources struct {
	Hostname string

	Sample   func(ctx context.Context) (collect.Sample, error)
	Thermal  func() (sysfs.Thermal, error)
	Power    func() (sysfs.Power, error)
	Sessions func() ([]sshwatch.Session, error)

	// AuthLines streams sshd log lines (journalctl -f / tail -F auth.log).
	AuthLines <-chan string

	Docker   *dockermon.Client
	Runner   services.Runner
	ProcFS   func(names []string) ([]services.Result, error) // process presence checks
	KeyPaths []string

	// TopProcs samples per-process CPU/memory over a short window (~1s);
	// nil disables /top.
	TopProcs func(ctx context.Context) ([]collect.Proc, error)

	// CheckCerts reports certificate expiry for host[:port] endpoints;
	// nil disables /ssl and the expiry watcher.
	CheckCerts func(ctx context.Context, hosts []string) []netcheck.CertStatus

	// Latency measures TCP connect time to host[:port]; nil disables /ping.
	Latency func(ctx context.Context, addr string) (time.Duration, error)

	// ConfigPath is where watch-list changes are persisted; empty means
	// in-memory only (replies say so).
	ConfigPath string
	// ListListeners returns the local TCP ports in LISTEN state.
	ListListeners func() ([]int, error)

	// UpdateCheck and UpdateApply are wired in Phase 8; nil = not available.
	UpdateCheck func(ctx context.Context) (string, bool, error)
	UpdateApply func(ctx context.Context) error
}

// Agent is the daemon.
type Agent struct {
	cfg     config.Config
	send    Sender
	updates Updates
	src     Sources

	engine *alert.Engine
	brute  *sshwatch.BruteDetector
	hist   *sshwatch.History
	keys   *sshwatch.KeysWatcher
	geo    *sshwatch.GeoResolver
	router *bot.Router

	mu      sync.Mutex
	snap    collect.Snapshot
	prevRaw collect.Sample
	thermal sysfs.Thermal
	power   sysfs.Power
	hadAC   bool
	acSeen  bool

	// Last scan results, for resolving numeric /services_add and
	// /ports_add arguments. Guarded by mu.
	lastServiceScan []string
	lastPortScan    []int

	// lastSessions is the SSH session list as last rendered, so sk:/skk:
	// kick callbacks resolve indexes against what the user saw. Guarded
	// by mu.
	lastSessions []sshwatch.Session

	// Live-mode session state (live.go). Guarded by mu; intervals are set
	// once in New and overridden only by tests.
	liveCancel   context.CancelFunc
	liveInterval time.Duration
	liveDuration time.Duration

	// pendingKB is set by a handler that wants a custom keyboard on its
	// reply and consumed by reply(). Safe because updates are processed
	// sequentially. Guarded by mu.
	pendingKB telegram.Keyboard

	// trend is a ring of recent usage points for sparklines. Guarded by mu.
	trend []trendPoint

	// digest accumulates the day's activity for the daily summary.
	// Guarded by mu. digestPoll is the loop's check interval, set once in
	// New and overridden only by tests.
	digest     digestStats
	digestPoll time.Duration

	// rebootChecked is set once the first sample with a readable uptime
	// has been inspected for a fresh host boot. Guarded by mu.
	rebootChecked bool

	// sslInterval is the certificate re-check period, set once in New and
	// overridden only by tests.
	sslInterval time.Duration

	// prevContainers maps container ID → state as of the last docker poll
	// (nil until seeded). Guarded by mu. dockerPoll is the poll period,
	// set once in New and overridden only by tests.
	prevContainers map[string]string
	dockerPoll     time.Duration
}

// trendPoint is one sampled reading kept for sparkline rendering.
type trendPoint struct {
	cpu, mem float64
	rx, tx   float64 // aggregate network rates, bytes/sec
}

// trendCap bounds the ring: at the 15s default interval this is ~10 min.
const trendCap = 40

// New assembles an Agent.
func New(cfg config.Config, send Sender, updates Updates, src Sources) *Agent {
	a := &Agent{
		cfg:          cfg,
		send:         send,
		updates:      updates,
		src:          src,
		engine:       alert.New(10 * time.Minute),
		brute:        sshwatch.NewBruteDetector(2*time.Minute, 5),
		hist:         sshwatch.NewHistory(500),
		keys:         sshwatch.NewKeysWatcher(src.KeyPaths),
		geo:          sshwatch.NewGeoResolver(),
		liveInterval: 3 * time.Second,
		liveDuration: 30 * time.Second,
		digest:       digestStats{since: time.Now()},
		digestPoll:   30 * time.Second,
		sslInterval:  12 * time.Hour,
		dockerPoll:   time.Minute,
	}
	a.router = a.buildRouter()
	return a
}

// Run starts all loops and blocks until ctx is canceled.
func (a *Agent) Run(ctx context.Context) error {
	var wg sync.WaitGroup
	loop := func(name string, f func(context.Context)) {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for ctx.Err() == nil {
				safely(name, func() { f(ctx) })
				if ctx.Err() == nil {
					time.Sleep(time.Second) // crashed loop: restart after a beat
				}
			}
		}()
	}
	loop("sampler", a.sampleLoop)
	if a.cfg.Monitors.SSH && a.src.AuthLines != nil {
		loop("sshwatch", a.authLoop)
	}
	if a.cfg.Monitors.SSH && len(a.src.KeyPaths) > 0 {
		loop("keyswatch", a.keysLoop)
	}
	if a.updates != nil {
		loop("bot", a.botLoop)
	}
	// Always run: the enabled flag is checked per tick so /settings can
	// turn the digest on without a restart.
	loop("digest", a.digestLoop)
	if a.src.CheckCerts != nil {
		loop("ssl", a.sslLoop)
	}
	if a.src.Docker != nil && a.cfg.Monitors.Docker {
		loop("docker", a.dockerLoop)
	}
	if err := a.send.SetMyCommands(ctx, commandMenu); err != nil {
		log.Printf("agent: setMyCommands: %v", err)
	}
	hello := fmt.Sprintf("✅ <b>statix-agent started</b> on %s", a.src.Hostname)
	if _, err := a.send.SendMessageKB(ctx, a.cfg.Telegram.ChatID, hello, telegram.Keyboard{{
		{Text: "📊 Status", Data: "status"},
		{Text: "👁 Watching", Data: "watching"},
	}}); err != nil {
		log.Printf("agent: hello: %v", err)
	}
	wg.Wait()
	return ctx.Err()
}

// safely runs f and converts a panic into a logged error so one subsystem
// cannot take down the agent (MVP §2's recover-from-crashes goal).
func safely(name string, f func()) {
	defer func() {
		if r := recover(); r != nil {
			log.Printf("agent: %s panicked: %v\n%s", name, r, debug.Stack())
		}
	}()
	f()
}

// push sends an HTML message to the configured chat, logging failures.
func (a *Agent) push(ctx context.Context, html string) {
	if err := a.send.SendMessage(ctx, a.cfg.Telegram.ChatID, html); err != nil {
		log.Printf("agent: push failed: %v", err)
	}
}

// ---- sampling & threshold evaluation ----

func (a *Agent) sampleLoop(ctx context.Context) {
	tick := time.NewTicker(a.cfg.SampleInterval.Duration)
	defer tick.Stop()
	a.sampleOnce(ctx) // immediate first sample so /status works right away
	for {
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
			a.sampleOnce(ctx)
		}
	}
}

func (a *Agent) sampleOnce(ctx context.Context) {
	now := time.Now()
	var alerts []*alert.Alert

	if a.src.Sample != nil && a.cfg.Monitors.System {
		raw, err := a.src.Sample(ctx)
		if err != nil {
			log.Printf("agent: sample: %v", err)
		} else {
			a.mu.Lock()
			snap := collect.Compute(a.prevRaw, raw)
			a.prevRaw = raw
			a.snap = snap
			if snap.CPUTotal.Percent > a.digest.peakCPU {
				a.digest.peakCPU = snap.CPUTotal.Percent
			}
			if mp := snap.Mem.UsedPercent(); mp > a.digest.peakMem {
				a.digest.peakMem = mp
			}
			rx, tx := bot.NetTrendVals(snap.Net)
			a.trend = append(a.trend, trendPoint{cpu: snap.CPUTotal.Percent, mem: snap.Mem.UsedPercent(), rx: rx, tx: tx})
			if len(a.trend) > trendCap {
				a.trend = a.trend[len(a.trend)-trendCap:]
			}
			a.mu.Unlock()
			alerts = append(alerts, a.checkReboot(snap, now))
			alerts = append(alerts, a.evalSystem(snap, now)...)
		}
	}
	if a.src.Thermal != nil && a.cfg.Monitors.Thermal {
		th, err := a.src.Thermal()
		if err == nil {
			a.mu.Lock()
			a.thermal = th
			a.mu.Unlock()
			if len(th.Sensors) > 0 {
				alerts = append(alerts, a.engine.Threshold(alert.ThresholdOpts{
					Key: "temp", Title: "Temperature", Severity: alert.Warning,
					Value: th.MaxCelsius(), Threshold: a.thresholds().TempCelsius,
					ClearMargin: 5, Unit: "°C",
				}, now))
			}
		}
	}
	if a.src.Power != nil && a.cfg.Monitors.Power {
		pw, err := a.src.Power()
		if err == nil {
			alerts = append(alerts, a.evalPower(pw, now)...)
		}
	}
	for _, al := range alerts {
		if al != nil {
			a.pushAlert(ctx, *al)
		}
	}
}

// rebootWindow is how fresh the host uptime must be at the agent's first
// sample to call it a reboot. Agent restarts (self-update, crash recovery)
// see hours of uptime and stay silent; only a fresh boot trips this.
const rebootWindow = 5 * time.Minute

// checkReboot inspects the first readable uptime: a host that just booted
// is worth a push — an unexpected reboot is an incident, a planned one is
// confirmation it came back.
func (a *Agent) checkReboot(s collect.Snapshot, now time.Time) *alert.Alert {
	if s.Uptime <= 0 {
		return nil // unreadable this tick; try again next sample
	}
	a.mu.Lock()
	done := a.rebootChecked
	a.rebootChecked = true
	a.mu.Unlock()
	if done || s.Uptime >= rebootWindow {
		return nil
	}
	body := fmt.Sprintf("%s came up %s ago", a.src.Hostname, bot.Dur(s.Uptime))
	return a.engine.Event("reboot", "Host rebooted", body, alert.Warning, now, time.Hour)
}

func (a *Agent) evalSystem(s collect.Snapshot, now time.Time) []*alert.Alert {
	t := a.thresholds()
	out := []*alert.Alert{
		a.engine.Threshold(alert.ThresholdOpts{
			Key: "cpu", Title: "CPU usage", Severity: alert.Warning,
			Value: s.CPUTotal.Percent, Threshold: t.CPUPercent, ClearMargin: 10, Unit: "%",
		}, now),
		a.engine.Threshold(alert.ThresholdOpts{
			Key: "mem", Title: "Memory usage", Severity: alert.Warning,
			Value: s.Mem.UsedPercent(), Threshold: t.MemPercent, ClearMargin: 10, Unit: "%",
		}, now),
	}
	for _, m := range s.Mounts {
		out = append(out, a.engine.Threshold(alert.ThresholdOpts{
			Key: "disk:" + m.MountPoint, Title: "Disk space " + m.MountPoint,
			Severity: alert.Critical, Value: m.UsedPercent,
			Threshold: t.DiskPercent, ClearMargin: 5, Unit: "%",
		}, now))
	}
	return out
}

func (a *Agent) evalPower(pw sysfs.Power, now time.Time) []*alert.Alert {
	a.mu.Lock()
	prevAC, seen := a.hadAC, a.acSeen
	a.hadAC, a.acSeen = pw.ACOnline, true
	a.power = pw
	a.mu.Unlock()

	var out []*alert.Alert
	if pw.HasAC && seen {
		if prevAC && !pw.ACOnline {
			body := "running on battery"
			if len(pw.Batteries) > 0 {
				b := pw.Batteries[0]
				body = fmt.Sprintf("running on battery — %.0f%%", b.Percent)
				if b.TimeToEmpty > 0 {
					body += fmt.Sprintf(", ~%s left", bot.Dur(b.TimeToEmpty))
				}
			}
			out = append(out, a.engine.Event("power-loss", "Power lost", body, alert.Critical, now, time.Minute))
		} else if !prevAC && pw.ACOnline {
			out = append(out, a.engine.Event("power-restored", "Power restored", "AC is back", alert.Info, now, time.Minute))
		}
	}
	if pw.HasBattery && pw.OnBattery() && len(pw.Batteries) > 0 {
		out = append(out, a.engine.Threshold(alert.ThresholdOpts{
			Key: "battery", Title: "Battery low", Severity: alert.Critical,
			Value: pw.Batteries[0].Percent, Threshold: a.thresholds().BatteryPercent,
			ClearMargin: 10, Below: true, Unit: "%",
		}, now))
	}
	return out
}

// ---- ssh watching ----

func (a *Agent) authLoop(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		case line, ok := <-a.src.AuthLines:
			if !ok {
				return
			}
			a.handleAuthLine(ctx, line, time.Now())
		}
	}
}

func (a *Agent) handleAuthLine(ctx context.Context, line string, now time.Time) {
	e, ok := sshwatch.ParseLine(line, now)
	if !ok {
		return
	}
	a.hist.Add(e)
	a.noteSSHEvent(e.Kind)
	switch e.Kind {
	case sshwatch.EventLogin:
		geo := a.geo.Lookup(ctx, e.IP)
		body := fmt.Sprintf("%s from %s via %s", e.User, e.IP, e.Method)
		if g := geo.String(); g != "" {
			body += " — " + g
		}
		sev, title := alert.Info, "SSH login"
		if e.Root {
			sev, title = alert.Critical, "ROOT SSH login"
		}
		// Every login alerts in real time (MVP §3); key by user+ip with a
		// tiny cooldown so a burst of multiplexed connections sends once.
		if al := a.engine.Event("ssh-login:"+e.User+"@"+e.IP, title, body, sev, now, 10*time.Second); al != nil {
			a.pushAlert(ctx, *al)
		}
	case sshwatch.EventFailed, sshwatch.EventInvalidUser:
		if a.brute.Record(e.IP, now) {
			n := a.brute.Count(e.IP, now)
			body := fmt.Sprintf("%d failed attempts from %s in 2m (last user: %s)", n, e.IP, e.User)
			if al := a.engine.Event("ssh-brute:"+e.IP, "Brute-force attack", body, alert.Critical, now, time.Minute); al != nil {
				a.pushAlert(ctx, *al)
			}
		}
	}
}

func (a *Agent) keysLoop(ctx context.Context) {
	tick := time.NewTicker(time.Minute)
	defer tick.Stop()
	a.keys.Poll() // seed baseline
	for {
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
			for _, ch := range a.keys.Poll() {
				al := a.engine.Event("keys:"+ch.Path, "authorized_keys "+ch.Kind, ch.Path, alert.Critical, time.Now(), time.Minute)
				if al != nil {
					a.pushAlert(ctx, *al)
				}
			}
		}
	}
}

// ---- bot ----

func (a *Agent) botLoop(ctx context.Context) {
	var offset int64
	for ctx.Err() == nil {
		ups, err := a.updates.GetUpdates(ctx, offset, 50*time.Second)
		if err != nil {
			if ctx.Err() == nil {
				log.Printf("agent: getUpdates: %v", err)
				time.Sleep(5 * time.Second)
			}
			continue
		}
		for _, u := range ups {
			if u.ID >= offset {
				offset = u.ID + 1
			}
			if u.Callback != nil {
				a.handleCallback(ctx, u.Callback)
				continue
			}
			if reply, cmd, ok := a.router.Dispatch(ctx, u); ok {
				a.reply(ctx, cmd, reply)
			}
		}
	}
}

func (a *Agent) buildRouter() *bot.Router {
	r := bot.NewRouter(a.cfg.Telegram.ChatID)
	// /start is a new user's first message ever — it must explain what the
	// bot does on its own and hand over the entry points, not point at docs.
	r.Handle("start", func(ctx context.Context, _ []string) string {
		var b strings.Builder
		fmt.Fprintf(&b, "👋 <b>%s</b> is under watch. This all happens automatically:\n\n", a.src.Hostname)
		b.WriteString("• 🚨 alert when CPU, RAM or disk cross a threshold\n")
		if a.cfg.Monitors.SSH {
			b.WriteString("• 🔐 report every SSH login, brute-force bursts, key changes\n")
		}
		watch := a.watchCopy()
		if n := len(watch.Services) + len(watch.Processes) + len(watch.Ports) + len(watch.HTTPChecks) + len(watch.SSLHosts); n > 0 {
			fmt.Fprintf(&b, "• 🧩 watch %d services, processes and ports\n", n)
		}
		if enabled, hour := a.digestCfg(); enabled {
			fmt.Fprintf(&b, "• 📰 send a daily digest at %02d:00\n", hour)
		}
		b.WriteString("\nAlerts carry buttons for the next step. Start here:")
		a.stashKB(telegram.Keyboard{
			{{Text: "📊 Status", Data: "status"}, {Text: "👁 Watching", Data: "watching"}},
			{{Text: "🔝 Top", Data: "top"}, {Text: "⚙️ Settings", Data: "settings"}},
		})
		return b.String()
	})
	r.Handle("help", func(ctx context.Context, _ []string) string {
		return "🖥 <b>Metrics</b>\n" +
			"/status — full dashboard\n" +
			"/cpu /mem /disk /net — one metric\n" +
			"/top — heaviest processes\n" +
			"/digest — daily summary (auto-sent each morning)\n" +
			"/temp /battery — hardware\n\n" +
			"🧩 <b>Workloads</b>\n" +
			"/services — units, processes, ports\n" +
			"/http — endpoint checks (/http add url)\n" +
			"/ping host — TCP latency from this server\n" +
			"/docker — containers\n\n" +
			"🔐 <b>Security</b>\n" +
			"/ssh — live sessions (disconnect buttons)\n" +
			"/ssh history — recent logins\n" +
			"/ssh fails — failed attempts\n" +
			"/firewall — open/close SSH port 22\n" +
			"/ssl — certificate expiry (/ssl add host)\n\n" +
			"👁 <b>Watching</b>\n" +
			"/watching — manage everything with buttons\n" +
			"/services_scan /ports_scan — find candidates\n" +
			"(/services_add, /ports_add, /procs_add … still work typed)\n\n" +
			"⚙️ <b>Maintenance</b>\n" +
			"/settings — tune thresholds &amp; digest\n" +
			"/update — check · /update_confirm — install\n" +
			"/clear_chat — wipe recent messages"
	})
	r.Handle("status", func(ctx context.Context, _ []string) string {
		a.mu.Lock()
		defer a.mu.Unlock()
		return bot.Status(a.src.Hostname, a.snap, a.thermal, a.power)
	})
	r.Handle("cpu", func(ctx context.Context, _ []string) string {
		a.mu.Lock()
		defer a.mu.Unlock()
		return bot.CPU(a.snap, bot.Spark(a.trendVals(func(p trendPoint) float64 { return p.cpu }), 100))
	})
	r.Handle("mem", func(ctx context.Context, _ []string) string {
		a.mu.Lock()
		defer a.mu.Unlock()
		return bot.Mem(a.snap, bot.Spark(a.trendVals(func(p trendPoint) float64 { return p.mem }), 100))
	})
	r.Handle("top", func(ctx context.Context, _ []string) string {
		if a.src.TopProcs == nil {
			return "Process inspection is not available in this build."
		}
		procs, err := a.src.TopProcs(ctx)
		if err != nil {
			return "Could not read processes: " + err.Error()
		}
		a.mu.Lock()
		memTotal := a.snap.Mem.Total
		a.mu.Unlock()
		return bot.Top(procs, memTotal)
	})
	r.Handle("digest", func(ctx context.Context, _ []string) string {
		return a.digestView(false)
	})
	r.Handle("disk", a.snapHandler(bot.Disk))
	r.Handle("net", func(ctx context.Context, _ []string) string {
		a.mu.Lock()
		defer a.mu.Unlock()
		// Autoscaled to each series' own peak: traffic has no natural 100%.
		rx := bot.Spark(a.trendVals(func(p trendPoint) float64 { return p.rx }), 0)
		tx := bot.Spark(a.trendVals(func(p trendPoint) float64 { return p.tx }), 0)
		return bot.Net(a.snap, rx, tx)
	})
	r.Handle("temp", func(ctx context.Context, _ []string) string {
		a.mu.Lock()
		defer a.mu.Unlock()
		return bot.Temp(a.thermal)
	})
	r.Handle("battery", func(ctx context.Context, _ []string) string {
		a.mu.Lock()
		defer a.mu.Unlock()
		return bot.Battery(a.power)
	})
	r.Handle("services", func(ctx context.Context, _ []string) string {
		return a.servicesReply(ctx)
	})
	r.Handle("docker", func(ctx context.Context, _ []string) string {
		if a.src.Docker == nil || !a.cfg.Monitors.Docker {
			return "Docker monitoring is not enabled."
		}
		cts, err := a.src.Docker.ListContainers(ctx)
		if err != nil {
			return "Docker unreachable: " + err.Error()
		}
		for i := range cts {
			if cts[i].State == "running" {
				a.src.Docker.Stats(ctx, &cts[i])
			}
		}
		return bot.Docker(cts)
	})
	r.Handle("ssh", func(ctx context.Context, args []string) string {
		sub := ""
		if len(args) > 0 {
			sub = strings.ToLower(args[0])
		}
		switch sub {
		case "history":
			return a.sshHistoryView()
		case "fails":
			return a.sshFailsView()
		default:
			text, kb := a.sshSessionsView(ctx)
			a.stashKB(kb)
			return text
		}
	})
	r.Handle("ssl", func(ctx context.Context, args []string) string {
		return a.sslView(ctx, args)
	})
	r.Handle("http", func(ctx context.Context, args []string) string {
		return a.httpView(ctx, args)
	})
	// /ping answers "can this server reach X, and how fast?" — the vantage
	// point is the VPS itself, which is the question when debugging from
	// the outside.
	r.Handle("ping", func(ctx context.Context, args []string) string {
		if a.src.Latency == nil {
			return "Latency checks are not available in this build."
		}
		if len(args) == 0 {
			return "Usage: /ping &lt;host[:port]&gt; — TCP connect time from this server (default port 443)"
		}
		addr := args[0]
		d, err := a.src.Latency(ctx, addr)
		if err != nil {
			return "🏓 " + esc(addr) + " — unreachable: " + esc(err.Error())
		}
		return fmt.Sprintf("🏓 %s — <b>%s</b>", esc(addr), fmtLatency(d))
	})
	// Direct aliases for alert action buttons (callback data is one token).
	r.Handle("ssh_history", func(ctx context.Context, _ []string) string { return a.sshHistoryView() })
	r.Handle("ssh_fails", func(ctx context.Context, _ []string) string { return a.sshFailsView() })
	applyUpdate := func(ctx context.Context) string {
		if a.src.UpdateCheck == nil || a.src.UpdateApply == nil {
			return "Self-update is not configured in this build."
		}
		if err := a.src.UpdateApply(ctx); err != nil {
			return "Update failed: " + err.Error()
		}
		return "Updating — the agent will restart."
	}
	r.Handle("update", func(ctx context.Context, args []string) string {
		if a.src.UpdateCheck == nil {
			return "Self-update is not configured in this build."
		}
		if len(args) > 0 && strings.EqualFold(args[0], "confirm") {
			return applyUpdate(ctx) // legacy "/update confirm" form
		}
		ver, available, err := a.src.UpdateCheck(ctx)
		if err != nil {
			return "Update check failed: " + err.Error()
		}
		if !available {
			return "Already up to date (" + ver + ")."
		}
		return "New version available: <b>" + ver + "</b>\nTap /update_confirm to install."
	})
	r.Handle("update_confirm", func(ctx context.Context, _ []string) string {
		return applyUpdate(ctx)
	})
	r.Handle("clear_chat", func(ctx context.Context, _ []string) string {
		chatID := a.cfg.Telegram.ChatID
		anchor, err := a.send.SendMessageID(ctx, chatID, "🧹")
		if err != nil {
			return "Could not clear: " + err.Error()
		}
		ids := make([]int64, 0, 301)
		for id := anchor; id > anchor-301 && id > 0; id-- {
			ids = append(ids, id)
		}
		if err := a.send.DeleteMessages(ctx, chatID, ids); err != nil {
			return "Could not clear: " + err.Error()
		}
		return "🧹 cleared"
	})
	a.registerWatchHandlers(r)
	return r
}

// fmtLatency renders a dial time at a precision that matches its size.
func fmtLatency(d time.Duration) string {
	if d < time.Millisecond {
		return fmt.Sprintf("%.2fms", float64(d.Microseconds())/1000)
	}
	if d < time.Second {
		return fmt.Sprintf("%dms", d.Milliseconds())
	}
	return fmt.Sprintf("%.1fs", d.Seconds())
}

// commandMenu is registered with Telegram so clients show autocomplete and
// tappable commands.
var commandMenu = []telegram.BotCommand{
	{Command: "status", Description: "full dashboard"},
	{Command: "cpu", Description: "CPU usage per core"},
	{Command: "mem", Description: "memory usage"},
	{Command: "disk", Description: "disk space and I/O"},
	{Command: "net", Description: "network rates and totals"},
	{Command: "top", Description: "heaviest processes by CPU and memory"},
	{Command: "digest", Description: "daily activity summary"},
	{Command: "temp", Description: "temperatures and fans"},
	{Command: "battery", Description: "battery state"},
	{Command: "services", Description: "watched services status"},
	{Command: "docker", Description: "containers"},
	{Command: "ssh", Description: "live SSH sessions (disconnect buttons)"},
	{Command: "watching", Description: "manage everything watched (buttons)"},
	{Command: "settings", Description: "tune alert thresholds (buttons)"},
	{Command: "firewall", Description: "open/close SSH port 22 (ufw)"},
	{Command: "ssl", Description: "certificate expiry for watched hosts"},
	{Command: "http", Description: "endpoint health checks"},
	{Command: "ping", Description: "TCP latency from this server"},
	{Command: "services_scan", Description: "find running services to watch"},
	{Command: "ports_scan", Description: "find listening ports to watch"},
	{Command: "update", Description: "check for a new version"},
	{Command: "update_confirm", Description: "install the update"},
	{Command: "clear_chat", Description: "delete recent messages"},
	{Command: "help", Description: "all commands"},
}

func (a *Agent) sshHistoryView() string {
	return bot.SSHEvents("SSH history", a.hist.Recent(20, nil))
}

func (a *Agent) sshFailsView() string {
	return bot.SSHEvents("Failed attempts", a.hist.Recent(20, func(e sshwatch.Event) bool {
		return e.Kind == sshwatch.EventFailed || e.Kind == sshwatch.EventInvalidUser
	}))
}

// trendVals extracts one series from the ring; callers hold a.mu. Series
// shorter than 2 points render no sparkline.
func (a *Agent) trendVals(f func(trendPoint) float64) []float64 {
	if len(a.trend) < 2 {
		return nil
	}
	out := make([]float64, len(a.trend))
	for i, p := range a.trend {
		out[i] = f(p)
	}
	return out
}

func (a *Agent) snapHandler(f func(collect.Snapshot) string) bot.Handler {
	return func(ctx context.Context, _ []string) string {
		a.mu.Lock()
		defer a.mu.Unlock()
		return f(a.snap)
	}
}

func (a *Agent) servicesReply(ctx context.Context) string {
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
	if len(watch.HTTPChecks) > 0 {
		specs := make([]services.HTTPSpec, len(watch.HTTPChecks))
		for i, h := range watch.HTTPChecks {
			specs[i] = services.HTTPSpec{URL: h.URL, ExpectStatus: h.ExpectStatus, Timeout: h.Timeout.Duration}
		}
		results = append(results, services.CheckHTTP(ctx, httpClient, specs)...)
	}
	return bot.ServiceResults(results)
}
