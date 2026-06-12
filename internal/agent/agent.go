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

	// Live-mode session state (live.go). Guarded by mu; intervals are set
	// once in New and overridden only by tests.
	liveCancel   context.CancelFunc
	liveInterval time.Duration
	liveDuration time.Duration
}

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
	if err := a.send.SetMyCommands(ctx, commandMenu); err != nil {
		log.Printf("agent: setMyCommands: %v", err)
	}
	a.push(ctx, fmt.Sprintf("✅ <b>statix-agent started</b> on %s", a.src.Hostname))
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
			a.mu.Unlock()
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
					Value: th.MaxCelsius(), Threshold: a.cfg.Thresholds.TempCelsius,
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
			a.push(ctx, bot.AlertMsg(a.src.Hostname, *al))
		}
	}
}

func (a *Agent) evalSystem(s collect.Snapshot, now time.Time) []*alert.Alert {
	t := a.cfg.Thresholds
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
			Value: pw.Batteries[0].Percent, Threshold: a.cfg.Thresholds.BatteryPercent,
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
			a.push(ctx, bot.AlertMsg(a.src.Hostname, *al))
		}
	case sshwatch.EventFailed, sshwatch.EventInvalidUser:
		if a.brute.Record(e.IP, now) {
			n := a.brute.Count(e.IP, now)
			body := fmt.Sprintf("%d failed attempts from %s in 2m (last user: %s)", n, e.IP, e.User)
			if al := a.engine.Event("ssh-brute:"+e.IP, "Brute-force attack", body, alert.Critical, now, time.Minute); al != nil {
				a.push(ctx, bot.AlertMsg(a.src.Hostname, *al))
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
					a.push(ctx, bot.AlertMsg(a.src.Hostname, *al))
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
	r.Handle("start", func(ctx context.Context, _ []string) string {
		return "🖥 Watching <b>" + a.src.Hostname + "</b> — alerts arrive here automatically.\nTry /status for the dashboard, /help for everything."
	})
	r.Handle("help", func(ctx context.Context, _ []string) string {
		return "🖥 <b>Metrics</b>\n" +
			"/status — full dashboard\n" +
			"/cpu /mem /disk /net — one metric\n" +
			"/temp /battery — hardware\n\n" +
			"🧩 <b>Workloads</b>\n" +
			"/services — units, processes, ports\n" +
			"/docker — containers\n\n" +
			"🔐 <b>Security</b>\n" +
			"/ssh — live sessions\n" +
			"/ssh history — recent logins\n" +
			"/ssh fails — failed attempts\n\n" +
			"👁 <b>Watching</b>\n" +
			"/services_scan /ports_scan — find candidates\n" +
			"/services_add /services_remove — manage units\n" +
			"/ports_add /ports_remove — manage ports\n" +
			"/procs_add /procs_remove — manage processes\n\n" +
			"⚙️ <b>Maintenance</b>\n" +
			"/update — check · /update_confirm — install\n" +
			"/clear_chat — wipe recent messages"
	})
	r.Handle("status", func(ctx context.Context, _ []string) string {
		a.mu.Lock()
		defer a.mu.Unlock()
		return bot.Status(a.src.Hostname, a.snap, a.thermal, a.power)
	})
	r.Handle("cpu", a.snapHandler(bot.CPU))
	r.Handle("mem", a.snapHandler(bot.Mem))
	r.Handle("disk", a.snapHandler(bot.Disk))
	r.Handle("net", a.snapHandler(bot.Net))
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
			return bot.SSHEvents("SSH history", a.hist.Recent(20, nil))
		case "fails":
			return bot.SSHEvents("Failed attempts", a.hist.Recent(20, func(e sshwatch.Event) bool {
				return e.Kind == sshwatch.EventFailed || e.Kind == sshwatch.EventInvalidUser
			}))
		default:
			if a.src.Sessions == nil {
				return "Session listing unavailable."
			}
			sessions, err := a.src.Sessions()
			if err != nil {
				return "Could not read sessions: " + err.Error()
			}
			geo := map[string]sshwatch.GeoInfo{}
			for _, s := range sessions {
				geo[s.Host] = a.geo.Lookup(ctx, s.Host)
			}
			return bot.Sessions(sessions, geo, time.Now())
		}
	})
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

// commandMenu is registered with Telegram so clients show autocomplete and
// tappable commands.
var commandMenu = []telegram.BotCommand{
	{Command: "status", Description: "full dashboard"},
	{Command: "cpu", Description: "CPU usage per core"},
	{Command: "mem", Description: "memory usage"},
	{Command: "disk", Description: "disk space and I/O"},
	{Command: "net", Description: "network rates and totals"},
	{Command: "temp", Description: "temperatures and fans"},
	{Command: "battery", Description: "battery state"},
	{Command: "services", Description: "watched services status"},
	{Command: "docker", Description: "containers"},
	{Command: "ssh", Description: "live SSH sessions"},
	{Command: "services_scan", Description: "find running services to watch"},
	{Command: "ports_scan", Description: "find listening ports to watch"},
	{Command: "update", Description: "check for a new version"},
	{Command: "update_confirm", Description: "install the update"},
	{Command: "clear_chat", Description: "delete recent messages"},
	{Command: "help", Description: "all commands"},
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
