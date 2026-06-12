package agent

import (
	"context"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/eliau2005/statixagent/internal/alert"
	"github.com/eliau2005/statixagent/internal/collect"
	"github.com/eliau2005/statixagent/internal/config"
	"github.com/eliau2005/statixagent/internal/procfs"
	"github.com/eliau2005/statixagent/internal/sysfs"
	"github.com/eliau2005/statixagent/internal/telegram"
)

type edit struct {
	messageID int64
	html      string
	kb        telegram.Keyboard
}

type fakeSender struct {
	mu        sync.Mutex
	sent      []string
	keyboards []telegram.Keyboard
	edits     []edit
	answered  []string
	deleted   []int64
	cmds      []telegram.BotCommand
	nextID    int64
}

func (f *fakeSender) SendMessage(ctx context.Context, chatID int64, html string) error {
	_, err := f.SendMessageID(ctx, chatID, html)
	return err
}

func (f *fakeSender) SendMessageID(ctx context.Context, chatID int64, html string) (int64, error) {
	return f.SendMessageKB(ctx, chatID, html, nil)
}

func (f *fakeSender) SendMessageKB(_ context.Context, _ int64, html string, kb telegram.Keyboard) (int64, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.sent = append(f.sent, html)
	f.keyboards = append(f.keyboards, kb)
	f.nextID++
	return f.nextID + 1000, nil
}

func (f *fakeSender) EditMessageKB(_ context.Context, _ int64, messageID int64, html string, kb telegram.Keyboard) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.edits = append(f.edits, edit{messageID, html, kb})
	return nil
}

func (f *fakeSender) AnswerCallback(_ context.Context, callbackID, text string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.answered = append(f.answered, callbackID+":"+text)
	return nil
}

func (f *fakeSender) DeleteMessages(_ context.Context, _ int64, ids []int64) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.deleted = append(f.deleted, ids...)
	return nil
}

func (f *fakeSender) SetMyCommands(_ context.Context, cmds []telegram.BotCommand) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.cmds = cmds
	return nil
}

func (f *fakeSender) all() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.sent...)
}

func (f *fakeSender) find(sub string) bool {
	for _, s := range f.all() {
		if strings.Contains(s, sub) {
			return true
		}
	}
	return false
}

func testConfig() config.Config {
	c := config.Default()
	c.Telegram.Token = "t"
	c.Telegram.ChatID = 42
	c.SampleInterval = config.Duration{Duration: time.Second}
	return c
}

func testAgent(send *fakeSender) *Agent {
	src := Sources{
		Hostname: "testhost",
		Sample: func(ctx context.Context) (collect.Sample, error) {
			return collect.Sample{
				At:   time.Now(),
				Stat: procfs.Stat{Aggregate: procfs.CPUStat{Name: "cpu", User: 100, Idle: 900}},
				Mem:  procfs.MemInfo{Total: 8 << 30, Available: 4 << 30},
			}, nil
		},
		Thermal: func() (sysfs.Thermal, error) { return sysfs.Thermal{}, nil },
		Power:   func() (sysfs.Power, error) { return sysfs.Power{}, nil },
	}
	return New(testConfig(), send, nil, src)
}

func TestThresholdAlertPushed(t *testing.T) {
	send := &fakeSender{}
	a := testAgent(send)
	now := time.Now()

	hot := collect.Snapshot{CPUTotal: collect.CPUUsage{Percent: 97}, Mem: procfs.MemInfo{Total: 100, Available: 60}}
	for _, al := range a.evalSystem(hot, now) {
		if al != nil {
			a.push(context.Background(), "ALERT:"+al.Title)
		}
	}
	if !send.find("ALERT:CPU usage") {
		t.Errorf("cpu alert not pushed: %v", send.all())
	}
	if send.find("ALERT:Memory") {
		t.Errorf("memory at 40%% must not alert: %v", send.all())
	}
}

func TestPowerLossAlert(t *testing.T) {
	send := &fakeSender{}
	a := testAgent(send)
	now := time.Now()

	plugged := sysfs.Power{HasAC: true, ACOnline: true, HasBattery: true,
		Batteries: []sysfs.Battery{{Percent: 80}}}
	unplugged := sysfs.Power{HasAC: true, ACOnline: false, HasBattery: true,
		Batteries: []sysfs.Battery{{Percent: 79, TimeToEmpty: 3 * time.Hour}}}

	if als := a.evalPower(plugged, now); countNonNil(als) != 0 {
		t.Fatalf("first reading must not alert: %+v", als)
	}
	als := a.evalPower(unplugged, now.Add(time.Minute))
	if countNonNil(als) != 1 {
		t.Fatalf("unplug must alert exactly once: %+v", als)
	}
	if als[0].Severity.String() != "critical" || !strings.Contains(als[0].Body, "79%") {
		t.Errorf("power loss alert = %+v", als[0])
	}
	als = a.evalPower(plugged, now.Add(5*time.Minute))
	found := false
	for _, al := range als {
		if al != nil && al.Title == "Power restored" {
			found = true
		}
	}
	if !found {
		t.Errorf("replug must notify: %+v", als)
	}
}

func TestRootLoginAlertAndBruteForce(t *testing.T) {
	send := &fakeSender{}
	a := testAgent(send)
	ctx := context.Background()
	now := time.Now()

	a.handleAuthLine(ctx, "Accepted publickey for root from 203.0.113.7 port 51234 ssh2: ED25519 SHA256:xyz", now)
	if !send.find("ROOT SSH login") {
		t.Errorf("root login must push critical alert: %v", send.all())
	}

	for i := 0; i < 5; i++ {
		a.handleAuthLine(ctx, "Failed password for invalid user admin from 192.0.2.4 port 33000 ssh2", now.Add(time.Duration(i)*time.Second))
	}
	if !send.find("Brute-force attack") {
		t.Errorf("5 failures must trigger brute alert: %v", send.all())
	}

	if got := len(a.hist.Recent(100, nil)); got != 6 {
		t.Errorf("history = %d events, want 6", got)
	}
}

func TestBotCommandsThroughRouter(t *testing.T) {
	send := &fakeSender{}
	a := testAgent(send)
	ctx := context.Background()

	// Seed a snapshot the handlers can read.
	a.sampleOnce(ctx)

	reply, _, ok := a.router.Dispatch(ctx, telegram.Update{ChatID: 42, Text: "/status"})
	if !ok || !strings.Contains(reply, "testhost") {
		t.Errorf("/status = %q", reply)
	}
	reply, _, _ = a.router.Dispatch(ctx, telegram.Update{ChatID: 42, Text: "/help"})
	if !strings.Contains(reply, "/ssh history") || !strings.Contains(reply, "<b>Security</b>") {
		t.Errorf("/help = %q", reply)
	}
	reply, _, _ = a.router.Dispatch(ctx, telegram.Update{ChatID: 42, Text: "/update"})
	if !strings.Contains(reply, "not configured") {
		t.Errorf("/update without updater = %q", reply)
	}
	reply, _, _ = a.router.Dispatch(ctx, telegram.Update{ChatID: 42, Text: "/ssh history"})
	if !strings.Contains(reply, "Nothing recorded") {
		t.Errorf("/ssh history empty = %q", reply)
	}
	if _, _, ok := a.router.Dispatch(ctx, telegram.Update{ChatID: 666, Text: "/status"}); ok {
		t.Error("foreign chat must be ignored")
	}
}

func TestUpdateCommandFlow(t *testing.T) {
	send := &fakeSender{}
	a := testAgent(send)
	applied := false
	a.src.UpdateCheck = func(ctx context.Context) (string, bool, error) { return "v1.2.0", true, nil }
	a.src.UpdateApply = func(ctx context.Context) error { applied = true; return nil }
	ctx := context.Background()

	reply, _, _ := a.router.Dispatch(ctx, telegram.Update{ChatID: 42, Text: "/update"})
	if !strings.Contains(reply, "v1.2.0") || !strings.Contains(reply, "/update_confirm") {
		t.Errorf("/update = %q", reply)
	}
	if applied {
		t.Fatal("/update alone must not apply (MVP §7 confirmation rule)")
	}
	// The legacy "/update confirm" form keeps working for old habits.
	reply, _, _ = a.router.Dispatch(ctx, telegram.Update{ChatID: 42, Text: "/update confirm"})
	if !applied || !strings.Contains(reply, "restart") {
		t.Errorf("confirm: applied=%v reply=%q", applied, reply)
	}
}

func TestRunStartsAndStops(t *testing.T) {
	send := &fakeSender{}
	a := testAgent(send)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- a.Run(ctx) }()

	deadline := time.After(3 * time.Second)
	for !send.find("statix-agent started") {
		select {
		case <-deadline:
			t.Fatal("startup message not sent")
		case <-time.After(10 * time.Millisecond):
		}
	}
	cancel()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("Run did not stop on cancel")
	}
}

type scanRunner struct{ listOutput string }

func (s scanRunner) Run(_ context.Context, name string, args ...string) (string, error) {
	if name == "systemctl" && args[0] == "list-units" {
		return s.listOutput, nil
	}
	return "ActiveState=active\nSubState=running\nNRestarts=0\n", nil
}

func TestWatchManagement(t *testing.T) {
	send := &fakeSender{}
	a := testAgent(send)
	cfgPath := filepath.Join(t.TempDir(), "config.toml")
	a.src.ConfigPath = cfgPath
	a.src.Runner = scanRunner{listOutput: "" +
		"nginx.service loaded active running A high performance web server\n" +
		"cron.service loaded active running Regular background jobs\n" +
		"statix-agent.service loaded active running StatixAgent\n"}
	a.src.ListListeners = func() ([]int, error) { return []int{22, 80, 22}, nil }
	ctx := context.Background()
	dispatch := func(text string) string {
		reply, _, _ := a.router.Dispatch(ctx, telegram.Update{ChatID: 42, Text: text})
		return reply
	}

	// Scan excludes the agent itself and numbers candidates.
	scan := dispatch("/services_scan")
	if !strings.Contains(scan, "nginx.service") || !strings.Contains(scan, "cron.service") {
		t.Fatalf("scan = %q", scan)
	}
	if strings.Contains(scan, "statix-agent.service") {
		t.Error("scan must exclude the agent's own unit")
	}

	// Add by index from the scan, then by name.
	if reply := dispatch("/services_add 1"); !strings.Contains(reply, "watching nginx.service") {
		t.Errorf("add by index = %q", reply)
	}
	if reply := dispatch("/services_add postgresql"); !strings.Contains(reply, "watching postgresql.service") {
		t.Errorf("add by name = %q", reply)
	}
	if reply := dispatch("/services_add 1"); !strings.Contains(reply, "already watched") {
		t.Errorf("duplicate add = %q", reply)
	}

	// Ports: scan dedupes, add by port and by index, with label.
	if scan := dispatch("/ports_scan"); !strings.Contains(scan, "port 22") || strings.Count(scan, "port 22") != 1 {
		t.Errorf("port scan = %q", scan)
	}
	if reply := dispatch("/ports_add 80 web"); !strings.Contains(reply, "watching port 80") {
		t.Errorf("ports_add = %q", reply)
	}
	if reply := dispatch("/procs_add node"); !strings.Contains(reply, "watching process node") {
		t.Errorf("procs_add = %q", reply)
	}

	// Persistence: the saved config reloads with everything in place.
	saved, err := config.Load(cfgPath)
	if err != nil {
		t.Fatalf("saved config does not load: %v", err)
	}
	if len(saved.Watch.Services) != 2 || saved.Watch.Services[0] != "nginx.service" {
		t.Errorf("saved services = %v", saved.Watch.Services)
	}
	if len(saved.Watch.Ports) != 1 || saved.Watch.Ports[0].Port != 80 || saved.Watch.Ports[0].Label != "web" {
		t.Errorf("saved ports = %+v", saved.Watch.Ports)
	}
	if len(saved.Watch.Processes) != 1 || saved.Watch.Processes[0] != "node" {
		t.Errorf("saved processes = %v", saved.Watch.Processes)
	}

	// Remove by name and by port; persisted again.
	if reply := dispatch("/services_remove nginx"); !strings.Contains(reply, "stopped watching nginx.service") {
		t.Errorf("remove = %q", reply)
	}
	if reply := dispatch("/ports_remove 80"); !strings.Contains(reply, "stopped watching port 80") {
		t.Errorf("ports_remove = %q", reply)
	}
	saved, _ = config.Load(cfgPath)
	if len(saved.Watch.Services) != 1 || len(saved.Watch.Ports) != 0 {
		t.Errorf("after removal: services=%v ports=%v", saved.Watch.Services, saved.Watch.Ports)
	}

	// Bare remove lists what is watched.
	if reply := dispatch("/services_remove"); !strings.Contains(reply, "postgresql.service") {
		t.Errorf("bare remove = %q", reply)
	}
}

func TestWatchWithoutConfigPath(t *testing.T) {
	send := &fakeSender{}
	a := testAgent(send)
	ctx := context.Background()
	reply, _, _ := a.router.Dispatch(ctx, telegram.Update{ChatID: 42, Text: "/procs_add nginx"})
	if !strings.Contains(reply, "not persisted") {
		t.Errorf("no config path must warn: %q", reply)
	}
	if !strings.Contains(reply, "1 processes") {
		t.Errorf("in-memory change must still apply: %q", reply)
	}
}

func TestUpdateConfirmCommand(t *testing.T) {
	send := &fakeSender{}
	a := testAgent(send)
	applied := false
	a.src.UpdateCheck = func(ctx context.Context) (string, bool, error) { return "v9.9.9", true, nil }
	a.src.UpdateApply = func(ctx context.Context) error { applied = true; return nil }
	ctx := context.Background()

	reply, _, _ := a.router.Dispatch(ctx, telegram.Update{ChatID: 42, Text: "/update"})
	if !strings.Contains(reply, "/update_confirm") {
		t.Errorf("/update must advertise the tappable command: %q", reply)
	}
	if applied {
		t.Fatal("/update must not apply")
	}
	reply, _, _ = a.router.Dispatch(ctx, telegram.Update{ChatID: 42, Text: "/update_confirm"})
	if !applied || !strings.Contains(reply, "restart") {
		t.Errorf("update_confirm: applied=%v reply=%q", applied, reply)
	}
}

func TestClearChat(t *testing.T) {
	send := &fakeSender{}
	a := testAgent(send)
	ctx := context.Background()
	reply, _, _ := a.router.Dispatch(ctx, telegram.Update{ChatID: 42, Text: "/clear_chat"})
	if reply != "🧹 cleared" {
		t.Errorf("reply = %q", reply)
	}
	send.mu.Lock()
	defer send.mu.Unlock()
	if len(send.deleted) != 301 {
		t.Fatalf("deleted %d ids, want 301", len(send.deleted))
	}
	if send.deleted[0] != 1001 { // anchor message id from the fake
		t.Errorf("sweep must start at the anchor id, got %d", send.deleted[0])
	}
}

func TestReplyAttachesNavKeyboard(t *testing.T) {
	send := &fakeSender{}
	a := testAgent(send)
	ctx := context.Background()
	a.sampleOnce(ctx)

	reply, cmd, ok := a.router.Dispatch(ctx, telegram.Update{ChatID: 42, Text: "/status"})
	if !ok {
		t.Fatal("dispatch failed")
	}
	a.reply(ctx, cmd, reply)

	send.mu.Lock()
	defer send.mu.Unlock()
	kb := send.keyboards[len(send.keyboards)-1]
	if kb == nil {
		t.Fatal("/status reply must carry the nav keyboard")
	}
	var labels []string
	for _, row := range kb {
		for _, b := range row {
			labels = append(labels, b.Text+"="+b.Data)
		}
	}
	joined := strings.Join(labels, " ")
	for _, want := range []string{"• 📊 Status=status", "🖥 CPU=cpu", "🔐 SSH=ssh", "🔄 Refresh=status"} {
		if !strings.Contains(joined, want) {
			t.Errorf("keyboard missing %q in %s", want, joined)
		}
	}
}

func TestReplyPlainForNonViews(t *testing.T) {
	send := &fakeSender{}
	a := testAgent(send)
	a.reply(context.Background(), "help", "HELP TEXT")
	send.mu.Lock()
	defer send.mu.Unlock()
	if send.keyboards[len(send.keyboards)-1] != nil {
		t.Error("non-view replies must not carry the nav keyboard")
	}
}

func TestCallbackNavigationEditsInPlace(t *testing.T) {
	send := &fakeSender{}
	a := testAgent(send)
	ctx := context.Background()
	a.sampleOnce(ctx)

	a.handleCallback(ctx, &telegram.Callback{ID: "cb1", ChatID: 42, MessageID: 555, Data: "cpu"})

	send.mu.Lock()
	defer send.mu.Unlock()
	if len(send.answered) != 1 || !strings.HasPrefix(send.answered[0], "cb1:") {
		t.Fatalf("callback must be answered: %v", send.answered)
	}
	if len(send.edits) != 1 || send.edits[0].messageID != 555 {
		t.Fatalf("edits = %+v", send.edits)
	}
	if !strings.Contains(send.edits[0].html, "<b>CPU</b>") {
		t.Errorf("edited content = %q", send.edits[0].html)
	}
	if send.edits[0].kb == nil {
		t.Error("nav view edit must keep the keyboard")
	}
	if len(send.sent) != 0 {
		t.Errorf("navigation must edit, not send new messages: %v", send.sent)
	}
}

func TestCallbackForeignChatIgnored(t *testing.T) {
	send := &fakeSender{}
	a := testAgent(send)
	a.handleCallback(context.Background(), &telegram.Callback{ID: "x", ChatID: 666, MessageID: 1, Data: "status"})
	send.mu.Lock()
	defer send.mu.Unlock()
	if len(send.edits) != 0 || len(send.answered) != 0 {
		t.Error("foreign-chat callbacks must be fully ignored")
	}
}

func TestUpdateOfferKeyboardAndInstallButton(t *testing.T) {
	send := &fakeSender{}
	a := testAgent(send)
	applied := false
	a.src.UpdateCheck = func(ctx context.Context) (string, bool, error) { return "v9.0.0", true, nil }
	a.src.UpdateApply = func(ctx context.Context) error { applied = true; return nil }
	ctx := context.Background()

	reply, cmd, _ := a.router.Dispatch(ctx, telegram.Update{ChatID: 42, Text: "/update"})
	a.reply(ctx, cmd, reply)
	send.mu.Lock()
	kb := send.keyboards[len(send.keyboards)-1]
	send.mu.Unlock()
	if kb == nil || kb[0][0].Data != "update_confirm" {
		t.Fatalf("update offer keyboard = %+v", kb)
	}

	// Pressing Install runs the update; pressing Later dismisses.
	a.handleCallback(ctx, &telegram.Callback{ID: "cb2", ChatID: 42, MessageID: 9, Data: "update_confirm"})
	if !applied {
		t.Error("install button must apply the update")
	}
	a.handleCallback(ctx, &telegram.Callback{ID: "cb3", ChatID: 42, MessageID: 9, Data: "dismiss"})
	send.mu.Lock()
	defer send.mu.Unlock()
	last := send.edits[len(send.edits)-1]
	if !strings.Contains(last.html, "postponed") {
		t.Errorf("dismiss edit = %q", last.html)
	}
}

func (f *fakeSender) editCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.edits)
}

func (f *fakeSender) lastEdit() edit {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.edits[len(f.edits)-1]
}

// waitFor polls until cond holds or the deadline passes.
func waitFor(t *testing.T, cond func() bool, what string) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", what)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

func TestLiveModeAnimatesAndFinishes(t *testing.T) {
	send := &fakeSender{}
	a := testAgent(send)
	a.liveInterval = 5 * time.Millisecond
	a.liveDuration = 60 * time.Millisecond
	ctx := context.Background()

	a.handleCallback(ctx, &telegram.Callback{ID: "cb", ChatID: 42, MessageID: 7, Data: "live"})

	// Session ends with a restore edit: no LIVE marker, nav keyboard back.
	waitFor(t, func() bool {
		return send.editCount() > 2 && !strings.Contains(send.lastEdit().html, "LIVE")
	}, "live session to finish")

	send.mu.Lock()
	defer send.mu.Unlock()
	liveEdits := 0
	stopButtonSeen := false
	for _, e := range send.edits[:len(send.edits)-1] {
		if strings.Contains(e.html, "🔴 <b>LIVE</b>") {
			liveEdits++
		}
		if e.kb != nil && len(e.kb) == 1 && e.kb[0][0].Data == "live_stop" {
			stopButtonSeen = true
		}
	}
	if liveEdits < 2 {
		t.Errorf("want multiple live frames, got %d of %d edits", liveEdits, len(send.edits))
	}
	if !stopButtonSeen {
		t.Error("live frames must carry the ⏹ Stop button")
	}
	final := send.edits[len(send.edits)-1]
	if final.messageID != 7 || final.kb == nil || final.kb[len(final.kb)-1][1].Data != "live" {
		t.Errorf("final edit must restore the nav keyboard on msg 7: %+v", final)
	}
}

func TestLiveModeStopButton(t *testing.T) {
	send := &fakeSender{}
	a := testAgent(send)
	a.liveInterval = 5 * time.Millisecond
	a.liveDuration = time.Hour // would run forever without the stop
	ctx := context.Background()

	a.handleCallback(ctx, &telegram.Callback{ID: "c1", ChatID: 42, MessageID: 9, Data: "live"})
	waitFor(t, func() bool { return send.editCount() >= 2 }, "live frames")
	a.handleCallback(ctx, &telegram.Callback{ID: "c2", ChatID: 42, MessageID: 9, Data: "live_stop"})
	waitFor(t, func() bool {
		return !strings.Contains(send.lastEdit().html, "LIVE")
	}, "stop to restore the normal view")
}

func TestWatchButtons(t *testing.T) {
	send := &fakeSender{}
	a := testAgent(send)
	cfgPath := filepath.Join(t.TempDir(), "config.toml")
	a.src.ConfigPath = cfgPath
	a.src.Runner = scanRunner{listOutput: "nginx.service loaded active running Web server\n"}
	a.src.ListListeners = func() ([]int, error) { return []int{443}, nil }
	ctx := context.Background()

	// Typed scan carries ➕ buttons via the stashed keyboard.
	reply, cmd, _ := a.router.Dispatch(ctx, telegram.Update{ChatID: 42, Text: "/services_scan"})
	a.reply(ctx, cmd, reply)
	send.mu.Lock()
	kb := send.keyboards[len(send.keyboards)-1]
	send.mu.Unlock()
	if kb == nil || kb[0][0].Data != "sa:1" || !strings.Contains(kb[0][0].Text, "➕") {
		t.Fatalf("scan keyboard = %+v", kb)
	}

	// Pressing ➕ adds the unit, persists, and re-renders the scan.
	a.handleCallback(ctx, &telegram.Callback{ID: "c1", ChatID: 42, MessageID: 5, Data: "sa:1"})
	saved, err := config.Load(cfgPath)
	if err != nil || len(saved.Watch.Services) != 1 || saved.Watch.Services[0] != "nginx.service" {
		t.Fatalf("after sa:1 saved=%+v err=%v", saved.Watch, err)
	}
	if last := send.lastEdit(); !strings.Contains(last.html, "already watched") {
		t.Errorf("re-rendered scan should show empty candidates: %q", last.html)
	}

	// Port add button.
	a.handleCallback(ctx, &telegram.Callback{ID: "c2", ChatID: 42, MessageID: 5, Data: "pa:443"})
	saved, _ = config.Load(cfgPath)
	if len(saved.Watch.Ports) != 1 || saved.Watch.Ports[0].Port != 443 {
		t.Fatalf("after pa:443 ports=%+v", saved.Watch.Ports)
	}

	// Watching view lists both with 🗑 buttons.
	a.handleCallback(ctx, &telegram.Callback{ID: "c3", ChatID: 42, MessageID: 5, Data: "watching"})
	last := send.lastEdit()
	if !strings.Contains(last.html, "nginx.service") || !strings.Contains(last.html, "port 443") {
		t.Errorf("watching view = %q", last.html)
	}
	flat := ""
	for _, row := range last.kb {
		for _, b := range row {
			flat += b.Data + " "
		}
	}
	if !strings.Contains(flat, "sr:nginx.service") || !strings.Contains(flat, "pr:443") {
		t.Errorf("watching keyboard = %s", flat)
	}

	// 🗑 removes and persists.
	a.handleCallback(ctx, &telegram.Callback{ID: "c4", ChatID: 42, MessageID: 5, Data: "sr:nginx.service"})
	a.handleCallback(ctx, &telegram.Callback{ID: "c5", ChatID: 42, MessageID: 5, Data: "pr:443"})
	saved, _ = config.Load(cfgPath)
	if len(saved.Watch.Services) != 0 || len(saved.Watch.Ports) != 0 {
		t.Errorf("after removals: %+v", saved.Watch)
	}
	if last := send.lastEdit(); !strings.Contains(last.html, "Nothing yet") {
		t.Errorf("empty watching view = %q", last.html)
	}
}

func TestWatchingCommand(t *testing.T) {
	send := &fakeSender{}
	a := testAgent(send)
	ctx := context.Background()
	reply, cmd, ok := a.router.Dispatch(ctx, telegram.Update{ChatID: 42, Text: "/watching"})
	if !ok || !strings.Contains(reply, "Nothing yet") {
		t.Fatalf("/watching = %q", reply)
	}
	a.reply(ctx, cmd, reply)
	send.mu.Lock()
	defer send.mu.Unlock()
	kb := send.keyboards[len(send.keyboards)-1]
	if kb == nil || kb[len(kb)-1][1].Data != "scan_svc" {
		t.Errorf("watching keyboard = %+v", kb)
	}
}

func countNonNil(als []*alert.Alert) int {
	n := 0
	for _, a := range als {
		if a != nil {
			n++
		}
	}
	return n
}
