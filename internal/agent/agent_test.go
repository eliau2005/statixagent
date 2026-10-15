package agent

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/eliau2005/statixagent/internal/alert"
	"github.com/eliau2005/statixagent/internal/collect"
	"github.com/eliau2005/statixagent/internal/config"
	"github.com/eliau2005/statixagent/internal/procfs"
	"github.com/eliau2005/statixagent/internal/sshwatch"
	"github.com/eliau2005/statixagent/internal/sysfs"
	"github.com/eliau2005/statixagent/internal/telegram"
	"github.com/eliau2005/statixagent/internal/tgui"
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
	// replyTo is the message each send replied to (0: none), by index.
	replyTo  []int64
	edits    []edit
	answered []string
	deleted  []int64
	cmds     []telegram.BotCommand
	// scopes logs SetMyCommands ("set:<scope>") and DeleteMyCommands
	// ("delete:<scope>") calls in order; setCmdsErr fails SetMyCommands.
	scopes     []string
	setCmdsErr error
	nextID     int64
	markups    []markupEdit
	// events logs sends, edits and answers in call order.
	events []string
	// editErr, when set, fails every EditMessageKB.
	editErr error
}

// markupEdit is one keyboard-only edit (EditMessageMarkup).
type markupEdit struct {
	id int64
	kb telegram.Keyboard
}

func (f *fakeSender) SendMessage(ctx context.Context, chatID int64, html string) error {
	_, err := f.SendMessageID(ctx, chatID, html)
	return err
}

func (f *fakeSender) SendMessageID(ctx context.Context, chatID int64, html string) (int64, error) {
	return f.SendMessageKB(ctx, chatID, html, nil)
}

func (f *fakeSender) SendMessageKB(ctx context.Context, chatID int64, html string, kb telegram.Keyboard) (int64, error) {
	return f.SendReplyKB(ctx, chatID, 0, html, kb)
}

func (f *fakeSender) SendReplyKB(_ context.Context, _ int64, replyTo int64, html string, kb telegram.Keyboard) (int64, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.events = append(f.events, "send")
	f.sent = append(f.sent, html)
	f.keyboards = append(f.keyboards, kb)
	f.replyTo = append(f.replyTo, replyTo)
	f.nextID++
	return f.nextID + 1000, nil
}

func (f *fakeSender) EditMessageKB(_ context.Context, _ int64, messageID int64, html string, kb telegram.Keyboard) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.events = append(f.events, "edit")
	if f.editErr != nil {
		return f.editErr
	}
	f.edits = append(f.edits, edit{messageID, html, kb})
	return nil
}

func (f *fakeSender) EditMessageMarkup(_ context.Context, _ int64, messageID int64, kb telegram.Keyboard) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.markups = append(f.markups, markupEdit{id: messageID, kb: kb})
	return nil
}

func (f *fakeSender) AnswerCallback(_ context.Context, callbackID, text string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.events = append(f.events, "answer")
	f.answered = append(f.answered, callbackID+":"+text)
	return nil
}

func (f *fakeSender) DeleteMessages(_ context.Context, _ int64, ids []int64) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.deleted = append(f.deleted, ids...)
	return nil
}

func (f *fakeSender) SetMyCommands(_ context.Context, cmds []telegram.BotCommand, scope telegram.CommandScope) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.scopes = append(f.scopes, fmt.Sprintf("set:%s:%d", scope.Type, scope.ChatID))
	if f.setCmdsErr != nil {
		return f.setCmdsErr
	}
	f.cmds = cmds
	return nil
}

func (f *fakeSender) DeleteMyCommands(_ context.Context, scope telegram.CommandScope) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.scopes = append(f.scopes, fmt.Sprintf("delete:%s:%d", scope.Type, scope.ChatID))
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
	for _, al := range evalSustained(a, hot, now) {
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

	for i := range 5 {
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
	if !ok || !strings.Contains(reply.Text, "testhost") {
		t.Errorf("/status = %q", reply.Text)
	}
	reply, _, _ = a.router.Dispatch(ctx, telegram.Update{ChatID: 42, Text: "/help"})
	if !strings.Contains(reply.Text, "/ssh history") || !strings.Contains(reply.Text, "<b>Security</b>") {
		t.Errorf("/help = %q", reply.Text)
	}
	reply, _, _ = a.router.Dispatch(ctx, telegram.Update{ChatID: 42, Text: "/update"})
	if !strings.Contains(reply.Text, "not configured") {
		t.Errorf("/update without updater = %q", reply.Text)
	}
	reply, _, _ = a.router.Dispatch(ctx, telegram.Update{ChatID: 42, Text: "/ssh history"})
	if !strings.Contains(reply.Text, "Nothing recorded") {
		t.Errorf("/ssh history empty = %q", reply.Text)
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
	if !strings.Contains(reply.Text, "v1.2.0") || !strings.Contains(reply.Text, "/update_confirm") {
		t.Errorf("/update = %q", reply.Text)
	}
	if applied {
		t.Fatal("/update alone must not apply (MVP §7 confirmation rule)")
	}
	// The legacy "/update confirm" form asks, like /update_confirm.
	reply, cmd, _ := a.router.Dispatch(ctx, telegram.Update{ChatID: 42, Text: "/update confirm"})
	a.reply(ctx, cmd, reply)
	if applied || !strings.Contains(reply.Text, "Install the update?") {
		t.Fatalf("/update confirm: applied=%v reply=%q", applied, reply.Text)
	}
	yes := tokenData(lastKeyboard(send), tgui.ActYes)
	if yes == "" {
		t.Fatalf("/update confirm keyboard = %+v", lastKeyboard(send))
	}
	a.handleCallback(ctx, &telegram.Callback{ID: "c1", ChatID: 42, MessageID: lastSentID(send), Data: yes})
	if !applied || !strings.Contains(send.lastEdit().html, "restart") {
		t.Errorf("Yes: applied=%v edit=%q", applied, send.lastEdit().html)
	}
}

// lastKeyboard returns the keyboard of the last message sent.
func lastKeyboard(send *fakeSender) telegram.Keyboard {
	send.mu.Lock()
	defer send.mu.Unlock()
	if len(send.keyboards) == 0 {
		return nil
	}
	return send.keyboards[len(send.keyboards)-1]
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
		return reply.Text
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

func TestWatchRejectsInvalidUnitNames(t *testing.T) {
	send := &fakeSender{}
	a := testAgent(send)
	cfgPath := filepath.Join(t.TempDir(), "config.toml")
	a.src.ConfigPath = cfgPath
	a.src.Runner = scanRunner{listOutput: "" +
		"nginx.service loaded active running A high performance web server\n" +
		"-x.service loaded active running Not a unit we pass to systemctl\n"}
	ctx := context.Background()
	dispatch := func(text string) string {
		reply, _, _ := a.router.Dispatch(ctx, telegram.Update{ChatID: 42, Text: text})
		return reply.Text
	}

	// Option-shaped names never reach the watch list (or systemctl).
	for _, arg := range []string{"--host=x", "-H", "a/b", "nginx;id"} {
		if reply := dispatch("/services_add " + arg); !strings.Contains(reply, "Invalid unit name") {
			t.Errorf("/services_add %s = %q, want rejection", arg, reply)
		}
	}
	if got := a.watchCopy().Services; len(got) != 0 {
		t.Errorf("services after invalid adds = %v", got)
	}

	// The scan does not offer a name the add would refuse.
	if scan := dispatch("/services_scan"); !strings.Contains(scan, "nginx.service") || strings.Contains(scan, "-x.service") {
		t.Errorf("scan = %q", scan)
	}

	// An invalid entry already in the config still loads, and can be removed.
	a.cfg.Watch.Services = []string{"--host=x"}
	if note := a.persist(a.cfg); note != "" {
		t.Fatalf("persist with a legacy entry: %q", note)
	}
	if _, err := config.Load(cfgPath); err != nil {
		t.Fatalf("config with a legacy entry must load: %v", err)
	}
	if reply := dispatch("/services_remove 1"); !strings.Contains(reply, "stopped watching --host=x") {
		t.Errorf("remove legacy entry = %q", reply)
	}
}

func TestWatchWithoutConfigPath(t *testing.T) {
	send := &fakeSender{}
	a := testAgent(send)
	ctx := context.Background()
	reply, _, _ := a.router.Dispatch(ctx, telegram.Update{ChatID: 42, Text: "/procs_add nginx"})
	if !strings.Contains(reply.Text, "not persisted") {
		t.Errorf("no config path must warn: %q", reply.Text)
	}
	if !strings.Contains(reply.Text, "1 processes") {
		t.Errorf("in-memory change must still apply: %q", reply.Text)
	}
}

// TestUpdateConfirmCommand: typed /update_confirm only asks; the update
// runs from the Yes button, and Cancel spends the token.
func TestUpdateConfirmCommand(t *testing.T) {
	send := &fakeSender{}
	a := testAgent(send)
	applied := 0
	a.src.UpdateCheck = func(ctx context.Context) (string, bool, error) { return "v9.9.9", true, nil }
	a.src.UpdateApply = func(ctx context.Context) error { applied++; return nil }
	ctx := context.Background()

	reply, _, _ := a.router.Dispatch(ctx, telegram.Update{ChatID: 42, Text: "/update"})
	if !strings.Contains(reply.Text, "/update_confirm") {
		t.Errorf("/update must advertise the tappable command: %q", reply.Text)
	}
	a.src.OffsetPath = filepath.Join(t.TempDir(), "tg-offset") // handleUpdate saves the cursor
	a.handleUpdate(ctx, telegram.Update{ChatID: 42, ChatType: "private", FromID: 42, Text: "/update_confirm"})
	if applied != 0 || !send.find("Install the update?") {
		t.Fatalf("/update_confirm: applied=%d sent=%v", applied, send.all())
	}
	kb, msg := lastKeyboard(send), lastSentID(send)
	if len(kb) != 1 || len(kb[0]) != 2 || tokenData(kb, tgui.ActYes) != kb[0][0].Data || tokenData(kb, tgui.ActNo) != kb[0][1].Data {
		t.Fatalf("confirm keyboard = %+v", kb)
	}
	press := func(id, data string) {
		a.handleCallback(ctx, &telegram.Callback{ID: id, ChatID: 42, ChatType: "private", FromID: 42, MessageID: msg, Data: data})
	}
	press("c1", kb[0][1].Data)
	if applied != 0 || !strings.Contains(send.lastEdit().html, "postponed") {
		t.Fatalf("Cancel: applied=%d edit=%q", applied, send.lastEdit().html)
	}
	press("c2", kb[0][0].Data)
	if applied != 0 || !strings.Contains(send.lastEdit().html, staleText) {
		t.Fatalf("Yes after Cancel: applied=%d edit=%q", applied, send.lastEdit().html)
	}
	a.handleUpdate(ctx, telegram.Update{ChatID: 42, ChatType: "private", FromID: 42, Text: "/update_confirm"})
	kb, msg = lastKeyboard(send), lastSentID(send)
	press("c3", kb[0][0].Data)
	if applied != 1 || !strings.Contains(send.lastEdit().html, "restart") {
		t.Errorf("Yes: applied=%d edit=%q", applied, send.lastEdit().html)
	}
}

// TestClearChat: typed /clear_chat only asks; Yes sweeps the chat and
// reports in a new message (the prompt is deleted too), Cancel keeps it.
func TestClearChat(t *testing.T) {
	send := &fakeSender{}
	a := testAgent(send)
	ctx := context.Background()
	a.src.OffsetPath = filepath.Join(t.TempDir(), "tg-offset") // handleUpdate saves the cursor
	a.handleUpdate(ctx, telegram.Update{ChatID: 42, ChatType: "private", FromID: 42, Text: "/clear_chat"})
	send.mu.Lock()
	deleted := len(send.deleted)
	send.mu.Unlock()
	if deleted != 0 || !send.find("Delete recent messages?") {
		t.Fatalf("/clear_chat: deleted=%d sent=%v", deleted, send.all())
	}
	kb := lastKeyboard(send)
	if len(kb) != 1 || len(kb[0]) != 2 || tokenData(kb, tgui.ActYes) != kb[0][0].Data || tokenData(kb, tgui.ActNo) != kb[0][1].Data {
		t.Fatalf("confirm keyboard = %+v", kb)
	}

	a.handleCallback(ctx, &telegram.Callback{ID: "c1", ChatID: 42, ChatType: "private", FromID: 42, MessageID: lastSentID(send), Data: kb[0][1].Data})
	if !strings.Contains(send.lastEdit().html, "left as it is") {
		t.Errorf("Cancel edit = %q", send.lastEdit().html)
	}

	a.handleUpdate(ctx, telegram.Update{ChatID: 42, ChatType: "private", FromID: 42, Text: "/clear_chat"})
	prompt := lastSentID(send)
	a.handleCallback(ctx, &telegram.Callback{ID: "c2", ChatID: 42, ChatType: "private", FromID: 42, MessageID: prompt, Data: tokenData(lastKeyboard(send), tgui.ActYes)})
	send.mu.Lock()
	defer send.mu.Unlock()
	if len(send.deleted) != 301 {
		t.Fatalf("deleted %d ids, want 301", len(send.deleted))
	}
	if send.deleted[0] != prompt+1 { // anchor message id from the fake
		t.Errorf("sweep must start at the anchor id, got %d", send.deleted[0])
	}
	if last := send.sent[len(send.sent)-1]; !strings.HasPrefix(last, "🧾 Chat cleared · last 300 messages · by 42 · ") || !strings.HasSuffix(last, "\n🧹 cleared") {
		t.Errorf("outcome = %q, want a new message with the receipt", last)
	}
	if got := send.answered[len(send.answered)-1]; got != "c2:Working…" {
		t.Errorf("Yes answered %q", got)
	}
}

func TestReplyAttachesHomeKeyboard(t *testing.T) {
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
		t.Fatal("/status reply must carry the Home keyboard")
	}
	var labels []string
	for _, row := range kb {
		for _, b := range row {
			labels = append(labels, b.Text+"="+b.Data)
		}
	}
	joined := strings.Join(labels, " ")
	for _, want := range []string{"📈 Metrics=~1v|met", "🔐 Security=~1v|sec", "▶️ Live=~1lv", "🔄 Refresh=~1v|home"} {
		if !strings.Contains(joined, want) {
			t.Errorf("keyboard missing %q in %s", want, joined)
		}
	}
}

func TestReplyPlainForNonViews(t *testing.T) {
	send := &fakeSender{}
	a := testAgent(send)
	a.reply(context.Background(), "help", tgui.View{Text: "HELP TEXT"})
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
	if kb == nil || kb[0][0].Data != "~1up" {
		t.Fatalf("update offer keyboard = %+v", kb)
	}

	// Pressing Install asks; its Yes runs the update; Later dismisses.
	a.handleCallback(ctx, &telegram.Callback{ID: "cb2", ChatID: 42, MessageID: 9, Data: kb[0][0].Data})
	if applied {
		t.Fatal("install button must ask before applying")
	}
	a.handleCallback(ctx, &telegram.Callback{ID: "cb2y", ChatID: 42, MessageID: 9, Data: tokenData(lastEditKB(send), tgui.ActYes)})
	if !applied {
		t.Error("Yes must apply the update")
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
	if len(send.answered) == 0 || send.answered[0] != "cb:Live mode active (tap Stop to exit)" {
		t.Errorf("want callback toast 'Live mode active (tap Stop to exit)', got %+v", send.answered)
	}
	liveEdits := 0
	stopButtonSeen := false
	for _, e := range send.edits[:len(send.edits)-1] {
		if strings.Contains(e.html, "🔴 <b>LIVE</b>") {
			liveEdits++
			if !strings.Contains(e.html, "🔴 <b>LIVE</b> · ") {
				t.Errorf("frame missing elapsed time format: %q", e.html)
			}
		}
		if len(e.kb) == 1 && e.kb[0][0].Data == "~1ls" {
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
	flatNav := ""
	for _, row := range final.kb {
		for _, b := range row {
			flatNav += b.Data + " "
		}
	}
	if final.messageID != 7 || !strings.Contains(flatNav, "~1lv") || !strings.Contains(flatNav, "~1v|home") {
		t.Errorf("final edit must restore Home on msg 7: %+v", final)
	}
}

func TestLiveModeDoesNotAdvanceSamplerState(t *testing.T) {
	send := &fakeSender{}
	a := testAgent(send)
	a.liveInterval = 5 * time.Millisecond
	a.liveDuration = 30 * time.Millisecond
	a.trend = []trendPoint{{cpu: 42}}
	a.prevRaw = collect.Sample{Stat: procfs.Stat{Aggregate: procfs.CPUStat{User: 7}}}
	sampleCalls := 0
	a.src.Sample = func(context.Context) (collect.Sample, error) {
		sampleCalls++
		return collect.Sample{
			At:   time.Now(),
			Stat: procfs.Stat{Aggregate: procfs.CPUStat{Name: "cpu", User: 100, Idle: 900}},
			Mem:  procfs.MemInfo{Total: 8 << 30, Available: 4 << 30},
		}, nil
	}

	a.startLive(context.Background(), 42, 7, "")
	waitFor(t, func() bool {
		return send.editCount() > 1 && !strings.Contains(send.lastEdit().html, "LIVE")
	}, "live session to finish")

	if sampleCalls != 0 {
		t.Errorf("live mode collected %d samples, want none", sampleCalls)
	}
	if got := len(a.trend); got != 1 {
		t.Errorf("live mode grew trend to %d points, want 1", got)
	}
	if got := a.prevRaw.Stat.Aggregate.User; got != 7 {
		t.Errorf("live mode changed sampler baseline user ticks to %d, want 7", got)
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

	send.mu.Lock()
	defer send.mu.Unlock()
	if len(send.answered) < 2 || send.answered[0] != "c1:Live mode active (tap Stop to exit)" || send.answered[1] != "c2:" {
		t.Errorf("unexpected answered callbacks: %+v", send.answered)
	}
}

func TestWatchButtons(t *testing.T) {
	send := &fakeSender{}
	a := testAgent(send)
	cfgPath := filepath.Join(t.TempDir(), "config.toml")
	a.src.ConfigPath = cfgPath
	a.src.Runner = scanRunner{listOutput: "nginx.service loaded active running Web server\n"}
	a.src.ListListeners = func() ([]int, error) { return []int{443}, nil }
	ctx := context.Background()

	// Typed scan replies with the scan screen and its ➕ buttons.
	reply, cmd, _ := a.router.Dispatch(ctx, telegram.Update{ChatID: 42, Text: "/services_scan"})
	a.reply(ctx, cmd, reply)
	kb := lastKeyboard(send)
	wantWA := "~1wa|u|" + callbackDigest("nginx.service") + "|1"
	if kb == nil || kb[0][0].Data != wantWA || !strings.Contains(kb[0][0].Text, "➕") {
		t.Fatalf("scan keyboard = %+v", kb)
	}

	// Pressing ➕ adds the unit, persists, and re-renders the scan; a
	// replay finds it watched and changes nothing.
	press(a, "c1", wantWA)
	saved, err := config.Load(cfgPath)
	if err != nil || len(saved.Watch.Services) != 1 || saved.Watch.Services[0] != "nginx.service" {
		t.Fatalf("after %s saved=%+v err=%v", wantWA, saved.Watch, err)
	}
	if last := send.lastEdit(); !strings.Contains(last.html, "already watched") {
		t.Errorf("re-rendered scan should show empty candidates: %q", last.html)
	}
	press(a, "c1r", wantWA)
	if got := a.watchCopy().Services; len(got) != 1 {
		t.Errorf("replayed ➕ changed the list: %v", got)
	}

	// Port add button.
	press(a, "c2", "~1wa|p|443|1")
	saved, _ = config.Load(cfgPath)
	if len(saved.Watch.Ports) != 1 || saved.Watch.Ports[0].Port != 443 {
		t.Fatalf("after wa|p|443 ports=%+v", saved.Watch.Ports)
	}

	// Watching lists both with 🗑 buttons carrying their IDs.
	press(a, "c3", "~1v|wat")
	last := send.lastEdit()
	if !strings.Contains(last.html, "nginx.service") || !strings.Contains(last.html, "🔌 443") {
		t.Errorf("watching view = %q", last.html)
	}
	wantWR := "~1wr|u|" + callbackDigest("nginx.service") + "|1"
	if flat := dumpKeyboard(last.kb); !strings.Contains(flat, wantWR) || !strings.Contains(flat, "~1wr|p|443|1") {
		t.Errorf("watching keyboard = %s", flat)
	}

	// 🗑 removes and persists.
	press(a, "c4", wantWR)
	press(a, "c5", "~1wr|p|443|1")
	saved, _ = config.Load(cfgPath)
	if len(saved.Watch.Services) != 0 || len(saved.Watch.Ports) != 0 {
		t.Errorf("after removals: %+v", saved.Watch)
	}
	if last := send.lastEdit(); !strings.Contains(last.html, "Nothing yet") {
		t.Errorf("empty watching view = %q", last.html)
	}
	// The legacy buttons of older keyboards still add and remove.
	press(a, "l1", "pa:8080")
	press(a, "l2", "pr:8080")
	if got := a.watchCopy().Ports; len(got) != 0 || !strings.HasPrefix(send.lastEdit().html, "👁 <b>Watching</b>") {
		t.Errorf("legacy pa/pr: ports %v, view %q", got, send.lastEdit().html)
	}
}

// TestScanAddIdentity: a ➕ button adds only the unit it was drawn for, even
// if a later scan shifted the list, and legacy sa:<n> never adds anything.
func TestScanAddIdentity(t *testing.T) {
	cases := []struct {
		name      string
		data      string
		rescan    string // scan output before the tap, "" = unchanged
		wantAdded string
		wantToast string
	}{
		{"same list", watchIndexData("sa:", 0, "nginx.service"), "", "nginx.service", "watching nginx.service"},
		{"list shifted", watchIndexData("sa:", 0, "nginx.service"),
			"cron.service loaded active running Jobs\nnginx.service loaded active running Web\n", "", "stale list"},
		{"unit gone", watchIndexData("sa:", 1, "redis.service"), "", "", "stale list"},
		{"legacy index", "sa:1", "", "", "List refreshed"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			send := &fakeSender{}
			a := testAgent(send)
			cfgPath := filepath.Join(t.TempDir(), "config.toml")
			a.src.ConfigPath = cfgPath
			runner := &scanRunner{listOutput: "nginx.service loaded active running Web\ncron.service loaded active running Jobs\n"}
			a.src.Runner = runner
			ctx := context.Background()

			a.handleCallback(ctx, &telegram.Callback{ID: "c0", ChatID: 42, MessageID: 5, Data: "scan_svc"})
			if tc.rescan != "" {
				runner.listOutput = tc.rescan
				a.handleCallback(ctx, &telegram.Callback{ID: "c1", ChatID: 42, MessageID: 6, Data: "scan_svc"})
			}
			a.handleCallback(ctx, &telegram.Callback{ID: "c2", ChatID: 42, MessageID: 5, Data: tc.data})

			saved, _ := config.Load(cfgPath)
			added := strings.Join(saved.Watch.Services, ",")
			if added != tc.wantAdded {
				t.Errorf("watched services = %q, want %q", added, tc.wantAdded)
			}
			send.mu.Lock()
			toast := send.answered[len(send.answered)-1]
			send.mu.Unlock()
			if !strings.Contains(toast, tc.wantToast) {
				t.Errorf("toast = %q, want %q", toast, tc.wantToast)
			}
		})
	}
}

// A ➕ button names its unit by digest, resolved against a fresh scan:
// it adds that unit even after the list shifted, and nothing when the
// unit is gone.
func TestScanAddByDigest(t *testing.T) {
	cases := []struct {
		name      string
		unit      string
		rescan    string // scan output before the tap, "" = unchanged
		wantAdded string
		wantToast string
	}{
		{"same list", "nginx.service", "", "nginx.service", "c:✅ Watching nginx.service (not persisted: no config path)"},
		{"list shifted", "nginx.service", "redis.service loaded active running KV\nnginx.service loaded active running Web\n",
			"nginx.service", "c:✅ Watching nginx.service (not persisted: no config path)"},
		{"unit gone", "nginx.service", "cron.service loaded active running Jobs\n", "", "c:" + itemGoneToast},
		{"never listed", "redis.service", "", "", "c:" + itemGoneToast},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			send := &fakeSender{}
			a := testAgent(send)
			runner := &scanRunner{listOutput: "nginx.service loaded active running Web\ncron.service loaded active running Jobs\n"}
			a.src.Runner = runner
			if tc.rescan != "" {
				runner.listOutput = tc.rescan
			}
			press(a, "c", "~1wa|u|"+callbackDigest(tc.unit)+"|1")
			if got := strings.Join(a.watchCopy().Services, ","); got != tc.wantAdded {
				t.Errorf("watched services = %q, want %q", got, tc.wantAdded)
			}
			if !slices.Equal(send.answered, []string{tc.wantToast}) || !strings.HasPrefix(send.lastEdit().html, "🔎 ") {
				t.Errorf("answered = %v, view %q", send.answered, send.lastEdit().html)
			}
		})
	}
}

func TestWatchingCommand(t *testing.T) {
	send := &fakeSender{}
	a := testAgent(send)
	ctx := context.Background()
	reply, cmd, ok := a.router.Dispatch(ctx, telegram.Update{ChatID: 42, Text: "/watching"})
	if !ok || !strings.Contains(reply.Text, "Nothing yet") {
		t.Fatalf("/watching = %q", reply.Text)
	}
	a.reply(ctx, cmd, reply)
	send.mu.Lock()
	defer send.mu.Unlock()
	kb := send.keyboards[len(send.keyboards)-1]
	if len(kb) < 2 || kb[len(kb)-2][0].Data != "~1v|scs" || kb[len(kb)-1][1].Data != "~1v|home" {
		t.Errorf("watching keyboard = %+v", kb)
	}
}

func TestAlertActionButtons(t *testing.T) {
	send := &fakeSender{}
	a := testAgent(send)
	ctx := context.Background()

	// Root login alert carries the SSH action row.
	a.handleAuthLine(ctx, "Accepted password for root from 203.0.113.7 port 22 ssh2", time.Now())
	send.mu.Lock()
	kb := send.keyboards[len(send.keyboards)-1]
	send.mu.Unlock()
	if kb == nil || len(kb[0]) != 3 || kb[0][0].Data != "~1o|ses" || kb[0][1].Data != "~1o|fai" || kb[0][2].Data != "~1o|fw" {
		t.Fatalf("ssh alert keyboard = %+v", kb)
	}
	if last := kb[len(kb)-1]; len(last) != 3 || !strings.HasPrefix(last[0].Data, "~1sz|1h|") {
		t.Fatalf("alert keyboard missing snooze row: %+v", kb)
	}

	// CPU threshold alert leads with the Top button (find the culprit),
	// then the CPU view.
	a.pushAlert(ctx, alert.Alert{Key: "cpu", Title: "CPU usage", Body: "high"})
	send.mu.Lock()
	kb = send.keyboards[len(send.keyboards)-1]
	send.mu.Unlock()
	if kb == nil || kb[0][0].Data != "~1o|top" || kb[0][1].Data != "~1o|cpu" {
		t.Fatalf("cpu alert keyboard = %+v", kb)
	}

	// Disk alerts have compound keys; the prefix selects the view.
	a.pushAlert(ctx, alert.Alert{Key: "disk:/home", Title: "Disk space", Body: "low"})
	send.mu.Lock()
	kb = send.keyboards[len(send.keyboards)-1]
	send.mu.Unlock()
	if kb == nil || kb[0][0].Data != "~1o|dsk" {
		t.Fatalf("disk alert keyboard = %+v", kb)
	}

	// The fails button resolves to a real screen, sent as a reply to
	// the alert; the legacy button of older alerts too, in place.
	a.handleCallback(ctx, &telegram.Callback{ID: "cb", ChatID: 42, MessageID: 3, Data: "~1o|fai"})
	if sent := send.all(); !strings.Contains(sent[len(sent)-1], "Failed logins") {
		t.Errorf("fails button view = %q", sent[len(sent)-1])
	}
	a.handleCallback(ctx, &telegram.Callback{ID: "cb", ChatID: 42, MessageID: 3, Data: "ssh_fails"})
	if last := send.lastEdit(); !strings.Contains(last.html, "Failed logins") {
		t.Errorf("ssh_fails callback view = %q", last.html)
	}
}

func TestStartupHelloHasButtons(t *testing.T) {
	send := &fakeSender{}
	a := testAgent(send)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- a.Run(ctx) }()
	waitFor(t, func() bool { return send.find("statix-agent started") }, "hello message")
	cancel()
	<-done

	send.mu.Lock()
	defer send.mu.Unlock()
	for i, s := range send.sent {
		if strings.Contains(s, "statix-agent started") {
			kb := send.keyboards[i]
			if kb == nil || kb[0][0].Data != "~1v|home" || kb[0][1].Data != "~1v|wat" {
				t.Errorf("hello keyboard = %+v", kb)
			}
			return
		}
	}
	t.Fatal("hello not found")
}

func TestSettingsButtons(t *testing.T) {
	send := &fakeSender{}
	a := testAgent(send)
	unlimitPresses(a)
	cfgPath := filepath.Join(t.TempDir(), "config.toml")
	a.src.ConfigPath = cfgPath
	ctx := context.Background()

	// /settings shows thresholds with tune buttons carrying their targets.
	reply, cmd, _ := a.router.Dispatch(ctx, telegram.Update{ChatID: 42, Text: "/settings"})
	if !strings.Contains(reply.Text, "Alert thresholds") || !strings.Contains(reply.Text, "90%") {
		t.Fatalf("/settings = %q", reply.Text)
	}
	a.reply(ctx, cmd, reply)
	send.mu.Lock()
	kb := send.keyboards[len(send.keyboards)-1]
	send.mu.Unlock()
	if kb == nil || kb[0][0].Data != "~1th|cpu|85" || kb[0][1].Data != "~1th|cpu" || kb[0][2].Data != "~1th|cpu|95" ||
		kb[0][0].Text != "🖥 CPU −5" || kb[0][2].Text != "🖥 CPU +5" {
		t.Fatalf("settings keyboard = %+v", kb)
	}

	// −5 lowers the CPU threshold to 85, persists, re-renders.
	press(a, "c1", kb[0][0].Data)
	if got := a.thresholds().CPUPercent; got != 85 {
		t.Errorf("cpu threshold = %.0f, want 85", got)
	}
	saved, err := config.Load(cfgPath)
	if err != nil || saved.Thresholds.CPUPercent != 85 {
		t.Errorf("saved cpu threshold = %+v err=%v", saved.Thresholds, err)
	}
	if last := send.lastEdit(); !strings.Contains(last.html, "85%") || last.kb[0][0].Data != "~1th|cpu|80" {
		t.Errorf("re-rendered settings = %q\n%s", last.html, dumpKeyboard(last.kb))
	}
	if got := send.answered[len(send.answered)-1]; got != "c1:CPU alert → 85%" {
		t.Errorf("answered %q", got)
	}

	// Clamping: battery cannot go below its floor, pressing the −5 each
	// fresh screen offers.
	for i := range 10 {
		press(a, fmt.Sprint("b", i), send.lastEdit().kb[4][0].Data)
	}
	if got := a.thresholds().BatteryPercent; got != 5 {
		t.Errorf("battery threshold = %.0f, want clamped to 5", got)
	}

	// Live evaluation uses the tuned threshold: CPU at 87% now alerts.
	als := evalSustained(a, collect.Snapshot{CPUTotal: collect.CPUUsage{Percent: 87}, Mem: procfs.MemInfo{Total: 100, Available: 60}}, time.Now())
	if countNonNil(als) != 1 {
		t.Errorf("tuned threshold must fire at 87%%: %+v", als)
	}

	// The value label explains the row without changing or editing it.
	before := send.editCount()
	press(a, "l", kb[0][1].Data)
	if send.editCount() != before || send.answered[len(send.answered)-1] != "l:Tap −5 or +5 to change the CPU alert." {
		t.Errorf("value label: edits %d→%d, answered %q", before, send.editCount(), send.answered[len(send.answered)-1])
	}

	// The noop labels of older keyboards answer without editing.
	press(a, "c3", "noop")
	if send.editCount() != before {
		t.Error("noop must not edit")
	}
}

// A threshold button carries its target, so pressing it again (a double
// tap, a replayed update, an old message) changes nothing.
func TestThresholdReplayChangesNothing(t *testing.T) {
	send := &fakeSender{}
	a := testAgent(send)
	cfgPath := filepath.Join(t.TempDir(), "config.toml")
	a.src.ConfigPath = cfgPath
	_, kb := a.settingsView()
	down := kb[0][0].Data // CPU 90 → 85
	press(a, "c1", down)
	saved, err := os.Stat(cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	for i := range 3 {
		press(a, fmt.Sprint("r", i), down)
	}
	if got := a.thresholds().CPUPercent; got != 85 {
		t.Errorf("after replays cpu threshold = %.0f, want 85", got)
	}
	if again, err := os.Stat(cfgPath); err != nil || !again.ModTime().Equal(saved.ModTime()) {
		t.Errorf("a replay rewrote the config: %v", err)
	}
	want := []string{"c1:CPU alert → 85%", "r0:CPU alert is already 85%", "r1:CPU alert is already 85%", "r2:CPU alert is already 85%"}
	if !slices.Equal(send.answered, want) {
		t.Errorf("answered = %v", send.answered)
	}
	// The old button of a value tuned since still sets what it says.
	press(a, "up", "~1th|cpu|95")
	press(a, "old", down)
	if got := a.thresholds().CPUPercent; got != 85 {
		t.Errorf("old button set %.0f, want its 85", got)
	}
}

// Forged threshold targets are refused: never NaN, Inf, out of range or
// in a form no button emits.
func TestThresholdForgedTargets(t *testing.T) {
	for _, data := range []string{"~1th|cpu|NaN", "~1th|cpu|Inf", "~1th|cpu|-Inf", "~1th|cpu|100", "~1th|cpu|49",
		"~1th|cpu|085", "~1th|cpu|85.0", "~1th|cpu|-5", "~1th|batt|4", "~1th|temp|106", "~1th|nope|80", "~1th|nope",
		"~1th", "~1th|cpu|85|1"} {
		send := &fakeSender{}
		a := testAgent(send)
		before := a.thresholds()
		press(a, "f", data)
		if a.thresholds() != before || !slices.Equal(send.answered, []string{"f:" + outdatedToast}) || len(send.edits) != 0 {
			t.Errorf("%s: answered %v, thresholds %+v", data, send.answered, a.thresholds())
		}
	}
}

// Thresholds change the bot's settings: a group viewer is refused.
func TestThresholdNeedsAdmin(t *testing.T) {
	send := &fakeSender{}
	a, _ := authAgent(t, send, -100, 7)
	a.handleCallback(context.Background(), &telegram.Callback{ID: "v", ChatID: -100, ChatType: "supergroup", FromID: 5, MessageID: 3, Data: "~1th|cpu|85"})
	if a.thresholds().CPUPercent != 90 || !slices.Equal(send.answered, []string{"v:" + adminOnlyToast}) {
		t.Errorf("viewer tuned: answered %v", send.answered)
	}
}

// Settings buttons of older versions carry a step; each press applies it.
func TestSettingsLegacyStep(t *testing.T) {
	send := &fakeSender{}
	a := testAgent(send)
	press(a, "c1", "th:cpu:-5")
	press(a, "c2", "th:cpu:-5")
	if got := a.thresholds().CPUPercent; got != 80 {
		t.Errorf("cpu threshold = %.0f, want 80", got)
	}
	if !strings.HasPrefix(send.lastEdit().html, "⚙️ <b>Settings</b>") || send.lastEdit().kb[0][0].Data != "~1th|cpu|75" {
		t.Errorf("legacy step re-rendered\n%s", dumpKeyboard(send.lastEdit().kb))
	}
}

func TestCPUTrendSparkline(t *testing.T) {
	send := &fakeSender{}
	a := testAgent(send)
	ctx := context.Background()
	// Two samples populate the trend ring.
	a.sampleOnce(ctx)
	a.sampleOnce(ctx)
	reply, _, _ := a.router.Dispatch(ctx, telegram.Update{ChatID: 42, Text: "/cpu"})
	if !strings.Contains(reply.Text, "trend") {
		t.Errorf("/cpu after 2 samples must show a trend line: %q", reply.Text)
	}
	// A fresh agent with <2 samples shows no trend.
	b := testAgent(&fakeSender{})
	reply, _, _ = b.router.Dispatch(ctx, telegram.Update{ChatID: 42, Text: "/cpu"})
	if strings.Contains(reply.Text, "trend") {
		t.Errorf("no-history /cpu must omit trend: %q", reply.Text)
	}
}

func TestParseUFWStatus(t *testing.T) {
	cases := []struct {
		name string
		out  string
		want sshPortState
	}{
		{"inactive", "Status: inactive\n", fwInactive},
		{"empty", "", fwUnparsed},
		{"non-ufw output", "ActiveState=active\nSubState=running\n", fwUnparsed},
		// CombinedOutput merges stderr, so warnings can precede the status
		// line; anchoring on line 0 would hide a healthy firewall.
		{"warning before status", "SyntaxWarning: invalid escape sequence '\\d'\nStatus: active\n\n22/tcp  ALLOW  Anywhere\n", fwOpen},
		{"warning before inactive", "WARN: uid is 0 but '/etc/ufw' is owned by 1000\nStatus: inactive\n", fwInactive},
		{"open", "Status: active\n\nTo                         Action      From\n--                         ------      ----\n22/tcp                     ALLOW       Anywhere\n80/tcp                     ALLOW       Anywhere\n22/tcp (v6)                ALLOW       Anywhere (v6)\n", fwOpen},
		{"closed", "Status: active\n\n22/tcp                     DENY        Anywhere\n", fwClosed},
		{"deny listed first wins", "Status: active\n\n22/tcp  DENY  Anywhere\n22/tcp  ALLOW  Anywhere\n", fwClosed},
		{"unmanaged", "Status: active\n\n443/tcp  ALLOW  Anywhere\n", fwUnmanaged},
		{"bare port form", "Status: active\n\n22  ALLOW  Anywhere\n", fwOpen},
	}
	for _, tc := range cases {
		if got := parseUFWStatus(tc.out); got != tc.want {
			t.Errorf("%s: parseUFWStatus = %v, want %v", tc.name, got, tc.want)
		}
	}
}

// failingUFW reports active+open status but fails on any rule change,
// mimicking the read-only-filesystem sandbox error.
type failingUFW struct{}

func (failingUFW) Run(_ context.Context, name string, args ...string) (string, error) {
	if name == "ufw" && args[0] == "status" {
		return "Status: active\n\n22/tcp  ALLOW  Anywhere\n", nil
	}
	return "ERROR: Could not open /etc/ufw/user.rules: read-only file system", errors.New("exit status 1")
}

func TestFirewallChangeFailureIsVisible(t *testing.T) {
	send := &fakeSender{}
	a := testAgent(send)
	a.src.Runner = failingUFW{}
	allowFw(t, a)

	id := confirmThrough(t, a, send, "fw_close_ask", 4)

	last := send.lastEdit()
	if !strings.Contains(last.html, "Change failed") || !strings.Contains(last.html, "read-only file system") {
		t.Errorf("failure must be shown persistently in the message, got: %q", last.html)
	}
	// The read-only error must come with the one-time sandbox fix command.
	if !strings.Contains(last.html, "ReadWritePaths=-/etc/ufw") {
		t.Errorf("sandbox failure must include the fix command, got: %q", last.html)
	}
	// The press was acknowledged before ufw ran; the banner alone carries
	// the failure, with no redundant toast line above it.
	if out := slowOutcome(t, send, id); strings.Contains(out, failedToast) {
		t.Errorf("failure toast echoed into the message: %q", out)
	}
}

// assertNoFirewallActions fails when a view offers a rule-changing button.
// Every state the agent cannot act on must be a dead end, not a trap.
func assertNoFirewallActions(t *testing.T, kb telegram.Keyboard) {
	t.Helper()
	for _, row := range kb {
		for _, b := range row {
			if strings.HasPrefix(b.Data, "fw_") {
				t.Errorf("non-manageable firewall must offer no actions: %+v", kb)
			}
		}
	}
}

// missingUFW is a host without ufw — Alpine, Arch, a Debian netinst, or a
// container: every candidate path fails to resolve.
type missingUFW struct{ calls [][]string }

func (m *missingUFW) Run(_ context.Context, name string, args ...string) (string, error) {
	m.calls = append(m.calls, append([]string{name}, args...))
	return "", &exec.Error{Name: name, Err: exec.ErrNotFound}
}

// sbinUFW has ufw installed at /usr/sbin/ufw only, as on a service whose
// PATH omits the sbin directories.
type sbinUFW struct{ calls [][]string }

func (s *sbinUFW) Run(_ context.Context, name string, args ...string) (string, error) {
	s.calls = append(s.calls, append([]string{name}, args...))
	if name != "/usr/sbin/ufw" {
		return "", &exec.Error{Name: name, Err: exec.ErrNotFound}
	}
	if args[0] == "status" {
		return "Status: active\n\n22/tcp  ALLOW  Anywhere\n", nil
	}
	return "Rule updated", nil
}

// notRootUFW is ufw present but refusing to run: the useful message is in
// the output, not in the exit status.
type notRootUFW struct{}

func (notRootUFW) Run(_ context.Context, _ string, _ ...string) (string, error) {
	return "ERROR: You need to be root to run this script", errors.New("exit status 1")
}

// inactiveUFW is ufw installed but never enabled.
type inactiveUFW struct{}

func (inactiveUFW) Run(_ context.Context, _ string, _ ...string) (string, error) {
	return "Status: inactive", nil
}

func TestFirewallMissingUFW(t *testing.T) {
	a := testAgent(&fakeSender{})
	runner := &missingUFW{}
	a.src.Runner = runner
	text, kb := a.firewallView(context.Background())

	if !strings.Contains(text, "not installed") {
		t.Errorf("missing-ufw view = %q", text)
	}
	// The old copy claimed the host was wide open and prescribed `ufw
	// enable`; on a firewalld or nftables host both are false, and acting on
	// them puts two rule owners on the same tables.
	if strings.Contains(text, "all ports are open") || strings.Contains(text, "ufw enable") {
		t.Errorf("must not claim the host is unprotected: %q", text)
	}
	if !strings.Contains(text, "firewalld") || !strings.Contains(text, "nftables") {
		t.Errorf("must name the likely backends: %q", text)
	}
	if strings.Contains(text, "exec:") {
		t.Errorf("raw exec error leaked into the view: %q", text)
	}
	assertNoFirewallActions(t, kb)
	// Every candidate path is probed before declaring the binary missing;
	// then the other firewalls are looked for, each once per path.
	want := len(ufwPaths) + len(firewalldPaths) + len(nftPaths) + len(iptablesPaths)
	if len(runner.calls) != want || !slices.Equal(runner.calls[len(ufwPaths)-1], []string{ufwPaths[len(ufwPaths)-1], "status"}) {
		t.Errorf("probe calls = %v, want one per candidate path", runner.calls)
	}
}

func TestFirewallMissingUFWBlocksChange(t *testing.T) {
	send := &fakeSender{}
	a := testAgent(send)
	runner := &missingUFW{}
	a.src.Runner = runner
	allowFw(t, a)
	// Telegram keeps inline keyboards live on old messages, so a confirm
	// can be pressed after ufw was removed. The action path must refuse
	// on its own.
	confirmThrough(t, a, send, "fw_close_ask", 4)

	last := send.lastEdit()
	if !strings.Contains(last.html, "ufw is not installed") {
		t.Errorf("stale button = %q", last.html)
	}
	if strings.Contains(last.html, "executable file not found") {
		t.Errorf("raw exec error must not reach the user: %q", last.html)
	}
	// The sandbox hint is for ufw's own write failures; it cannot fix this.
	if strings.Contains(last.html, "ReadWritePaths") {
		t.Errorf("systemd hint must not fire on a missing binary: %q", last.html)
	}
	for _, c := range runner.calls {
		if probe := strings.Join(c[1:], " "); probe != "status" && probe != "--state" && probe != "list ruleset" && probe != "-S" {
			t.Errorf("no rule change may run without ufw: %v", runner.calls)
		}
	}
}

// blockedUFW is ufw present but not executable: a noexec mount, a MAC
// policy, or mode 0700. exec reports it through the error, not through
// output, which is what ReadWritePaths advice must not be triggered by.
type blockedUFW struct{}

func (blockedUFW) Run(_ context.Context, name string, _ ...string) (string, error) {
	return "", &fs.PathError{Op: "fork/exec", Path: name, Err: fs.ErrPermission}
}

func TestFirewallBlockedBinaryGetsNoSandboxHint(t *testing.T) {
	send := &fakeSender{}
	a := testAgent(send)
	a.src.Runner = blockedUFW{}
	allowFw(t, a)
	confirmThrough(t, a, send, "fw_close_ask", 4)

	last := send.lastEdit()
	if !strings.Contains(last.html, "permission denied") {
		t.Errorf("the real cause must be shown: %q", last.html)
	}
	// The systemd snippet fixes ufw's own file writes; it cannot make a
	// non-executable binary run, so offering it here sends the user in
	// circles.
	if strings.Contains(last.html, "ReadWritePaths") {
		t.Errorf("exec-level failure must not draw the sandbox hint: %q", last.html)
	}
}

func TestFirewallInactiveBlocksChange(t *testing.T) {
	send := &fakeSender{}
	a := testAgent(send)
	a.src.Runner = inactiveUFW{}
	allowFw(t, a)
	// The view was rendered while ufw was active, then someone ran
	// `ufw disable`. Writing the rule anyway would report "port 22 closed"
	// while nothing is enforced.
	confirmThrough(t, a, send, "fw_close_ask", 4)

	last := send.lastEdit()
	if !strings.Contains(last.html, "would not be enforced") {
		t.Errorf("inactive ufw must refuse the change: %q", last.html)
	}
	if strings.Contains(last.html, "Port 22 closed") {
		t.Errorf("must not claim a change that is not enforced: %q", last.html)
	}
}

func TestFirewallNotRootShowsUFWsOwnError(t *testing.T) {
	a := testAgent(&fakeSender{})
	a.src.Runner = notRootUFW{}
	text, kb := a.firewallView(context.Background())

	if !strings.Contains(text, "need to be root") {
		t.Errorf("must surface ufw's own message: %q", text)
	}
	if strings.Contains(text, "exit status 1") {
		t.Errorf("exit status must not replace the real cause: %q", text)
	}
	if strings.Contains(text, "not installed") || strings.Contains(text, "all ports are open") {
		t.Errorf("a blocked probe is not a missing or inactive ufw: %q", text)
	}
	assertNoFirewallActions(t, kb)
}

func TestFirewallSbinFallback(t *testing.T) {
	a := testAgent(&fakeSender{})
	runner := &sbinUFW{}
	a.src.Runner = runner
	ctx := context.Background()

	// A restricted service PATH must not be reported as a missing package.
	if text, _ := a.firewallView(ctx); !strings.Contains(text, "🔓 <b>open</b>") {
		t.Errorf("ufw in sbin must be found: %q", text)
	}
	// Rule changes go to the same resolved binary, not back to bare "ufw".
	b := a.fwBackend("")
	if p := b.Probe(ctx); !p.manageable() {
		t.Fatalf("probe = %+v", p)
	}
	if _, err := b.Apply(ctx, fwPlan{{Op: opInsert, Spec: []string{"deny", sshPort}}}); err != nil {
		t.Fatalf("Apply failed: %v", err)
	}
	var changed bool
	for _, c := range runner.calls {
		// The view also probes sshd and ss for the SSH port; only ufw
		// invocations are under test here.
		if c[1] == "status" || !strings.HasSuffix(c[0], "ufw") {
			continue
		}
		if c[0] != "/usr/sbin/ufw" {
			t.Errorf("rule change did not use the resolved path: %v", c)
		}
		if c[1] == "insert" {
			changed = true
		}
	}
	if !changed {
		t.Errorf("rule change never ran: %v", runner.calls)
	}
}

func TestFirewallInactiveHasNoActions(t *testing.T) {
	a := testAgent(&fakeSender{})
	a.src.Runner = inactiveUFW{}
	text, kb := a.firewallView(context.Background())
	if !strings.Contains(text, "<b>inactive</b>") || !strings.Contains(text, "ufw enable") {
		t.Errorf("inactive view = %q", text)
	}
	assertNoFirewallActions(t, kb)
}

func TestFirewallUnparsedStatusHasNoActions(t *testing.T) {
	a := testAgent(&fakeSender{})
	a.src.Runner = scanRunner{} // answers, but not with anything ufw-shaped
	text, kb := a.firewallView(context.Background())
	if !strings.Contains(text, "could not read") || !strings.Contains(text, "<b>unknown</b>") {
		t.Errorf("unparsed view = %q", text)
	}
	if strings.Contains(text, "all ports are open") {
		t.Errorf("an unreadable state must not be reported as open: %q", text)
	}
	assertNoFirewallActions(t, kb)
}

func TestSandboxHintOnlyForUFWWriteErrors(t *testing.T) {
	readOnly := &fwFailure{
		cmd: "ufw deny 22/tcp",
		out: "ERROR: Could not open /etc/ufw/user.rules: read-only file system",
		err: errors.New("exit status 1"),
	}
	if !strings.Contains(sandboxHint(readOnly), "ReadWritePaths=-/etc/ufw") {
		t.Error("ufw's own write failure must carry the sandbox fix")
	}
	// `permission denied` on the binary — a noexec mount or a MAC policy —
	// is a different problem that ReadWritePaths cannot fix. The failure is
	// built the way the probe path builds it: ufw itself printed nothing,
	// so the message lives in err, where the matcher must not see it.
	execDenied := &fwFailure{cmd: "/usr/sbin/ufw status",
		err: &fs.PathError{Op: "fork/exec", Path: "/usr/sbin/ufw", Err: fs.ErrPermission}}
	if got := sandboxHint(execDenied); got != "" {
		t.Errorf("sandboxHint on an exec error = %q, want empty", got)
	}
	if d := execDenied.display(); !strings.Contains(d, "permission denied") {
		t.Errorf("the cause must still be shown to the user: %q", d)
	}
	execNotFound := &fwFailure{cmd: "ufw deny 22/tcp", err: &exec.Error{Name: "ufw", Err: exec.ErrNotFound}}
	if got := sandboxHint(execNotFound); got != "" {
		t.Errorf("sandboxHint on a missing binary = %q, want empty", got)
	}
	if got := sandboxHint(&fwFailure{reason: "ufw is not installed on this host"}); got != "" {
		t.Errorf("sandboxHint without ufw output = %q, want empty", got)
	}
}

// kickRunner records invocations and reports success.
type kickRunner struct {
	calls [][]string
}

func (k *kickRunner) Run(_ context.Context, name string, args ...string) (string, error) {
	k.calls = append(k.calls, append([]string{name}, args...))
	return "", nil
}

// sshTestEpoch is fixed so every Sessions() call reports the same logins,
// as utmp does; kick buttons fingerprint the start time.
var sshTestEpoch = time.Now()

func sshTestSessions() []sshwatch.Session {
	return []sshwatch.Session{
		{User: "alice", TTY: "pts/0", Host: "10.0.0.5", Since: sshTestEpoch.Add(-time.Hour)},
		{User: "bob", TTY: "pts/1", Host: "10.0.0.6", Since: sshTestEpoch.Add(-time.Minute)},
	}
}

// sessionsFrom serves *list on every call so a test can change the live
// sessions between taps.
func sessionsFrom(list *[]sshwatch.Session) func() ([]sshwatch.Session, error) {
	return func() ([]sshwatch.Session, error) {
		return append([]sshwatch.Session(nil), (*list)...), nil
	}
}

func TestSSHKickFlow(t *testing.T) {
	send := &fakeSender{}
	a := testAgent(send)
	runner := &kickRunner{}
	a.src.Runner = runner
	a.src.Sessions = func() ([]sshwatch.Session, error) { return sshTestSessions(), nil }
	ctx := context.Background()

	// /ssh lists sessions with one kick button per session plus nav rows.
	reply, cmd, _ := a.router.Dispatch(ctx, telegram.Update{ChatID: 42, Text: "/ssh"})
	if !strings.Contains(reply.Text, "alice") || !strings.Contains(reply.Text, "Active sessions") {
		t.Fatalf("/ssh = %q", reply.Text)
	}
	a.reply(ctx, cmd, reply)
	send.mu.Lock()
	kb := send.keyboards[len(send.keyboards)-1]
	send.mu.Unlock()
	sessions := sshTestSessions()
	wantSK1 := "~1kk|" + sessionFingerprint(sessions[0])
	if kb == nil || kb[0][0].Data != wantSK1 || kb[0][1].Data != "~1kk|"+sessionFingerprint(sessions[1]) {
		t.Fatalf("ssh keyboard = %+v", kb)
	}
	if kb[1][0].Data != "~1v|his^ses" || kb[2][1].Data != "~1v|home" {
		t.Fatalf("nav rows must follow kick rows: %+v", kb)
	}

	// The ask step warns and does NOT signal anything.
	a.handleCallback(ctx, &telegram.Callback{ID: "c1", ChatID: 42, MessageID: 7, Data: wantSK1})
	if len(runner.calls) != 0 {
		t.Fatal("confirmation screen must not run pkill")
	}
	last := send.lastEdit()
	if !strings.Contains(last.html, "Disconnect SSH session?") || !strings.Contains(last.html, "alice") {
		t.Fatalf("ask view = %q", last.html)
	}
	if last.kb[0][0].Data != tokenData(last.kb, tgui.ActYes) || last.kb[0][1].Data != tokenData(last.kb, tgui.ActNo) {
		t.Fatalf("ask keyboard = %+v", last.kb)
	}

	// Confirming kicks the chosen tty and re-renders the list.
	a.handleCallback(ctx, &telegram.Callback{ID: "c2", ChatID: 42, MessageID: 7, Data: last.kb[0][0].Data})
	if len(runner.calls) != 1 || strings.Join(runner.calls[0], " ") != "pkill -KILL -t pts/0" {
		t.Fatalf("runner calls = %v", runner.calls)
	}
	if last := send.lastEdit(); !strings.Contains(last.html, "Active sessions") {
		t.Errorf("after kick view = %q", last.html)
	}
	if out := slowOutcome(t, send, "c2"); !strings.Contains(out, "alice disconnected") {
		t.Errorf("kick outcome = %q", out)
	}
}

func TestSSHKickStaleIndex(t *testing.T) {
	send := &fakeSender{}
	a := testAgent(send)
	runner := &kickRunner{}
	a.src.Runner = runner
	a.src.Sessions = func() ([]sshwatch.Session, error) { return sshTestSessions()[:1], nil }
	ctx := context.Background()

	a.handleCallback(ctx, &telegram.Callback{ID: "c0", ChatID: 42, MessageID: 7, Data: "ssh"})
	a.handleCallback(ctx, &telegram.Callback{ID: "c1", ChatID: 42, MessageID: 7,
		Data: sessionCallbackData("sk:", 5, sshTestSessions()[0])})
	if len(runner.calls) != 0 {
		t.Fatal("stale index must not run pkill")
	}
	send.mu.Lock()
	toast := send.answered[len(send.answered)-1]
	send.mu.Unlock()
	if !strings.Contains(toast, "Session changed, refreshed") {
		t.Errorf("toast = %q", toast)
	}
	if last := send.lastEdit(); !strings.Contains(last.html, "Active sessions") {
		t.Errorf("stale index must re-render the list: %q", last.html)
	}
}

// TestSSHKickIdentity checks that a kick button only ever reaches the login
// it was drawn for, whatever happens to the list between the taps.
func TestSSHKickIdentity(t *testing.T) {
	alice, bob := sshTestSessions()[0], sshTestSessions()[1]
	aliceAgain := alice
	aliceAgain.Since = alice.Since.Add(30 * time.Second) // re-login on pts/0
	both := []sshwatch.Session{alice, bob}
	cases := []struct {
		name      string
		data      string             // the Kick button pressed
		before    []sshwatch.Session // live sessions at Kick time
		after     []sshwatch.Session // at Yes time; nil = no Yes is offered
		wantKill  string             // tty signalled, "" = none
		wantToast string             // ask's answer, or the outcome on Yes
	}{
		{"confirm same login", sessionCallbackData("sk:", 1, alice),
			both, both, "pts/0", "disconnected"},
		{"list shifted under index", sessionCallbackData("sk:", 1, alice),
			both, []sshwatch.Session{bob, alice}, "pts/0", "disconnected"},
		{"login gone", sessionCallbackData("sk:", 1, alice),
			both, []sshwatch.Session{bob}, "", sessionGoneToast},
		{"same tty new login", sessionCallbackData("sk:", 1, alice),
			both, []sshwatch.Session{aliceAgain, bob}, "", sessionGoneToast},
		{"ask after shift", sessionCallbackData("sk:", 2, bob),
			[]sshwatch.Session{bob}, nil, "", sessionGoneToast},
		{"bad fingerprint", "skk:1:zzzzzzzzzzzzzzzz",
			[]sshwatch.Session{alice}, nil, "", sessionGoneToast},
		{"legacy sk refreshes", "sk:1",
			[]sshwatch.Session{alice}, nil, "", "List refreshed"},
		{"legacy skk out of range", "skk:3",
			[]sshwatch.Session{alice}, nil, "", sessionGoneToast},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			live := tc.before
			a, send, runner := kickAgent(t, &live)
			ctx := context.Background()

			a.handleCallback(ctx, &telegram.Callback{ID: "c1", ChatID: 42, MessageID: 7, Data: tc.data})
			yes := tokenData(lastEditKB(send), tgui.ActYes)
			var feedback string
			if tc.after == nil {
				send.mu.Lock()
				feedback = send.answered[len(send.answered)-1]
				send.mu.Unlock()
				if yes != "" {
					t.Fatalf("%q offered a Yes", tc.data)
				}
			} else {
				live = tc.after
				a.handleCallback(ctx, &telegram.Callback{ID: "c2", ChatID: 42, MessageID: 7, Data: yes})
				feedback = slowOutcome(t, send, "c2")
			}
			var killed string
			if len(runner.calls) == 1 {
				killed = runner.calls[0][len(runner.calls[0])-1]
			} else if len(runner.calls) > 1 {
				t.Fatalf("runner calls = %v", runner.calls)
			}
			if killed != tc.wantKill {
				t.Errorf("killed %q, want %q", killed, tc.wantKill)
			}
			if !strings.Contains(feedback, tc.wantToast) {
				t.Errorf("feedback = %q, want %q", feedback, tc.wantToast)
			}
		})
	}
}

// TestSSHKickDoubleTap: the second Yes never signals the tty again (it
// may already belong to someone else).
func TestSSHKickDoubleTap(t *testing.T) {
	alice, bob := sshTestSessions()[0], sshTestSessions()[1]
	live := []sshwatch.Session{alice, bob}
	a, send, runner := kickAgent(t, &live)
	ctx := context.Background()

	a.handleCallback(ctx, &telegram.Callback{ID: "c0", ChatID: 42, MessageID: 7, Data: sessionCallbackData("sk:", 1, alice)})
	yes := tokenData(lastEditKB(send), tgui.ActYes)
	a.handleCallback(ctx, &telegram.Callback{ID: "c1", ChatID: 42, MessageID: 7, Data: yes})
	live = []sshwatch.Session{bob} // alice is gone; bob moves to index 1
	a.handleCallback(ctx, &telegram.Callback{ID: "c2", ChatID: 42, MessageID: 7, Data: yes})

	if len(runner.calls) != 1 || strings.Join(runner.calls[0], " ") != "pkill -KILL -t pts/0" {
		t.Fatalf("runner calls = %v", runner.calls)
	}
	send.mu.Lock()
	defer send.mu.Unlock()
	if got := send.answered[len(send.answered)-1]; got != "c2:"+doneToast {
		t.Errorf("second tap answered %q", got)
	}
}

func TestParseSessionData(t *testing.T) {
	cases := []struct {
		in     string
		n      int
		fp     string
		wantOK bool
	}{
		{"1:0123456789abcdef", 1, "0123456789abcdef", true},
		{"3", 3, "", true},
		{"0", 0, "", false},
		{"-1", 0, "", false},
		{"x:0123456789abcdef", 0, "", false},
		{"1:0123456789ABCDEF", 0, "", false},
		{"1:abc", 0, "", false},
		{"1:", 0, "", false},
	}
	for _, tc := range cases {
		n, fp, ok := parseSessionData(tc.in)
		if n != tc.n || fp != tc.fp || ok != tc.wantOK {
			t.Errorf("parseSessionData(%q) = %d,%q,%v want %d,%q,%v", tc.in, n, fp, ok, tc.n, tc.fp, tc.wantOK)
		}
	}
}

// failingKick mimics pkill matching a process it is not allowed to signal.
type failingKick struct{}

func (failingKick) Run(_ context.Context, _ string, _ ...string) (string, error) {
	return "pkill: killing pid 4242 failed: Operation not permitted", errors.New("exit status 1")
}

func TestSSHKickFailureIsVisible(t *testing.T) {
	send := &fakeSender{}
	a := testAgent(send)
	a.src.Runner = failingKick{}
	a.src.Sessions = func() ([]sshwatch.Session, error) { return sshTestSessions()[:1], nil }
	ctx := context.Background()

	a.handleCallback(ctx, &telegram.Callback{ID: "c0", ChatID: 42, MessageID: 4, Data: "ssh"})
	id := confirmThrough(t, a, send, sessionCallbackData("sk:", 1, sshTestSessions()[0]), 4)

	last := send.lastEdit()
	if !strings.Contains(last.html, "Disconnect failed") || !strings.Contains(last.html, "Operation not permitted") {
		t.Errorf("failure must be shown persistently in the message, got: %q", last.html)
	}
	if !strings.Contains(last.html, "lacks permission") {
		t.Errorf("permission failure must include the hint, got: %q", last.html)
	}
	if out := slowOutcome(t, send, id); strings.Contains(out, failedToast) || !strings.Contains(out, " · failed\n") {
		t.Errorf("failure toast echoed, or no failed receipt: %q", out)
	}
}

// goneKick mimics pkill exit 1 with no output: nothing matched the tty.
type goneKick struct{}

func (goneKick) Run(_ context.Context, _ string, _ ...string) (string, error) {
	return "", errors.New("exit status 1")
}

func TestSSHKickAlreadyGone(t *testing.T) {
	send := &fakeSender{}
	a := testAgent(send)
	a.src.Runner = goneKick{}
	a.src.Sessions = func() ([]sshwatch.Session, error) { return sshTestSessions()[:1], nil }
	ctx := context.Background()

	a.handleCallback(ctx, &telegram.Callback{ID: "c0", ChatID: 42, MessageID: 4, Data: "ssh"})
	id := confirmThrough(t, a, send, sessionCallbackData("sk:", 1, sshTestSessions()[0]), 4)

	if last := send.lastEdit(); strings.Contains(last.html, "Disconnect failed") {
		t.Errorf("vanished session is not a failure: %q", last.html)
	}
	if out := slowOutcome(t, send, id); !strings.Contains(out, "already gone") {
		t.Errorf("kick outcome = %q", out)
	}
}

func TestValidTTY(t *testing.T) {
	cases := map[string]bool{
		"pts/3":     true,
		"tty1":      true,
		"":          false,
		"-t":        false,
		"pts/3; rm": false,
	}
	for tty, want := range cases {
		if got := validTTY(tty); got != want {
			t.Errorf("validTTY(%q) = %v, want %v", tty, got, want)
		}
	}
}

// systemSustainN is how many samples the CPU and memory rules need at a's
// configured interval.
func systemSustainN(a *Agent) int {
	return sustainSamples(systemSustain, a.cfg.SampleInterval.Duration)
}

// evalSustained feeds the same snapshot through evalSystem for a full sustain
// window, one sample interval apart, and returns the last evaluation.
func evalSustained(a *Agent, s collect.Snapshot, now time.Time) []*alert.Alert {
	var out []*alert.Alert
	for i := range systemSustainN(a) {
		out = a.evalSystem(s, now.Add(time.Duration(i)*a.cfg.SampleInterval.Duration))
	}
	return out
}

// keyed returns the alert for key from one evaluation, or nil.
func keyed(als []*alert.Alert, key string) *alert.Alert {
	for _, al := range als {
		if al != nil && al.Key == key {
			return al
		}
	}
	return nil
}

func cpuSnap(pct float64) collect.Snapshot {
	return collect.Snapshot{CPUTotal: collect.CPUUsage{Percent: pct}, Mem: procfs.MemInfo{Total: 100, Available: 60}}
}

func memSnap(usedPct float64) collect.Snapshot {
	return collect.Snapshot{Mem: procfs.MemInfo{Total: 100, Available: uint64(100 - usedPct)}}
}

func TestSustainSamples(t *testing.T) {
	cases := []struct {
		d, interval time.Duration
		want        int
	}{
		{time.Minute, 15 * time.Second, 4},
		{time.Minute, 5 * time.Second, 12},
		{time.Minute, time.Second, 60},
		{time.Minute, 45 * time.Second, 2},
		{time.Minute, 2 * time.Minute, 1},
		{time.Minute, 0, 1},
		{0, 15 * time.Second, 1},
	}
	for _, c := range cases {
		if got := sustainSamples(c.d, c.interval); got != c.want {
			t.Errorf("sustainSamples(%s, %s) = %d, want %d", c.d, c.interval, got, c.want)
		}
	}
}

// TestCPUBurstIsSilent replays the #66 timeline: a backup pegs the CPU for
// one sample, then for one sample short of the window. Neither may push an
// alert or a recovery notice.
func TestCPUBurstIsSilent(t *testing.T) {
	a := testAgent(&fakeSender{})
	step := a.cfg.SampleInterval.Duration
	now := time.Now()
	tick := func(pct float64) {
		t.Helper()
		if als := a.evalSystem(cpuSnap(pct), now); countNonNil(als) != 0 {
			t.Fatalf("%.0f%% at %s pushed: %+v", pct, now.Format(time.TimeOnly), als)
		}
		now = now.Add(step)
	}

	tick(12)
	tick(97)
	tick(18)
	for range systemSustainN(a) - 1 {
		tick(97)
	}
	tick(18)
	if a.engine.Active("cpu") {
		t.Fatal("a burst shorter than the sustain window must not leave cpu active")
	}
}

func TestCPUSustainedFiresOnce(t *testing.T) {
	a := testAgent(&fakeSender{})
	step := a.cfg.SampleInterval.Duration
	now := time.Now()
	n := systemSustainN(a)

	for i := 1; i <= n; i++ {
		al := keyed(a.evalSystem(cpuSnap(97), now), "cpu")
		now = now.Add(step)
		if i < n && al != nil {
			t.Fatalf("sample %d/%d fired early: %+v", i, n, al)
		}
		if i == n && (al == nil || al.Resolved) {
			t.Fatalf("sample %d/%d must fire: %+v", i, n, al)
		}
	}
	// Still hot: hysteresis keeps it to one message.
	for range 3 {
		if al := keyed(a.evalSystem(cpuSnap(97), now), "cpu"); al != nil {
			t.Fatalf("held violation re-fired: %+v", al)
		}
		now = now.Add(step)
	}
	// Recovery is immediate — no sustain on the way down.
	rec := keyed(a.evalSystem(cpuSnap(20), now), "cpu")
	if rec == nil || !rec.Resolved {
		t.Fatalf("recovery expected on first cool sample: %+v", rec)
	}
}

func TestMemSustained(t *testing.T) {
	a := testAgent(&fakeSender{})
	step := a.cfg.SampleInterval.Duration
	now := time.Now()
	n := systemSustainN(a)

	// A build that briefly eats memory stays quiet.
	for range n - 1 {
		if al := keyed(a.evalSystem(memSnap(95), now), "mem"); al != nil {
			t.Fatalf("memory burst fired: %+v", al)
		}
		now = now.Add(step)
	}
	if al := keyed(a.evalSystem(memSnap(40), now), "mem"); al != nil {
		t.Fatalf("memory recovery without a fire pushed: %+v", al)
	}
	now = now.Add(step)

	// Held for the full window, it fires on the last sample.
	var al *alert.Alert
	for range n {
		al = keyed(a.evalSystem(memSnap(95), now), "mem")
		now = now.Add(step)
	}
	if al == nil || al.Resolved {
		t.Fatalf("sustained memory pressure must fire: %+v", al)
	}
}

func TestSustainScalesWithInterval(t *testing.T) {
	a := testAgent(&fakeSender{})
	a.cfg.SampleInterval = config.Duration{Duration: 15 * time.Second}
	now := time.Now()

	for i := 1; i <= 3; i++ {
		if al := keyed(a.evalSystem(cpuSnap(97), now), "cpu"); al != nil {
			t.Fatalf("sample %d at 15s fired before a minute: %+v", i, al)
		}
		now = now.Add(15 * time.Second)
	}
	if al := keyed(a.evalSystem(cpuSnap(97), now), "cpu"); al == nil {
		t.Fatal("4th sample at 15s (a full minute) must fire")
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
