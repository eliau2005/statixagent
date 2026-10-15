package agent

import (
	"bytes"
	"context"
	"log"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/eliau2005/statixagent/internal/bot"
	"github.com/eliau2005/statixagent/internal/telegram"
)

// fakeUpdates mimics Telegram's queue: getUpdates returns every pending
// update at or past offset and drops (confirms) those below it. A long
// poll that finds nothing cancels the test's context, ending botLoop.
type fakeUpdates struct {
	mu       sync.Mutex
	pending  []telegram.Update
	polls    []int64 // offsets of long polls
	confirms []int64 // offsets of zero-timeout confirm calls
	cancel   context.CancelFunc
}

func (f *fakeUpdates) GetUpdates(ctx context.Context, offset int64, timeout time.Duration) ([]telegram.Update, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if timeout == 0 {
		f.confirms = append(f.confirms, offset)
	} else {
		f.polls = append(f.polls, offset)
	}
	var out []telegram.Update
	for _, u := range f.pending {
		if u.ID >= offset {
			out = append(out, u)
		}
	}
	f.pending = out
	if len(out) == 0 && timeout > 0 {
		f.cancel()
		return nil, context.Canceled
	}
	return out, nil
}

// replayAgent builds a test agent polling fu, with the cursor saved at path.
func replayAgent(send *fakeSender, fu *fakeUpdates, path string) *Agent {
	src := testAgent(send).src
	src.OffsetPath = path
	return New(testConfig(), send, fu, src)
}

// countHandler registers a state-changing test command and returns its
// run counter.
func countHandler(a *Agent, cmd string) *int {
	n := new(int)
	a.router.Handle(cmd, bot.Text(func(context.Context, []string) string {
		*n++
		return "done"
	}))
	return n
}

func runBotLoop(a *Agent, fu *fakeUpdates) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	fu.cancel = cancel
	safely("bot", func() { a.botLoop(ctx) })
}

func TestBotLoopPanicDoesNotReplay(t *testing.T) {
	send := &fakeSender{}
	fu := &fakeUpdates{pending: []telegram.Update{
		{ID: 10, ChatID: 42, Text: "/boom"},
		{ID: 11, ChatID: 42, Text: "/act"},
	}}
	a := replayAgent(send, fu, filepath.Join(t.TempDir(), "tg-offset"))
	booms := 0
	a.router.Handle("boom", bot.Text(func(context.Context, []string) string {
		booms++
		panic("poison update")
	}))
	acts := countHandler(a, "act")

	// Run restarts the loop after a panic; do the same by hand.
	log.SetOutput(&bytes.Buffer{})
	t.Cleanup(func() { log.SetOutput(os.Stderr) })
	runBotLoop(a, fu)
	runBotLoop(a, fu)

	if booms != 1 {
		t.Errorf("poison update ran %d times, want 1", booms)
	}
	if *acts != 1 {
		t.Errorf("update after the poison one ran %d times, want 1", *acts)
	}
	if fu.polls[1] != 11 {
		t.Errorf("restarted loop polled from %d, want 11 (polls %v)", fu.polls[1], fu.polls)
	}
}

func TestRestartWithSavedOffsetDoesNotReplay(t *testing.T) {
	path := filepath.Join(t.TempDir(), "tg-offset")
	batch := []telegram.Update{{ID: 5, ChatID: 42, Text: "/act"}}

	send := &fakeSender{}
	fu := &fakeUpdates{pending: batch}
	a := replayAgent(send, fu, path)
	acts := countHandler(a, "act")
	runBotLoop(a, fu)
	if *acts != 1 {
		t.Fatalf("act ran %d times, want 1", *acts)
	}
	if data, err := os.ReadFile(path); err != nil || strings.TrimSpace(string(data)) != "6" {
		t.Fatalf("saved offset = %q, %v; want 6", data, err)
	}

	// The process died before the next poll confirmed update 5, so
	// Telegram hands it to the new process again.
	fu2 := &fakeUpdates{pending: batch}
	b := replayAgent(&fakeSender{}, fu2, path)
	acts2 := countHandler(b, "act")
	runBotLoop(b, fu2)
	if *acts2 != 0 {
		t.Errorf("act replayed after restart (%d runs)", *acts2)
	}
	if fu2.polls[0] != 6 {
		t.Errorf("first poll after restart from %d, want 6", fu2.polls[0])
	}
}

func TestOffsetSavedBeforeStateChange(t *testing.T) {
	cases := []struct {
		name string
		u    telegram.Update
		save bool
	}{
		{"view command", telegram.Update{ID: 3, ChatID: 42, Text: "/status"}, false},
		{"plain text", telegram.Update{ID: 3, ChatID: 42, Text: "hello"}, false},
		{"foreign chat", telegram.Update{ID: 3, ChatID: 7, Text: "/act"}, false},
		{"state change", telegram.Update{ID: 3, ChatID: 42, Text: "/act"}, true},
		{"button press", telegram.Update{ID: 3, ChatID: 42, Callback: &telegram.Callback{ID: "c", ChatID: 42, MessageID: 1, Data: "status"}}, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "tg-offset")
			a := replayAgent(&fakeSender{}, &fakeUpdates{}, path)
			saved := ""
			a.router.Handle("act", bot.Text(func(context.Context, []string) string {
				data, _ := os.ReadFile(path)
				saved = string(data)
				return "done"
			}))
			a.offset = tc.u.ID + 1
			a.handleUpdate(context.Background(), tc.u)
			data, err := os.ReadFile(path)
			if got := err == nil; got != tc.save {
				t.Fatalf("offset saved = %v, want %v", got, tc.save)
			}
			if tc.save && strings.TrimSpace(string(data)) != "4" {
				t.Errorf("saved offset = %q, want 4", data)
			}
			if tc.u.Text == "/act" && tc.save && strings.TrimSpace(saved) != "4" {
				t.Errorf("offset on disk while the command ran = %q, want 4", saved)
			}
		})
	}
}

func TestOffsetConfirmedWithTelegramWithoutPath(t *testing.T) {
	fu := &fakeUpdates{}
	a := replayAgent(&fakeSender{}, fu, "")
	countHandler(a, "act")
	a.offset = 9
	a.handleUpdate(context.Background(), telegram.Update{ID: 8, ChatID: 42, Text: "/act"})
	if len(fu.confirms) != 1 || fu.confirms[0] != 9 {
		t.Errorf("confirm calls = %v, want [9]", fu.confirms)
	}
	a.handleUpdate(context.Background(), telegram.Update{ID: 9, ChatID: 42, Text: "/status"})
	if len(fu.confirms) != 1 {
		t.Errorf("a view must not confirm: %v", fu.confirms)
	}
}

func TestQueuedCommandDateGate(t *testing.T) {
	boot := time.Now()
	cases := []struct {
		name string
		text string
		date time.Time
		runs bool
	}{
		{"queued state change", "/act", boot.Add(-2 * time.Minute), false},
		{"queued with bot suffix", "/act@my_bot", boot.Add(-time.Hour), false},
		{"within grace", "/act", boot.Add(-10 * time.Second), true},
		{"after boot", "/act", boot.Add(time.Minute), true},
		{"no date", "/act", time.Time{}, true},
		{"queued view", "/status", boot.Add(-time.Hour), true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			send := &fakeSender{}
			a := replayAgent(send, &fakeUpdates{}, filepath.Join(t.TempDir(), "tg-offset"))
			a.boot = boot
			acts := countHandler(a, "act")
			a.handleUpdate(context.Background(), telegram.Update{ID: 1, ChatID: 42, Text: tc.text, Date: tc.date})
			if tc.text == "/act" || tc.text == "/act@my_bot" {
				if ran := *acts == 1; ran != tc.runs {
					t.Errorf("ran = %v, want %v", ran, tc.runs)
				}
			}
			refused := send.find("was not run")
			if refused == tc.runs {
				t.Errorf("refusal notice = %v, want %v: %v", refused, !tc.runs, send.all())
			}
			if !tc.runs && !send.find("<code>/act</code>") {
				t.Errorf("notice must name the command: %v", send.all())
			}
		})
	}
}

func TestIsView(t *testing.T) {
	cases := []struct {
		text string
		view bool
	}{
		{"/status", true},
		{"/ssh history", true},
		{"/ssl", true},
		{"/http", true},
		{"/update", true},
		{"/firewall", true},
		{"/services_scan", true},
		{"/ssl add example.com", false},
		{"/http remove 1", false},
		{"/update confirm", false},
		{"/update_confirm", false},
		{"/clear_chat", false},
		{"/trust 203.0.113.7", false},
		{"/untrust 203.0.113.7", false},
		{"/services_add nginx", false},
		{"/services_remove 1", false},
		{"/ports_add 443", false},
		{"/ports_remove 443", false},
		{"/procs_add redis", false},
		{"/procs_remove redis", false},
		{"/nope", false},
	}
	for _, tc := range cases {
		fields := strings.Fields(strings.TrimPrefix(tc.text, "/"))
		if got := isView(fields[0], fields[1:]); got != tc.view {
			t.Errorf("isView(%q) = %v, want %v", tc.text, got, tc.view)
		}
	}
}

// Every registered command must be classified on purpose: views are
// listed in viewCommands (or isView), everything else must be a known
// state change, so a new handler cannot slip in as a view by accident.
func TestEveryCommandClassified(t *testing.T) {
	stateChanging := map[string]bool{
		"update_confirm": true, "clear_chat": true, "trust": true, "untrust": true,
		"services_add": true, "services_remove": true, "ports_add": true,
		"ports_remove": true, "procs_add": true, "procs_remove": true,
		"ssl": true, "http": true, "update": true, // views only without arguments
	}
	for _, cmd := range testAgent(&fakeSender{}).router.Commands() {
		if viewCommands[cmd] == stateChanging[cmd] {
			t.Errorf("/%s: view=%v, stateChanging=%v; classify it exactly once", cmd, viewCommands[cmd], stateChanging[cmd])
		}
	}
}

func TestLoadOffset(t *testing.T) {
	dir := t.TempDir()
	write := func(name, data string, age time.Duration) string {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, []byte(data), 0o600); err != nil {
			t.Fatal(err)
		}
		mt := time.Now().Add(-age)
		if err := os.Chtimes(p, mt, mt); err != nil {
			t.Fatal(err)
		}
		return p
	}
	cases := []struct {
		name string
		path string
		want int64
		logs bool
	}{
		{"no path", "", 0, false},
		{"missing", filepath.Join(dir, "absent"), 0, false},
		{"valid", write("ok", "1234\n", time.Minute), 1234, false},
		{"stale", write("stale", "1234\n", 25*time.Hour), 0, false},
		{"corrupt", write("corrupt", "12x4", time.Minute), 0, true},
		{"negative", write("negative", "-5", time.Minute), 0, true},
		{"empty", write("empty", "", time.Minute), 0, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var buf bytes.Buffer
			log.SetOutput(&buf)
			t.Cleanup(func() { log.SetOutput(os.Stderr) })
			if got := loadOffset(tc.path); got != tc.want {
				t.Errorf("loadOffset = %d, want %d", got, tc.want)
			}
			if logged := strings.Contains(buf.String(), "update offset"); logged != tc.logs {
				t.Errorf("logged = %v, want %v: %q", logged, tc.logs, buf.String())
			}
		})
	}
}
