package agent

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/eliau2005/statixagent/internal/collect"
	"github.com/eliau2005/statixagent/internal/telegram"
)

// telegramTags are the tags Telegram's HTML parse mode accepts.
var telegramTags = map[string]bool{
	"b": true, "strong": true, "i": true, "em": true, "u": true, "ins": true,
	"s": true, "strike": true, "del": true, "a": true, "code": true, "pre": true,
	"span": true, "tg-spoiler": true, "tg-emoji": true, "blockquote": true,
}

var htmlEntity = regexp.MustCompile(`^&(lt|gt|amp|quot|#[0-9]+|#x[0-9a-fA-F]+);`)

// checkTelegramHTML mirrors the parse errors Telegram answers with ("can't
// parse entities"): unknown or unbalanced tags and bare & < > characters.
// Such a reply is rejected outright and the user gets nothing.
func checkTelegramHTML(s string) error {
	var open []string
	for i := 0; i < len(s); i++ {
		switch s[i] {
		case '&':
			if !htmlEntity.MatchString(s[i:]) {
				return fmt.Errorf("bare & at %d", i)
			}
		case '>':
			return fmt.Errorf("bare > at %d", i)
		case '<':
			end := strings.IndexByte(s[i:], '>')
			if end < 0 {
				return fmt.Errorf("unterminated tag at %d", i)
			}
			tag := s[i+1 : i+end]
			closing := strings.HasPrefix(tag, "/")
			name, _, _ := strings.Cut(strings.TrimPrefix(tag, "/"), " ")
			if !telegramTags[name] {
				return fmt.Errorf("unsupported tag <%s> at %d", tag, i)
			}
			if closing {
				if len(open) == 0 || open[len(open)-1] != name {
					return fmt.Errorf("unbalanced </%s> at %d", name, i)
				}
				open = open[:len(open)-1]
			} else {
				open = append(open, name)
			}
			i += end
		}
	}
	if len(open) > 0 {
		return fmt.Errorf("unclosed tags %v", open)
	}
	return nil
}

func TestCheckTelegramHTML(t *testing.T) {
	for _, tc := range []struct {
		in string
		ok bool
	}{
		{"<b>x</b> &lt;host&gt; &amp; &#39;", true},
		{"<a href=\"https://x\">x</a>", true},
		{"Usage: /ssl add <host[:port]>", false},
		{"a & b", false},
		{"<b>x", false},
		{"<b><i>x</b></i>", false},
		{"x > y", false},
	} {
		if err := checkTelegramHTML(tc.in); (err == nil) != tc.ok {
			t.Errorf("checkTelegramHTML(%q) = %v, want ok=%v", tc.in, err, tc.ok)
		}
	}
}

// hostileErr carries every character that breaks Telegram HTML.
var hostileErr = errors.New(`exec "<ufw>": a & b > c`)

// clearFailSender fails the calls /clear_chat makes.
type clearFailSender struct {
	*fakeSender
	failSend, failDelete bool
}

func (f *clearFailSender) SendMessageID(ctx context.Context, chatID int64, html string) (int64, error) {
	if f.failSend {
		return 0, hostileErr
	}
	return f.fakeSender.SendMessageID(ctx, chatID, html)
}

func (f *clearFailSender) DeleteMessages(ctx context.Context, chatID int64, ids []int64) error {
	if f.failDelete {
		return hostileErr
	}
	return f.fakeSender.DeleteMessages(ctx, chatID, ids)
}

// TestUsageAndErrorRepliesAreValidHTML runs each handler down its usage and
// error paths: every reply must parse, or Telegram drops it silently.
func TestUsageAndErrorRepliesAreValidHTML(t *testing.T) {
	for _, tc := range []struct {
		name  string
		text  string
		setup func(*Agent)
		want  string
	}{
		{name: "ssl usage", text: "/ssl add", want: "Usage: /ssl add"},
		{name: "ssl bad verb", text: "/ssl drop x.example", want: "Usage: /ssl add"},
		{name: "ssl add host", text: "/ssl add <x>&y", want: "Watching"},
		{name: "http usage", text: "/http add", want: "Usage: /http"},
		{name: "ping usage", text: "/ping", setup: func(a *Agent) {
			a.src.Latency = func(context.Context, string) (time.Duration, error) { return 0, nil }
		}, want: "Usage: /ping"},
		{name: "ping error", text: "/ping x.example", setup: func(a *Agent) {
			a.src.Latency = func(context.Context, string) (time.Duration, error) { return 0, hostileErr }
		}, want: "unreachable"},
		{name: "services_add usage", text: "/services_add", want: "Usage: /services_add"},
		{name: "services_remove usage", text: "/services_remove", want: "Usage: /services_remove"},
		{name: "ports_add usage", text: "/ports_add", want: "Usage: /ports_add"},
		{name: "ports_add bad port", text: "/ports_add <x>", want: "is not a port"},
		{name: "ports_remove usage", text: "/ports_remove", want: "Usage: /ports_remove"},
		{name: "procs_add usage", text: "/procs_add", want: "Usage: /procs_add"},
		{name: "procs_remove usage", text: "/procs_remove", want: "Usage: /procs_remove"},
		{name: "trust usage", text: "/trust", want: "Usage: /trust"},
		{name: "trust bad ip", text: "/trust <x>", want: "❌"},
		{name: "untrust usage", text: "/untrust", want: "Usage: /untrust"},
		{name: "top error", text: "/top", setup: func(a *Agent) {
			a.src.TopProcs = func(context.Context) ([]collect.Proc, error) { return nil, hostileErr }
		}, want: "Could not read processes"},
		{name: "update check error", text: "/update", setup: func(a *Agent) {
			a.src.UpdateCheck = func(context.Context) (string, bool, error) { return "", false, hostileErr }
		}, want: "Update check failed"},
		{name: "update offer version", text: "/update", setup: func(a *Agent) {
			a.src.UpdateCheck = func(context.Context) (string, bool, error) { return "v1<2>&", true, nil }
		}, want: "New version available"},
		{name: "update current version", text: "/update", setup: func(a *Agent) {
			a.src.UpdateCheck = func(context.Context) (string, bool, error) { return "v1<2>&", false, nil }
		}, want: "Already up to date"},
		{name: "update confirm prompt", text: "/update_confirm", setup: func(a *Agent) {
			a.src.UpdateCheck = func(context.Context) (string, bool, error) { return "v2", true, nil }
			a.src.UpdateApply = func(context.Context) error { return hostileErr }
		}, want: "Install the update?"},
		{name: "clear chat prompt", text: "/clear_chat", want: "Delete recent messages?"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			a := testAgent(&fakeSender{})
			if tc.setup != nil {
				tc.setup(a)
			}
			reply := dispatchText(t, a, tc.text)
			if !strings.Contains(reply, tc.want) {
				t.Errorf("reply = %q, want it to contain %q", reply, tc.want)
			}
			if err := checkTelegramHTML(reply); err != nil {
				t.Errorf("reply %q is not valid Telegram HTML: %v", reply, err)
			}
		})
	}
}

// TestConfirmedErrorsAreValidHTML presses Yes on the update and clear-chat
// prompts down their error paths: the outcome must parse as HTML.
func TestConfirmedErrorsAreValidHTML(t *testing.T) {
	for _, tc := range []struct {
		name                 string
		data                 string
		failSend, failDelete bool
		want                 string
	}{
		{"update apply fails", cbUpdateYes, false, false, "Update failed"},
		{"anchor send fails", cbClearYes, true, false, "Could not clear"},
		{"delete fails", cbClearYes, false, true, "Could not clear"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			send := &clearFailSender{fakeSender: &fakeSender{}, failSend: tc.failSend, failDelete: tc.failDelete}
			a := New(testConfig(), send, nil, testAgent(send.fakeSender).src)
			a.src.UpdateCheck = func(context.Context) (string, bool, error) { return "v2", true, nil }
			a.src.UpdateApply = func(context.Context) error { return hostileErr }
			confirmThrough(t, a, send.fakeSender, tc.data, 5) // the legacy Yes asks again
			var out string
			if tc.data == cbClearYes {
				// The clear outcome is a new message: the prompt is gone.
				sent := send.all()
				out = sent[len(sent)-1]
			} else {
				out = send.lastEdit().html
			}
			if !strings.Contains(out, tc.want) {
				t.Errorf("outcome = %q, want it to contain %q", out, tc.want)
			}
			if err := checkTelegramHTML(out); err != nil {
				t.Errorf("outcome %q is not valid Telegram HTML: %v", out, err)
			}
		})
	}
}

// TestThresholdCallbackRejectsForgedDelta covers forged th: data: only the
// keyboard's ±5 steps may change a threshold.
func TestThresholdCallbackRejectsForgedDelta(t *testing.T) {
	for _, tc := range []struct {
		data  string
		want  float64
		toast string
	}{
		{"th:cpu:-5", 85, "CPU → 85%"},
		{"th:cpu:+5", 95, "CPU → 95%"},
		{"th:cpu:5", 95, "CPU → 95%"},
		{"th:cpu:NaN", 90, "bad action"},
		{"th:cpu:nan", 90, "bad action"},
		{"th:cpu:Inf", 90, "bad action"},
		{"th:cpu:-Inf", 90, "bad action"},
		{"th:cpu:+50", 90, "bad action"},
		{"th:cpu:-1", 90, "bad action"},
		{"th:cpu:0", 90, "bad action"},
		{"th:cpu:", 90, "bad action"},
	} {
		t.Run(tc.data, func(t *testing.T) {
			send := &fakeSender{}
			a := testAgent(send)
			a.handleCallback(context.Background(), &telegram.Callback{ID: "c", ChatID: 42, MessageID: 4, Data: tc.data})
			if got := a.thresholds().CPUPercent; got != tc.want {
				t.Errorf("cpu threshold = %v, want %v", got, tc.want)
			}
			send.mu.Lock()
			defer send.mu.Unlock()
			if len(send.answered) != 1 || !strings.HasPrefix(send.answered[0], "c:"+tc.toast) {
				t.Errorf("answered = %v, want toast %q", send.answered, tc.toast)
			}
		})
	}
}

// TestLiveStopWithoutSession: a Stop button that outlived its session (agent
// restart) must restore Home with its keyboard, not stay stuck.
func TestLiveStopWithoutSession(t *testing.T) {
	send := &fakeSender{}
	a := testAgent(send)
	a.sampleOnce(context.Background())

	a.handleCallback(context.Background(), &telegram.Callback{ID: "c", ChatID: 42, MessageID: 11, Data: "live_stop"})

	send.mu.Lock()
	defer send.mu.Unlock()
	if len(send.answered) != 1 || send.answered[0] != "c:" {
		t.Errorf("answered = %v", send.answered)
	}
	if len(send.edits) != 1 {
		t.Fatalf("want one restore edit, got %+v", send.edits)
	}
	e := send.edits[0]
	if e.messageID != 11 || strings.Contains(e.html, "LIVE") || !strings.Contains(e.html, "testhost") {
		t.Errorf("restore edit = %+v", e)
	}
	if e.kb == nil || e.kb[len(e.kb)-1][1].Data != "~1v|home" {
		t.Errorf("restore edit must carry the Home keyboard: %+v", e.kb)
	}
}

// TestLiveStopOtherMessage: a stale Stop on another message restores that
// message and leaves the running session alone.
func TestLiveStopOtherMessage(t *testing.T) {
	send := &fakeSender{}
	a := testAgent(send)
	a.liveInterval = 5 * time.Millisecond
	a.liveDuration = time.Hour
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	a.startLive(ctx, 42, 7)
	waitFor(t, func() bool { return send.editCount() >= 1 }, "live frame")
	a.handleCallback(ctx, &telegram.Callback{ID: "c", ChatID: 42, MessageID: 8, Data: "live_stop"})

	a.mu.Lock()
	running := a.liveCancel != nil && a.liveMsg == 7
	a.mu.Unlock()
	if !running {
		t.Error("a Stop on another message must not end the running session")
	}
	send.mu.Lock()
	restored := false
	for _, e := range send.edits {
		if e.messageID == 8 && !strings.Contains(e.html, "LIVE") {
			restored = true
		}
	}
	send.mu.Unlock()
	if !restored {
		t.Error("the stale message must be restored to Status")
	}
	a.stopLive(7)
}

// TestLiveStopAfterSessionEnded: once a session hits its ceiling, a later
// Stop on that message still re-renders instead of doing nothing.
func TestLiveStopAfterSessionEnded(t *testing.T) {
	send := &fakeSender{}
	a := testAgent(send)
	a.liveInterval = 5 * time.Millisecond
	a.liveDuration = 20 * time.Millisecond

	a.startLive(context.Background(), 42, 7)
	waitFor(t, func() bool {
		a.mu.Lock()
		defer a.mu.Unlock()
		return a.liveCancel == nil
	}, "session to end")

	before := send.editCount()
	a.handleCallback(context.Background(), &telegram.Callback{ID: "c", ChatID: 42, MessageID: 7, Data: "live_stop"})
	if send.editCount() != before+1 {
		t.Fatalf("want a restore edit, edits %d -> %d", before, send.editCount())
	}
	if last := send.lastEdit(); last.messageID != 7 || strings.Contains(last.html, "LIVE") {
		t.Errorf("restore edit = %+v", last)
	}
}

// navRefresh returns the Refresh button's callback data.
func navRefresh(kb telegram.Keyboard) string {
	for _, row := range kb {
		for _, b := range row {
			if strings.HasPrefix(b.Text, "🔄") {
				return b.Data
			}
		}
	}
	return ""
}

// TestSSHEventViewsKeepKeyboard: History and Failed logins (old alert
// buttons and commands) open their screens, and Refresh re-runs the same
// screen.
func TestSSHEventViewsKeepKeyboard(t *testing.T) {
	for _, tc := range []struct {
		token, text, cmd, title, refresh string
	}{
		{"ssh_fails", "/ssh_fails", "ssh_fails", "Failed logins", "~1v|fai"},
		{"ssh_fails", "/ssh fails", "ssh", "Failed logins", "~1v|fai"},
		{"ssh_history", "/ssh_history", "ssh_history", "SSH history", "~1v|his"},
		{"ssh_history", "/ssh history", "ssh", "SSH history", "~1v|his"},
	} {
		t.Run(tc.text, func(t *testing.T) {
			send := &fakeSender{}
			a := testAgent(send)
			ctx := context.Background()
			a.handleAuthLine(ctx, "Failed password for root from 203.0.113.7 port 22 ssh2", time.Now())

			// Button press edits in place with the keyboard.
			a.handleCallback(ctx, &telegram.Callback{ID: "c", ChatID: 42, MessageID: 3, Data: tc.token})
			e := send.lastEdit()
			if e.messageID != 3 || !strings.Contains(e.html, tc.title) {
				t.Errorf("callback view = %+v", e)
			}
			if got := navRefresh(e.kb); got != tc.refresh {
				t.Errorf("callback Refresh = %q, want %q (kb %+v)", got, tc.refresh, e.kb)
			}

			// Typed command replies with the same keyboard.
			reply, cmd, _ := a.router.Dispatch(ctx, telegram.Update{ChatID: 42, Text: tc.text})
			if cmd != tc.cmd {
				t.Fatalf("cmd = %q, want %q", cmd, tc.cmd)
			}
			a.reply(ctx, cmd, reply)
			send.mu.Lock()
			kb := send.keyboards[len(send.keyboards)-1]
			send.mu.Unlock()
			if got := navRefresh(kb); got != tc.refresh {
				t.Errorf("command Refresh = %q, want %q (kb %+v)", got, tc.refresh, kb)
			}
		})
	}
}
