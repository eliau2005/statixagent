package agent

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/eliau2005/statixagent/internal/telegram"
	"github.com/eliau2005/statixagent/internal/tgui"
)

// editErrSender fails selected edits: errFor(n) is the result of the n-th
// EditMessageKB call (from 1). Calls are timestamped for backoff checks.
type editErrSender struct {
	*fakeSender
	errFor func(n int) error

	mu    sync.Mutex
	calls []time.Time
}

func (s *editErrSender) EditMessageKB(ctx context.Context, chatID, messageID int64, html string, kb telegram.Keyboard) error {
	s.mu.Lock()
	s.calls = append(s.calls, time.Now())
	n := len(s.calls)
	s.mu.Unlock()
	if err := s.errFor(n); err != nil {
		return err
	}
	return s.fakeSender.EditMessageKB(ctx, chatID, messageID, html, kb)
}

func (s *editErrSender) callTimes() []time.Time {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]time.Time(nil), s.calls...)
}

func TestLiveIntervalDefault(t *testing.T) {
	a := New(testConfig(), &fakeSender{}, nil, Sources{Hostname: "h"})
	if a.liveInterval != 5*time.Second {
		t.Errorf("liveInterval = %v, want 5s", a.liveInterval)
	}
}

func TestLiveModeBacksOffOn429(t *testing.T) {
	const retryAfter = 150 * time.Millisecond
	send := &editErrSender{fakeSender: &fakeSender{}, errFor: func(n int) error {
		if n == 1 {
			return &telegram.APIError{Code: 429, Description: "Too Many Requests: retry after 1", RetryAfter: retryAfter}
		}
		return nil
	}}
	a := testAgent(send.fakeSender)
	a.send = send
	a.liveInterval = 5 * time.Millisecond
	a.liveDuration = time.Hour
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	a.startLive(ctx, 42, 7, "")
	waitFor(t, func() bool { return len(send.callTimes()) >= 2 }, "a frame after the 429")
	cancel()

	calls := send.callTimes()
	if gap := calls[1].Sub(calls[0]); gap < retryAfter {
		t.Errorf("next frame %v after a 429, want at least retry_after %v", gap, retryAfter)
	}
}

func TestLiveModeStopsWhenMessageGone(t *testing.T) {
	gone := &telegram.APIError{Code: 400, Description: "Bad Request: message to edit not found"}
	send := &editErrSender{fakeSender: &fakeSender{}, errFor: func(n int) error {
		if n >= 2 {
			return gone
		}
		return nil
	}}
	a := testAgent(send.fakeSender)
	a.send = send
	a.liveInterval = 5 * time.Millisecond
	a.liveDuration = time.Hour // would run forever without the stop
	a.startLive(context.Background(), 42, 7, "")
	waitFor(t, func() bool { return len(send.callTimes()) >= 2 }, "the failing frame")

	// No more frames and no restore edit: the message no longer exists.
	time.Sleep(50 * time.Millisecond)
	if n := len(send.callTimes()); n != 2 {
		t.Errorf("edits after the message was gone: %d calls, want 2", n)
	}
}

// pressOn presses data on message msg of the owner's private chat.
func pressOn(a *Agent, id string, msg int64, data string) {
	a.handleCallback(context.Background(), &telegram.Callback{
		ID: id, ChatID: 42, ChatType: "private", FromID: 42, MessageID: msg, Data: data,
	})
}

// editsOf returns the edits made to message msg so far.
func editsOf(send *fakeSender, msg int64) []edit {
	send.mu.Lock()
	defer send.mu.Unlock()
	var out []edit
	for _, e := range send.edits {
		if e.messageID == msg {
			out = append(out, e)
		}
	}
	return out
}

// showsScreen reports whether e shows screen id: its keyboard is the one
// the screen renders, which needs no clock.
func showsScreen(a *Agent, e edit, id string) bool {
	_, kb := a.screen(context.Background(), tgui.Open(id))
	return !strings.Contains(e.html, "LIVE") && fmt.Sprint(e.kb) == fmt.Sprint(kb)
}

// liveAgent is an agent whose Live sessions tick fast and never end on
// their own.
func liveAgent(t *testing.T) (*Agent, *fakeSender) {
	send := &fakeSender{}
	a := testAgent(send)
	a.liveInterval = 5 * time.Millisecond
	a.liveDuration = time.Hour
	t.Cleanup(func() {
		a.mu.Lock()
		s := a.live
		a.mu.Unlock()
		if s != nil {
			a.stopLive(s.chatID, s.messageID)
		}
	})
	return a, send
}

// TestLiveTwoMessages: starting Live on a second message stops the first
// session and puts its message back on the screen it came from.
func TestLiveTwoMessages(t *testing.T) {
	a, send := liveAgent(t)
	pressOn(a, "a", 7, "~1lv^set")
	waitFor(t, func() bool { return len(editsOf(send, 7)) >= 2 }, "frames on the first message")
	if kb := editsOf(send, 7)[0].kb; len(kb) != 1 || kb[0][0].Data != "~1ls^set" || kb[0][0].Text != "⏹ Stop live" {
		t.Errorf("live keyboard = %+v, want one Stop carrying From", kb)
	}
	pressOn(a, "b", 8, "~1lv")
	waitFor(t, func() bool { return len(editsOf(send, 8)) >= 3 }, "frames on the second message")

	first := editsOf(send, 7)
	if last := first[len(first)-1]; !showsScreen(a, last, scrSettings) {
		t.Errorf("first message ends on %+v, want Settings", last)
	}
	time.Sleep(30 * time.Millisecond)
	if n := len(editsOf(send, 7)); n != len(first) {
		t.Errorf("the stopped session edited its message %d more times", n-len(first))
	}
	a.mu.Lock()
	running := a.live != nil && a.live.messageID == 8
	a.mu.Unlock()
	if !running {
		t.Error("the second session is not the running one")
	}
}

// TestLiveNavPressStopsLive: any other press on the live message stops
// the session before its own view goes in, and no frame overwrites it.
func TestLiveNavPressStopsLive(t *testing.T) {
	for _, data := range []string{"~1v|cpu", "cpu"} {
		t.Run(data, func(t *testing.T) {
			a, send := liveAgent(t)
			pressOn(a, "live", 9, "~1lv")
			waitFor(t, func() bool { return len(editsOf(send, 9)) >= 2 }, "live frames")
			pressOn(a, "nav", 9, data)
			time.Sleep(30 * time.Millisecond)

			edits := editsOf(send, 9)
			if last := edits[len(edits)-1]; !showsScreen(a, last, scrCPU) {
				t.Errorf("message ends on %+v, want CPU", last)
			}
			a.mu.Lock()
			stopped := a.live == nil
			a.mu.Unlock()
			if !stopped {
				t.Error("the session still runs after a navigation press")
			}
		})
	}
}

// TestLiveStopReturnsToFrom: Stop shows the screen Live was started
// from, Home by default, with or without a running session; the legacy
// data still starts and stops a session.
func TestLiveStopReturnsToFrom(t *testing.T) {
	cases := []struct {
		name, start, stop, want string
	}{
		{"from settings", "~1lv^set", "~1ls", scrSettings},
		{"default home", "~1lv", "~1ls", scrHome},
		{"legacy", "live", "live_stop", scrHome},
		{"no session", "", "~1ls^set", scrSettings},
		{"legacy no session", "", "live_stop", scrHome},
		{"unknown from", "", "~1ls^zz", scrHome},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			a, send := liveAgent(t)
			if tc.start != "" {
				pressOn(a, "start", 5, tc.start)
				waitFor(t, func() bool { return len(editsOf(send, 5)) >= 2 }, "live frames")
			}
			pressOn(a, "stop", 5, tc.stop)
			time.Sleep(20 * time.Millisecond)

			edits := editsOf(send, 5)
			if len(edits) == 0 || !showsScreen(a, edits[len(edits)-1], tc.want) {
				t.Errorf("message ends on %+v, want %s", edits, tc.want)
			}
			send.mu.Lock()
			defer send.mu.Unlock()
			want := 1
			if tc.start != "" {
				want = 2
			}
			if len(send.answered) != want || send.answered[len(send.answered)-1] != "stop:" {
				t.Errorf("answered = %v, want each press once", send.answered)
			}
			if a.live != nil {
				t.Error("a session still runs after Stop")
			}
		})
	}
}
