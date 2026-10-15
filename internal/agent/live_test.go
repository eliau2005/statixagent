package agent

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/eliau2005/statixagent/internal/telegram"
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
	a.startLive(ctx, 42, 7)
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
	a.startLive(context.Background(), 42, 7)
	waitFor(t, func() bool { return len(send.callTimes()) >= 2 }, "the failing frame")

	// No more frames and no restore edit: the message no longer exists.
	time.Sleep(50 * time.Millisecond)
	if n := len(send.callTimes()); n != 2 {
		t.Errorf("edits after the message was gone: %d calls, want 2", n)
	}
}
