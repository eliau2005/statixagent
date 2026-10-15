package agent

import (
	"context"
	"fmt"
	"time"

	"github.com/eliau2005/statixagent/internal/bot"
	"github.com/eliau2005/statixagent/internal/telegram"
	"github.com/eliau2005/statixagent/internal/tgui"
)

// Live mode: pressing ▶️ Live re-renders the sampler-owned status snapshot in
// place on a short tick until the user taps ⏹ Stop (or a safety ceiling is
// reached). Rendering never collects or evaluates extra samples, so viewing
// the dashboard cannot change alert cadence or trend history. Only one live
// session runs at a time. A 429 pauses frames for the retry_after Telegram
// asked for, and a deleted message ends the session.

// spinnerFrames animate the live header, one frame per tick.
var spinnerFrames = []string{"◐", "◓", "◑", "◒"}

// liveKeyboard replaces the nav while a session runs.
func liveKeyboard() telegram.Keyboard {
	return telegram.Keyboard{{{Text: "⏹ Stop", Data: "live_stop"}}}
}

// startLive begins a session on the given message, canceling any previous
// one. It returns immediately; the ticking happens in a goroutine bound to
// the agent's context.
func (a *Agent) startLive(ctx context.Context, chatID, messageID int64) {
	a.mu.Lock()
	if a.liveCancel != nil {
		a.liveCancel()
	}
	liveCtx, cancel := context.WithCancel(ctx)
	a.liveCancel = cancel
	a.liveMsg = messageID
	a.liveSeq++
	seq := a.liveSeq
	interval, duration := a.liveInterval, a.liveDuration
	a.mu.Unlock()

	go func() {
		defer cancel()
		safely("live", func() {
			a.runLive(liveCtx, chatID, messageID, interval, duration)
		})
		// A session that hit its ceiling is over: a later Stop on that
		// message must take the no-session path instead of doing nothing.
		a.mu.Lock()
		if a.liveSeq == seq {
			a.liveCancel = nil
		}
		a.mu.Unlock()
	}()
}

// stopLive cancels the session running on messageID, reporting whether
// there was one; the session's own exit path then restores the view.
func (a *Agent) stopLive(messageID int64) bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.liveCancel == nil || a.liveMsg != messageID {
		return false
	}
	a.liveCancel()
	a.liveCancel = nil
	return true
}

func (a *Agent) runLive(ctx context.Context, chatID, messageID int64, interval, duration time.Duration) {
	start := time.Now()
	var deadline time.Time
	if duration > 0 {
		deadline = start.Add(duration)
	}
	tick := time.NewTicker(interval)
	defer tick.Stop()

	n := 0
	render := func() string {
		a.mu.Lock()
		body := bot.Status(a.src.Hostname, a.snap, a.thermal, a.power)
		a.mu.Unlock()
		elapsed := time.Since(start).Round(time.Second)
		header := fmt.Sprintf("%s 🔴 <b>LIVE</b> · %s\n", spinnerFrames[n%len(spinnerFrames)], bot.Dur(elapsed))
		n++
		return header + body
	}

	// pauseUntil holds frames back after a 429. frame reports false once
	// the message is gone: there is nothing left to edit or restore.
	var pauseUntil time.Time
	frame := func() bool {
		err := a.send.EditMessageKB(ctx, chatID, messageID, render(), liveKeyboard())
		if telegram.IsMessageNotFound(err) {
			return false
		}
		if wait, ok := telegram.RetryAfter(err); ok {
			pauseUntil = time.Now().Add(max(wait, interval))
		}
		return true
	}

	if !frame() {
		return
	}
	for {
		select {
		case <-ctx.Done():
			a.finishLive(chatID, messageID)
			return
		case <-tick.C:
			if !deadline.IsZero() && time.Now().After(deadline) {
				a.finishLive(chatID, messageID)
				return
			}
			if time.Now().Before(pauseUntil) {
				continue
			}
			if !frame() {
				return
			}
		}
	}
}

// finishLive restores Home in place, so a stopped session leaves no
// orphan state. It uses a fresh context: the live context is already
// canceled on the stop path.
func (a *Agent) finishLive(chatID, messageID int64) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	text, kb := a.screen(ctx, tgui.Open(scrHome))
	a.send.EditMessageKB(ctx, chatID, messageID, text, kb)
}
