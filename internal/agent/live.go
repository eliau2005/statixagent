package agent

import (
	"context"
	"fmt"
	"slices"
	"time"

	"github.com/eliau2005/statixagent/internal/bot"
	"github.com/eliau2005/statixagent/internal/telegram"
	"github.com/eliau2005/statixagent/internal/tgui"
)

// Live mode: pressing ▶️ Live re-renders the sampler-owned status snapshot in
// place on a short tick until the user taps ⏹ Stop (or a safety ceiling is
// reached). Rendering never collects or evaluates extra samples, so viewing
// the dashboard cannot change alert cadence or trend history. A 429 pauses
// frames for the retry_after Telegram asked for, and a deleted message ends
// the session.
//
// The session is the one writer of its message (docs/telegram-ux-redesign.md
// §4.3). Only one runs at a time: starting Live on another message stops
// the old session and puts its message back on the screen it came from.
// Any other press on the live message stops the session first and waits
// for its last frame, so the press's own edit is never overwritten.

// Live acts. Both carry the screen Stop returns to as From ("" for Home),
// so a Stop pressed after a restart still lands where the user came from.
// The legacy live and live_stop data keep working and return to Home.
const (
	actLive     = "lv"
	actLiveStop = "ls"
)

// spinnerFrames animate the live header, one frame per tick.
var spinnerFrames = []string{"◐", "◓", "◑", "◒"}

// liveSession is one running Live mode.
type liveSession struct {
	chatID, messageID int64
	from              string // screen Stop returns to; "" for Home
	cancel            context.CancelFunc
	done              chan struct{} // closed once the last frame is out
}

// liveKeyboard replaces the screen's buttons while a session runs.
func liveKeyboard(from string) telegram.Keyboard {
	return telegram.Keyboard{{{Text: "⏹ Stop live", Data: callData(tgui.Call{Act: actLiveStop, From: from})}}}
}

// livePress handles a press of a live act, already authorized.
func (a *Agent) livePress(ctx context.Context, cb *telegram.Callback, c tgui.Call) {
	if len(c.Args) != 0 {
		a.refuseCallback(ctx, cb, false)
		return
	}
	if c.Act == actLive {
		a.answer(ctx, cb, "Live mode active (tap Stop to exit)")
		a.startLive(ctx, cb.ChatID, cb.MessageID, c.From)
		return
	}
	a.stopLivePress(ctx, cb, c.From)
}

// stopLivePress ends the session on the pressed message and shows the
// screen it came from. With no session there (the agent restarted, or a
// newer session took over) it shows from, so Stop is never a dead end.
func (a *Agent) stopLivePress(ctx context.Context, cb *telegram.Callback, from string) {
	if s := a.stopLive(cb.ChatID, cb.MessageID); s != nil {
		from = s.from
	}
	text, kb := a.screen(ctx, a.liveBack(from))
	a.finishCallback(ctx, cb, false, text, kb, "")
}

// liveBack is the call that shows the screen a session returns to: from
// when it names a registered screen, else Home.
func (a *Agent) liveBack(from string) tgui.Call {
	if from != "" && slices.Contains(a.ui.Screens(), from) {
		return tgui.Open(from)
	}
	return tgui.Open(scrHome)
}

// startLive begins a session on the given message. A session already
// running is stopped first; when it was on another message, that message
// goes back to its screen. It returns once the new session is registered;
// the ticking happens in a goroutine bound to ctx.
func (a *Agent) startLive(ctx context.Context, chatID, messageID int64, from string) {
	liveCtx, cancel := context.WithCancel(ctx)
	s := &liveSession{chatID: chatID, messageID: messageID, from: from, cancel: cancel, done: make(chan struct{})}
	a.mu.Lock()
	old := a.live
	a.live = s
	interval, duration := a.liveInterval, a.liveDuration
	a.mu.Unlock()

	if old != nil {
		old.stop()
		if old.chatID != chatID || old.messageID != messageID {
			a.restoreLive(old)
		}
	}
	go func() {
		defer close(s.done)
		defer cancel()
		safely("live", func() { a.runLive(liveCtx, s, interval, duration) })
	}()
}

// stop cancels the session and waits for its goroutine to finish, so no
// frame of it can land after the caller's own edit.
func (s *liveSession) stop() {
	s.cancel()
	<-s.done
}

// stopLive stops the session running on the message, if any, and returns
// it. The caller decides what the message shows next.
func (a *Agent) stopLive(chatID, messageID int64) *liveSession {
	a.mu.Lock()
	s := a.live
	if s == nil || s.chatID != chatID || s.messageID != messageID {
		a.mu.Unlock()
		return nil
	}
	a.live = nil
	a.mu.Unlock()
	s.stop()
	return s
}

// takeLive unregisters s if it is still the running session, reporting
// whether it was. Whoever takes a session restores its message.
func (a *Agent) takeLive(s *liveSession) bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.live != s {
		return false
	}
	a.live = nil
	return true
}

func (a *Agent) runLive(ctx context.Context, s *liveSession, interval, duration time.Duration) {
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
		err := a.send.EditMessageKB(ctx, s.chatID, s.messageID, render(), liveKeyboard(s.from))
		if telegram.IsMessageNotFound(err) {
			return false
		}
		if wait, ok := telegram.RetryAfter(err); ok {
			pauseUntil = time.Now().Add(max(wait, interval))
		}
		return true
	}
	// finish ends a session that stopped on its own (its ceiling, or the
	// agent shutting down): it restores the message unless a press already
	// took the session over.
	finish := func() {
		if a.takeLive(s) {
			a.restoreLive(s)
		}
	}

	if !frame() {
		a.takeLive(s)
		return
	}
	for {
		select {
		case <-ctx.Done():
			finish()
			return
		case <-tick.C:
			if !deadline.IsZero() && time.Now().After(deadline) {
				finish()
				return
			}
			if time.Now().Before(pauseUntil) {
				continue
			}
			if !frame() {
				a.takeLive(s)
				return
			}
		}
	}
}

// restoreLive puts a session's message back on the screen it came from, so
// a stopped session leaves no orphan state. It uses a fresh context: the
// live context is already canceled on the stop path.
func (a *Agent) restoreLive(s *liveSession) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	text, kb := a.screen(ctx, a.liveBack(s.from))
	a.send.EditMessageKB(ctx, s.chatID, s.messageID, text, kb)
}
