package agent

import (
	"context"
	"fmt"
	"time"

	"github.com/eliau2005/statixagent/internal/bot"
	"github.com/eliau2005/statixagent/internal/telegram"
)

// Live mode: pressing ▶️ Live re-renders the status card in place on a
// short tick, turning the message into a self-updating dashboard for a
// bounded window. Only one live session runs at a time.

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
	interval, duration := a.liveInterval, a.liveDuration
	a.mu.Unlock()

	go func() {
		defer cancel()
		safely("live", func() {
			a.runLive(liveCtx, chatID, messageID, interval, duration)
		})
	}()
}

func (a *Agent) stopLive() {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.liveCancel != nil {
		a.liveCancel()
		a.liveCancel = nil
	}
}

func (a *Agent) runLive(ctx context.Context, chatID, messageID int64, interval, duration time.Duration) {
	deadline := time.Now().Add(duration)
	tick := time.NewTicker(interval)
	defer tick.Stop()

	frame := 0
	render := func() string {
		a.sampleOnce(ctx) // fresh data every tick, not the 15s cadence
		a.mu.Lock()
		body := bot.Status(a.src.Hostname, a.snap, a.thermal, a.power)
		a.mu.Unlock()
		left := time.Until(deadline).Round(time.Second)
		if left < 0 {
			left = 0
		}
		header := fmt.Sprintf("%s 🔴 <b>LIVE</b> · %s left\n", spinnerFrames[frame%len(spinnerFrames)], bot.Dur(left))
		frame++
		return header + body
	}

	a.send.EditMessageKB(ctx, chatID, messageID, render(), liveKeyboard())
	for {
		select {
		case <-ctx.Done():
			a.finishLive(chatID, messageID)
			return
		case <-tick.C:
			if time.Now().After(deadline) {
				a.finishLive(chatID, messageID)
				return
			}
			a.send.EditMessageKB(ctx, chatID, messageID, render(), liveKeyboard())
		}
	}
}

// finishLive restores the normal status view and nav keyboard. It uses a
// fresh context: the live context is already canceled on the stop path.
func (a *Agent) finishLive(chatID, messageID int64) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	a.mu.Lock()
	body := bot.Status(a.src.Hostname, a.snap, a.thermal, a.power)
	a.mu.Unlock()
	a.send.EditMessageKB(ctx, chatID, messageID, body, navKeyboard("status"))
}
