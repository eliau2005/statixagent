package telegram

import (
	"context"
	"sync"
	"time"
)

// clock is the time source for send pacing and 429 waits; tests inject a
// fake one so no test sleeps for real.
type clock struct {
	now   func() time.Time
	sleep func(ctx context.Context, d time.Duration) error
}

var realClock = clock{now: time.Now, sleep: sleepCtx}

// orReal lets a zero clock (a Client built as a struct literal) work.
func (c clock) orReal() clock {
	if c.now == nil || c.sleep == nil {
		return realClock
	}
	return c
}

// sleepCtx waits d or until ctx is done.
func sleepCtx(ctx context.Context, d time.Duration) error {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
		return nil
	}
}

// chatLimiter is a token bucket per chat that keeps sends and edits under
// Telegram's ~1 msg/s per-chat limit. It never drops: a caller over budget
// waits for its turn, so an alert flood is delayed rather than lost or
// answered with 429s. The bot talks to one configured chat, so the map
// stays tiny.
type chatLimiter struct {
	every time.Duration // one token refills per interval
	burst float64
	clock clock

	mu    sync.Mutex
	chats map[int64]*bucket
}

type bucket struct {
	tokens float64 // may go negative: each unit is a queued reservation
	last   time.Time
}

func newChatLimiter(every time.Duration, burst int, clk clock) *chatLimiter {
	return &chatLimiter{every: every, burst: float64(burst), clock: clk.orReal(), chats: map[int64]*bucket{}}
}

// wait reserves one send for chatID and sleeps until it is due. Reserving
// under the lock keeps concurrent callers (the update loop, live mode,
// alert loops) in order without holding the lock while sleeping.
func (l *chatLimiter) wait(ctx context.Context, chatID int64) error {
	l.mu.Lock()
	now := l.clock.now()
	b := l.chats[chatID]
	if b == nil {
		b = &bucket{tokens: l.burst, last: now}
		l.chats[chatID] = b
	}
	if el := now.Sub(b.last); el > 0 {
		b.tokens = min(l.burst, b.tokens+float64(el)/float64(l.every))
		b.last = now
	}
	b.tokens--
	var delay time.Duration
	if b.tokens < 0 {
		delay = time.Duration(-b.tokens * float64(l.every))
	}
	l.mu.Unlock()
	if delay <= 0 {
		return nil
	}
	if err := l.clock.sleep(ctx, delay); err != nil {
		// Give the unused reservation back so later sends are not delayed
		// by one that never happened.
		l.mu.Lock()
		b.tokens++
		l.mu.Unlock()
		return err
	}
	return nil
}
