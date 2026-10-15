package agent

import (
	"context"
	"log"
	"sync"
	"time"

	"github.com/eliau2005/statixagent/internal/telegram"
	"github.com/eliau2005/statixagent/internal/tgui"
)

// Button presses are rate limited per actor (docs/telegram-ux-redesign.md
// §6): a token bucket generous enough that no person tapping through the
// screens meets it, which stops a stuck client or a script from turning
// every press into systemctl, Docker or ufw work. Every press counts,
// views and confirms alike. The limit applies only after authorize, so
// foreign chats stay unanswered and cannot fill the table.

const (
	pressBurst = 10          // presses allowed at once
	pressEvery = time.Second // one press refills per interval
)

// slowDownToast answers a press over the limit; it does nothing else.
const slowDownToast = "Slow down a little"

// phaseRateLimited is the audit phase of a confirm press refused by the
// limiter. Its token stays pending, so pressing again later still works.
const phaseRateLimited = "rate_limited"

// pressLimiter is a token bucket per actor. burst and every are set once
// in New and overridden only by tests.
type pressLimiter struct {
	burst float64       // presses allowed at once
	every time.Duration // one press refills per interval

	mu     sync.Mutex
	actors map[int64]*pressBucket
}

type pressBucket struct {
	tokens float64
	last   time.Time
}

// allow takes one press from actor's bucket at now, reporting whether
// there was one. Buckets that have refilled are dropped, so the table only
// holds actors who pressed within the last burst intervals.
func (l *pressLimiter) allow(actor int64, now time.Time) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.actors == nil {
		l.actors = map[int64]*pressBucket{}
	}
	for id, b := range l.actors {
		if l.refill(b, now) >= l.burst {
			delete(l.actors, id)
		}
	}
	b := l.actors[actor]
	if b == nil {
		b = &pressBucket{tokens: l.burst, last: now}
		l.actors[actor] = b
	}
	if b.tokens < 1 {
		return false
	}
	b.tokens--
	return true
}

// refill adds the presses earned since the last one and returns the total.
func (l *pressLimiter) refill(b *pressBucket, now time.Time) float64 {
	if el := now.Sub(b.last); el > 0 {
		b.tokens = min(l.burst, b.tokens+float64(el)/float64(l.every))
		b.last = now
	}
	return b.tokens
}

// admitPress applies the limit to an authorized press. Over the limit it
// answers with the toast, records a confirm press (c, decoded from "~1"
// data) in the audit log, and reports false: the press does nothing else.
func (a *Agent) admitPress(ctx context.Context, cb *telegram.Callback, c *tgui.Call) bool {
	actor := cb.FromID
	if actor == 0 {
		actor = cb.ChatID
	}
	if a.presses.allow(actor, a.now()) {
		return true
	}
	log.Printf("agent: rate limiting presses from %d", actor)
	if c != nil {
		rec := auditRecord{Phase: phaseRateLimited, ActorID: cb.FromID, ChatID: cb.ChatID, MessageID: cb.MessageID}
		var arg string
		if len(c.Args) == 1 {
			arg = c.Args[0]
		}
		switch c.Act {
		case tgui.ActYes:
			rec.NonceHash = nonceHash(tgui.Nonce(arg))
			a.writeAudit(rec)
		case tgui.ActNo:
			rec.NonceHash = nonceHash(arg)
			a.writeAudit(rec)
		default:
			ask, ok := a.asks[c.Act]
			switch {
			case !ok:
			case ask.resolve == nil:
				// A firewall plan ask builds its target from fresh state
				// only when it runs; record the act alone.
				rec.Action = c.Act
				a.writeAudit(rec)
			default:
				if rec.Action, rec.Target, ok = ask.resolve(c.Args); ok {
					a.writeAudit(rec)
				}
			}
		}
	}
	a.answer(ctx, cb, slowDownToast)
	return false
}
