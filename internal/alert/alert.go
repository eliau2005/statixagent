// Package alert decides when a measurement or event becomes a notification.
// Threshold alerts use hysteresis (fire once on crossing, clear on recovery
// past a margin) plus a cooldown so a flapping metric cannot spam the chat.
// A rule may also demand the violation hold for several consecutive samples,
// which is what keeps an instantaneous sensor (temperature) from alerting on
// a two-second spike. Event alerts (new login, power loss) dedupe by key +
// cooldown only.
package alert

import (
	"fmt"
	"sync"
	"time"
)

// Severity orders alerts for formatting.
type Severity int

const (
	Info Severity = iota
	Warning
	Critical
)

func (s Severity) String() string {
	switch s {
	case Critical:
		return "critical"
	case Warning:
		return "warning"
	default:
		return "info"
	}
}

// Alert is one notification to push to the bot.
type Alert struct {
	Key      string // stable identity for dedupe ("cpu", "disk:/", "ssh:login")
	Severity Severity
	Title    string
	Body     string
	Resolved bool // recovery notice for a previously firing threshold
	At       time.Time
}

// Engine tracks firing state per key.
type Engine struct {
	// Cooldown is the minimum gap between two fires of the same key.
	Cooldown time.Duration

	mu           sync.Mutex
	active       map[string]bool
	streak       map[string]int // consecutive violating samples per key
	lastFired    map[string]time.Time
	snoozedUntil map[string]time.Time
}

// New returns an Engine with the given re-fire cooldown.
func New(cooldown time.Duration) *Engine {
	return &Engine{
		Cooldown:     cooldown,
		active:       map[string]bool{},
		streak:       map[string]int{},
		lastFired:    map[string]time.Time{},
		snoozedUntil: map[string]time.Time{},
	}
}

// Snooze silences a key until the given time: no fires, no recoveries.
// A violation still in progress when the snooze expires fires again.
func (e *Engine) Snooze(key string, until time.Time) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.snoozedUntil[key] = until
}

// snoozed reports whether key is silenced at now. Callers hold e.mu.
func (e *Engine) snoozed(key string, now time.Time) bool {
	until, ok := e.snoozedUntil[key]
	return ok && now.Before(until)
}

// ThresholdOpts configures one threshold evaluation.
type ThresholdOpts struct {
	Key         string
	Title       string
	Severity    Severity
	Value       float64
	Threshold   float64
	ClearMargin float64 // recovery requires passing threshold by this much
	Below       bool    // true: alert when Value < Threshold (battery)
	Unit        string  // "%", "°C" — used in the body text

	// Sustain is how many consecutive violating samples must arrive before
	// the rule fires. 0 and 1 both mean "fire on the first one". Raise it for
	// a metric read as an instant value rather than an interval average: a
	// laptop CPU touches 90°C for two seconds on any burst, and that is not
	// an incident. Recovery is unaffected — a cleared value resolves at once.
	Sustain int
}

// Threshold evaluates one rule. It returns a firing alert once the violation
// has held for Sustain consecutive samples, a Resolved alert when the value
// recovers past the margin, and nil otherwise.
func (e *Engine) Threshold(o ThresholdOpts, now time.Time) *Alert {
	violating := o.Value >= o.Threshold
	recovered := o.Value < o.Threshold-o.ClearMargin
	if o.Below {
		violating = o.Value <= o.Threshold
		recovered = o.Value > o.Threshold+o.ClearMargin
	}

	e.mu.Lock()
	defer e.mu.Unlock()

	// Count the run of violating samples first, so a snoozed key still has an
	// accurate streak when the snooze lifts.
	if violating {
		e.streak[o.Key]++
	} else {
		e.streak[o.Key] = 0
	}
	sustained := violating && e.streak[o.Key] >= max(o.Sustain, 1)

	if e.snoozed(o.Key, now) {
		// Stay quiet. Recovery clears the firing state silently so that a
		// violation still present (or back) after the snooze fires fresh.
		if recovered {
			e.active[o.Key] = false
		}
		return nil
	}
	switch {
	case sustained && !e.active[o.Key]:
		if last, ok := e.lastFired[o.Key]; ok && now.Sub(last) < e.Cooldown {
			return nil // refuse to flap inside the cooldown
		}
		e.active[o.Key] = true
		e.lastFired[o.Key] = now
		cmp := "above"
		if o.Below {
			cmp = "below"
		}
		return &Alert{
			Key: o.Key, Severity: o.Severity, Title: o.Title, At: now,
			Body: fmt.Sprintf("%.1f%s is %s the %.1f%s threshold", o.Value, o.Unit, cmp, o.Threshold, o.Unit),
		}
	case recovered && e.active[o.Key]:
		e.active[o.Key] = false
		return &Alert{
			Key: o.Key, Severity: Info, Title: o.Title, Resolved: true, At: now,
			Body: fmt.Sprintf("recovered: now %.1f%s", o.Value, o.Unit),
		}
	}
	return nil
}

// Event emits an event alert unless the same key fired within the cooldown.
// cooldownOverride > 0 replaces the engine default (0 = always emit).
func (e *Engine) Event(key, title, body string, sev Severity, now time.Time, cooldownOverride time.Duration) *Alert {
	cd := e.Cooldown
	if cooldownOverride != 0 {
		cd = cooldownOverride
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.snoozed(key, now) {
		return nil
	}
	if last, ok := e.lastFired[key]; ok && cd > 0 && now.Sub(last) < cd {
		return nil
	}
	e.lastFired[key] = now
	return &Alert{Key: key, Severity: sev, Title: title, Body: body, At: now}
}

// Active reports whether a threshold key is currently firing.
func (e *Engine) Active(key string) bool {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.active[key]
}
