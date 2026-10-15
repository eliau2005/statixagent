// Package alert decides when a measurement or event becomes a notification.
// Threshold alerts use hysteresis (fire once on crossing, clear on recovery
// past a margin) plus a cooldown so a flapping metric cannot spam the chat.
// A rule may also demand the violation hold for several consecutive samples,
// which is what keeps an instantaneous sensor (temperature) from alerting on
// a two-second spike. Pass/fail checks (a watched unit, port or endpoint)
// follow the same rules with a boolean in place of a value. Event alerts
// (new login, power loss) dedupe by key + cooldown only.
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

// Unsnooze lifts a snooze on key; a key that is not snoozed is left as
// it is.
func (e *Engine) Unsnooze(key string) {
	e.mu.Lock()
	defer e.mu.Unlock()
	delete(e.snoozedUntil, key)
}

// SnoozedUntil reports until when key is silenced, if it is at now.
func (e *Engine) SnoozedUntil(key string, now time.Time) (time.Time, bool) {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.snoozedUntil[key], e.snoozed(key, now)
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
	fire, resolve := e.step(o.Key, violating, recovered, o.Sustain, now)
	switch {
	case fire:
		cmp := "above"
		if o.Below {
			cmp = "below"
		}
		return &Alert{
			Key: o.Key, Severity: o.Severity, Title: o.Title, At: now,
			Body: fmt.Sprintf("%.1f%s is %s the %.1f%s threshold", o.Value, o.Unit, cmp, o.Threshold, o.Unit),
		}
	case resolve:
		return &Alert{
			Key: o.Key, Severity: Info, Title: o.Title, Resolved: true, At: now,
			Body: fmt.Sprintf("recovered: now %.1f%s", o.Value, o.Unit),
		}
	}
	return nil
}

// Check is Threshold for a check that either passes or fails, such as a
// unit being active: fire when it starts failing, resolve when it passes
// again after a fire, with the same cooldown and snooze. A failure that
// was not alerted (cooldown, snooze) resolves silently; one still in
// progress when they end fires then.
func (e *Engine) Check(key string, failing bool, now time.Time) (fire, resolve bool) {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.step(key, failing, !failing, 1, now)
}

// Seed records whether a check is failing without alerting, for a
// watcher's first look after startup: a failure already there is not
// news, but its recovery is.
func (e *Engine) Seed(key string, failing bool) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.active[key] = failing
	e.streak[key] = 0
}

// step moves key's firing state for one sample and reports whether it
// fires or resolves. Callers hold e.mu.
func (e *Engine) step(key string, violating, recovered bool, sustain int, now time.Time) (fire, resolve bool) {
	// Count the run of violating samples first, so a snoozed key still has an
	// accurate streak when the snooze lifts.
	if violating {
		e.streak[key]++
	} else {
		e.streak[key] = 0
	}
	sustained := violating && e.streak[key] >= max(sustain, 1)

	if e.snoozed(key, now) {
		// Stay quiet. Recovery clears the firing state silently so that a
		// violation still present (or back) after the snooze fires fresh.
		if recovered {
			e.active[key] = false
		}
		return false, false
	}
	switch {
	case sustained && !e.active[key]:
		if last, ok := e.lastFired[key]; ok && now.Sub(last) < e.Cooldown {
			return false, false // refuse to flap inside the cooldown
		}
		e.active[key] = true
		e.lastFired[key] = now
		return true, false
	case recovered && e.active[key]:
		e.active[key] = false
		return false, true
	}
	return false, false
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
