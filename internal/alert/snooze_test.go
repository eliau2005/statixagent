package alert

import (
	"testing"
	"time"
)

func TestSnoozeThreshold(t *testing.T) {
	e := New(time.Minute)
	now := time.Now()
	hot := ThresholdOpts{Key: "cpu", Title: "CPU", Severity: Warning, Value: 95, Threshold: 90, ClearMargin: 10, Unit: "%"}
	cool := hot
	cool.Value = 50

	e.Snooze("cpu", now.Add(time.Hour))
	if al := e.Threshold(hot, now); al != nil {
		t.Fatalf("snoozed threshold fired: %+v", al)
	}
	// Still violating after the snooze expires: fires fresh.
	after := now.Add(2 * time.Hour)
	if al := e.Threshold(hot, after); al == nil {
		t.Fatal("expired snooze did not re-fire")
	}

	// Recovery during a snooze is silent and resets the firing state.
	e.Snooze("cpu", after.Add(time.Hour))
	if al := e.Threshold(cool, after.Add(time.Minute)); al != nil {
		t.Fatalf("snoozed recovery emitted: %+v", al)
	}
	later := after.Add(2 * time.Hour)
	if al := e.Threshold(hot, later); al == nil {
		t.Fatal("violation after silent recovery did not fire")
	}
}

func TestSnoozeEvent(t *testing.T) {
	e := New(time.Minute)
	now := time.Now()
	e.Snooze("ssl:x", now.Add(time.Hour))
	if al := e.Event("ssl:x", "Cert", "expiring", Warning, now, 0); al != nil {
		t.Fatalf("snoozed event emitted: %+v", al)
	}
	// Unrelated keys are unaffected.
	if al := e.Event("ssl:y", "Cert", "expiring", Warning, now, 0); al == nil {
		t.Fatal("other key suppressed")
	}
	// After expiry the event flows again, with lastFired untouched by the
	// suppressed attempt.
	if al := e.Event("ssl:x", "Cert", "expiring", Warning, now.Add(2*time.Hour), 0); al == nil {
		t.Fatal("event after snooze expiry suppressed")
	}
}
