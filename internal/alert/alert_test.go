package alert

import (
	"strings"
	"testing"
	"time"
)

var t0 = time.Date(2026, 6, 12, 17, 0, 0, 0, time.UTC)

func cpuOpts(v float64) ThresholdOpts {
	return ThresholdOpts{
		Key: "cpu", Title: "CPU usage", Severity: Warning,
		Value: v, Threshold: 90, ClearMargin: 5, Unit: "%",
	}
}

func TestThresholdFireOnceAndRecover(t *testing.T) {
	e := New(10 * time.Minute)

	if a := e.Threshold(cpuOpts(50), t0); a != nil {
		t.Fatalf("below threshold fired: %+v", a)
	}
	a := e.Threshold(cpuOpts(95), t0.Add(time.Minute))
	if a == nil || a.Resolved || a.Severity != Warning {
		t.Fatalf("crossing must fire: %+v", a)
	}
	if !strings.Contains(a.Body, "95.0% is above the 90.0%") {
		t.Errorf("body = %q", a.Body)
	}
	if a := e.Threshold(cpuOpts(97), t0.Add(2*time.Minute)); a != nil {
		t.Fatalf("still violating must not re-fire: %+v", a)
	}
	// 88% is under threshold but inside the 5-point clear margin: no recovery yet.
	if a := e.Threshold(cpuOpts(88), t0.Add(3*time.Minute)); a != nil {
		t.Fatalf("inside hysteresis margin must stay silent: %+v", a)
	}
	if !e.Active("cpu") {
		t.Fatal("must still be active inside margin")
	}
	rec := e.Threshold(cpuOpts(60), t0.Add(4*time.Minute))
	if rec == nil || !rec.Resolved {
		t.Fatalf("recovery alert expected: %+v", rec)
	}
	if e.Active("cpu") {
		t.Fatal("must be inactive after recovery")
	}
}

func TestThresholdCooldownBlocksFlapping(t *testing.T) {
	e := New(10 * time.Minute)
	e.Threshold(cpuOpts(95), t0)                  // fire
	e.Threshold(cpuOpts(50), t0.Add(time.Minute)) // recover
	if a := e.Threshold(cpuOpts(95), t0.Add(2*time.Minute)); a != nil {
		t.Fatalf("re-fire inside cooldown: %+v", a)
	}
	if a := e.Threshold(cpuOpts(95), t0.Add(11*time.Minute)); a == nil {
		t.Fatal("re-fire after cooldown must work")
	}
}

func TestThresholdBelowMode(t *testing.T) {
	e := New(0)
	battery := func(v float64) ThresholdOpts {
		return ThresholdOpts{
			Key: "battery", Title: "Battery", Severity: Critical,
			Value: v, Threshold: 15, ClearMargin: 5, Below: true, Unit: "%",
		}
	}
	if a := e.Threshold(battery(80), t0); a != nil {
		t.Fatalf("healthy battery fired: %+v", a)
	}
	a := e.Threshold(battery(12), t0.Add(time.Minute))
	if a == nil || !strings.Contains(a.Body, "below") {
		t.Fatalf("low battery must fire with 'below': %+v", a)
	}
	if a := e.Threshold(battery(17), t0.Add(2*time.Minute)); a != nil {
		t.Fatalf("17%% is inside clear margin (15+5): %+v", a)
	}
	rec := e.Threshold(battery(45), t0.Add(3*time.Minute))
	if rec == nil || !rec.Resolved {
		t.Fatalf("charging past margin must resolve: %+v", rec)
	}
}

func TestEventCooldown(t *testing.T) {
	e := New(time.Hour)
	a := e.Event("power-loss", "Power lost", "running on battery", Critical, t0, 0)
	if a == nil || a.Severity != Critical {
		t.Fatalf("first event must emit: %+v", a)
	}
	if a := e.Event("power-loss", "Power lost", "again", Critical, t0.Add(time.Minute), 0); a != nil {
		t.Fatalf("inside default cooldown: %+v", a)
	}
	// Override: ssh logins always alert (cooldown -1 → effectively zero? use small override)
	if a := e.Event("ssh-login", "login", "alice", Info, t0, time.Nanosecond); a == nil {
		t.Fatal("first ssh login must emit")
	}
	if a := e.Event("ssh-login", "login", "alice again", Info, t0.Add(time.Second), time.Nanosecond); a == nil {
		t.Fatal("tiny override cooldown must allow immediate re-emit")
	}
}

func tempOpts(v float64) ThresholdOpts {
	return ThresholdOpts{
		Key: "temp", Title: "Temperature", Severity: Warning,
		Value: v, Threshold: 70, ClearMargin: 5, Unit: "°C", Sustain: 3,
	}
}

func TestThresholdSustainIgnoresSpike(t *testing.T) {
	e := New(10 * time.Minute)

	// A mobile CPU boosting for one sample: over threshold, then back down.
	if a := e.Threshold(tempOpts(92), t0); a != nil {
		t.Fatalf("single spike fired: %+v", a)
	}
	if a := e.Threshold(tempOpts(41), t0.Add(15*time.Second)); a != nil {
		t.Fatalf("cooled sample fired: %+v", a)
	}
	if e.Active("temp") {
		t.Fatal("a spike must not leave the key active")
	}
	// Two in a row is still short of Sustain, and the run restarts after a
	// sample that clears.
	e.Threshold(tempOpts(92), t0.Add(30*time.Second))
	if a := e.Threshold(tempOpts(91), t0.Add(45*time.Second)); a != nil {
		t.Fatalf("second consecutive sample fired early: %+v", a)
	}
	if a := e.Threshold(tempOpts(41), t0.Add(60*time.Second)); a != nil {
		t.Fatalf("recovery without a fire must stay silent: %+v", a)
	}
	if a := e.Threshold(tempOpts(92), t0.Add(75*time.Second)); a != nil {
		t.Fatalf("streak must restart after a clearing sample: %+v", a)
	}
}

func TestThresholdSustainFiresWhenHeld(t *testing.T) {
	e := New(10 * time.Minute)

	e.Threshold(tempOpts(88), t0)
	e.Threshold(tempOpts(90), t0.Add(15*time.Second))
	a := e.Threshold(tempOpts(92), t0.Add(30*time.Second))
	if a == nil || a.Resolved {
		t.Fatalf("third consecutive sample must fire: %+v", a)
	}
	if !strings.Contains(a.Body, "92.0°C is above the 70.0°C") {
		t.Errorf("body = %q", a.Body)
	}
	// Recovery is immediate — it does not wait for a run of its own.
	rec := e.Threshold(tempOpts(41), t0.Add(45*time.Second))
	if rec == nil || !rec.Resolved {
		t.Fatalf("recovery alert expected: %+v", rec)
	}
}

func TestThresholdSustainDefaultsToOne(t *testing.T) {
	e := New(10 * time.Minute)
	if a := e.Threshold(cpuOpts(95), t0); a == nil {
		t.Fatal("Sustain 0 must fire on the first violating sample")
	}
}
