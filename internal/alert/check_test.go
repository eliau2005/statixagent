package alert

import (
	"testing"
	"time"
)

func TestCheckTransitions(t *testing.T) {
	type step struct {
		at      time.Duration
		failing bool
		fire    bool
		resolve bool
	}
	for _, tc := range []struct {
		name  string
		seed  *bool
		steps []step
	}{
		{name: "fires once, then recovers", steps: []step{
			{0, false, false, false},
			{time.Minute, true, true, false},
			{2 * time.Minute, true, false, false},
			{3 * time.Minute, false, false, true},
			{4 * time.Minute, false, false, false},
		}},
		{name: "a flap inside the cooldown stays silent, and fires once it ends", steps: []step{
			{0, true, true, false},
			{time.Minute, false, false, true},
			{2 * time.Minute, true, false, false},
			{3 * time.Minute, false, false, false}, // never alerted: no recovery
			{4 * time.Minute, true, false, false},
			{11 * time.Minute, true, true, false},
		}},
		{name: "seeded failing: silent, then its recovery", seed: new(true), steps: []step{
			{0, true, false, false},
			{time.Minute, false, false, true},
		}},
		{name: "seeded healthy: the first failure fires", seed: new(false), steps: []step{
			{0, true, true, false},
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			e := New(10 * time.Minute)
			if tc.seed != nil {
				e.Seed("svc:x", *tc.seed)
			}
			for i, s := range tc.steps {
				fire, resolve := e.Check("svc:x", s.failing, t0.Add(s.at))
				if fire != s.fire || resolve != s.resolve {
					t.Fatalf("step %d: fire, resolve = %v, %v; want %v, %v", i, fire, resolve, s.fire, s.resolve)
				}
			}
		})
	}
}

func TestCheckSnooze(t *testing.T) {
	e := New(10 * time.Minute)
	e.Snooze("svc:x", t0.Add(time.Hour))
	if fire, _ := e.Check("svc:x", true, t0); fire {
		t.Fatal("snoozed check fired")
	}
	// Still failing when the snooze ends: it fires then.
	if fire, _ := e.Check("svc:x", true, t0.Add(2*time.Hour)); !fire {
		t.Fatal("failure outlasting the snooze did not fire")
	}
	// A recovery during a snooze is silent too.
	e.Snooze("svc:x", t0.Add(3*time.Hour))
	if _, resolve := e.Check("svc:x", false, t0.Add(150*time.Minute)); resolve {
		t.Fatal("snoozed recovery resolved")
	}
}
