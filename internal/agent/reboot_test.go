package agent

import (
	"testing"
	"time"

	"github.com/eliau2005/statixagent/internal/alert"
	"github.com/eliau2005/statixagent/internal/collect"
)

func TestCheckReboot(t *testing.T) {
	now := time.Now()

	// Fresh boot at first sample: alert once, then never again.
	a := testAgent(&fakeSender{})
	al := a.checkReboot(collect.Snapshot{Uptime: 2 * time.Minute}, now)
	if al == nil || al.Title != "Host rebooted" || al.Severity != alert.Warning {
		t.Fatalf("fresh boot alert = %+v", al)
	}
	if again := a.checkReboot(collect.Snapshot{Uptime: 3 * time.Minute}, now); again != nil {
		t.Errorf("second sample re-alerted: %+v", again)
	}

	// Long uptime at first sample (routine agent restart): silent, and the
	// check is spent.
	a = testAgent(&fakeSender{})
	if al := a.checkReboot(collect.Snapshot{Uptime: 6 * time.Hour}, now); al != nil {
		t.Errorf("agent restart alerted: %+v", al)
	}
	if al := a.checkReboot(collect.Snapshot{Uptime: time.Minute}, now); al != nil {
		t.Errorf("check ran twice: %+v", al)
	}

	// Unreadable uptime leaves the check pending for the next sample.
	a = testAgent(&fakeSender{})
	if al := a.checkReboot(collect.Snapshot{}, now); al != nil {
		t.Errorf("zero uptime alerted: %+v", al)
	}
	if al := a.checkReboot(collect.Snapshot{Uptime: time.Minute}, now); al == nil {
		t.Error("check spent by an unreadable sample")
	}
}
