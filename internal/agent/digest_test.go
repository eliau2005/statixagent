package agent

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/eliau2005/statixagent/internal/alert"
)

func TestNextDigestTime(t *testing.T) {
	loc := time.UTC
	cases := []struct {
		now  time.Time
		hour int
		want time.Time
	}{
		// before the hour: today
		{time.Date(2026, 6, 13, 7, 30, 0, 0, loc), 9, time.Date(2026, 6, 13, 9, 0, 0, 0, loc)},
		// after the hour: tomorrow
		{time.Date(2026, 6, 13, 10, 0, 0, 0, loc), 9, time.Date(2026, 6, 14, 9, 0, 0, 0, loc)},
		// exactly at the hour: tomorrow (never fire twice)
		{time.Date(2026, 6, 13, 9, 0, 0, 0, loc), 9, time.Date(2026, 6, 14, 9, 0, 0, 0, loc)},
		// midnight digest
		{time.Date(2026, 6, 13, 23, 59, 0, 0, loc), 0, time.Date(2026, 6, 14, 0, 0, 0, 0, loc)},
	}
	for _, c := range cases {
		if got := nextDigestTime(c.now, c.hour); !got.Equal(c.want) {
			t.Errorf("nextDigestTime(%v, %d) = %v, want %v", c.now, c.hour, got, c.want)
		}
	}
}

func TestDigestAccumulatesAndResets(t *testing.T) {
	send := &fakeSender{}
	a := testAgent(send)
	ctx := context.Background()

	// Two logins (root's own Critical alert counts; deploy's Info notice
	// must not), one failure, one critical alert, one resolved alert.
	a.handleAuthLine(ctx, "Accepted password for root from 203.0.113.7 port 22 ssh2", time.Now())
	a.handleAuthLine(ctx, "Accepted publickey for deploy from 203.0.113.8 port 22 ssh2", time.Now())
	a.handleAuthLine(ctx, "Failed password for invalid user admin from 203.0.113.9 port 22 ssh2", time.Now())
	a.pushAlert(ctx, alert.Alert{Key: "disk:/", Title: "Disk space", Severity: alert.Critical})
	a.pushAlert(ctx, alert.Alert{Key: "cpu", Title: "CPU usage", Resolved: true})

	out := a.digestView(false)
	for _, want := range []string{"2 logins", "1 failed", "2 alerts", "2 critical"} {
		if !strings.Contains(out, want) {
			t.Errorf("digest missing %q: %q", want, out)
		}
	}

	// A reset starts a clean window.
	a.digestView(true)
	out = a.digestView(false)
	if !strings.Contains(out, "no SSH activity") || !strings.Contains(out, "no alerts") {
		t.Errorf("digest after reset: %q", out)
	}
}

func TestDigestCommand(t *testing.T) {
	send := &fakeSender{}
	a := testAgent(send)
	reply := dispatchText(t, a, "/digest")
	if !strings.Contains(reply, "daily digest") {
		t.Errorf("/digest reply: %q", reply)
	}
}
