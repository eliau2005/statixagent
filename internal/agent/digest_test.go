package agent

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/eliau2005/statixagent/internal/alert"
)

func TestDigestDue(t *testing.T) {
	at := func(day, hour, minute int) time.Time {
		return time.Date(2026, 6, day, hour, minute, 0, 0, time.UTC)
	}
	lastDay := 0

	// Wrong hour: not due.
	if _, due := digestDue(at(13, 8, 59), 9, lastDay); due {
		t.Error("due before the hour")
	}
	// The hour arrives: due exactly once, any minute within it.
	lastDay, due := digestDue(at(13, 9, 17), 9, lastDay)
	if !due {
		t.Fatal("not due at the configured hour")
	}
	if _, again := digestDue(at(13, 9, 47), 9, lastDay); again {
		t.Error("fired twice in one day")
	}
	// Next day, same hour: due again.
	if _, due := digestDue(at(14, 9, 0), 9, lastDay); !due {
		t.Error("not due the next day")
	}
}

func TestDigestSettingsButtons(t *testing.T) {
	send := &fakeSender{}
	a := testAgent(send)
	ctx := context.Background()

	// The settings view shows the digest row.
	text, kb := a.settingsView()
	if !strings.Contains(text, "Daily digest") || !strings.Contains(text, "09:00") {
		t.Fatalf("settings view: %q", text)
	}
	last := kb[len(kb)-2]
	if last[0].Data != "dg:hour:-1" || last[1].Data != "dg:toggle" || last[2].Data != "dg:hour:+1" {
		t.Fatalf("digest buttons = %+v", last)
	}

	// Toggle flips the runtime config.
	if _, _, toast, handled := a.handleSettingsCallback(ctx, "dg:toggle"); !handled || !strings.Contains(toast, "off") {
		t.Errorf("toggle: handled=%v toast=%q", handled, toast)
	}
	if enabled, _ := a.digestCfg(); enabled {
		t.Error("digest still enabled after toggle")
	}

	// Hour wraps around midnight in both directions.
	for i := 0; i < 10; i++ {
		a.handleSettingsCallback(ctx, "dg:hour:-1")
	}
	if _, hour := a.digestCfg(); hour != 23 {
		t.Errorf("hour after 10x -1 from 9: got %d, want 23", hour)
	}
	a.handleSettingsCallback(ctx, "dg:hour:+1")
	if _, hour := a.digestCfg(); hour != 0 {
		t.Errorf("hour after +1 from 23: got %d, want 0", hour)
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
