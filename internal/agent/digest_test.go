package agent

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/eliau2005/statixagent/internal/alert"
	"github.com/eliau2005/statixagent/internal/telegram"
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
	unlimitPresses(a)

	// The settings view shows the digest row; its buttons carry the state
	// and hour they set.
	text, kb := a.settingsView()
	if !strings.Contains(text, "Daily digest") || !strings.Contains(text, "09:00") {
		t.Fatalf("settings view: %q", text)
	}
	digestRow := func(kb telegram.Keyboard) []telegram.Button {
		for _, row := range kb {
			if strings.HasPrefix(row[0].Text, "📰 Digest") {
				return row
			}
		}
		return nil
	}
	if got := dumpKeyboard(telegram.Keyboard{digestRow(kb)}); got != "[📰 Digest: on] → ~1dg|off  [−1h] → ~1dh|8  [09:00] → ~1dh  [+1h] → ~1dh|10\n" {
		t.Fatalf("digest buttons = %s", got)
	}

	// Off, twice: the replay finds it off and changes nothing.
	press(a, "c1", "~1dg|off")
	press(a, "c2", "~1dg|off")
	if enabled, _ := a.digestCfg(); enabled {
		t.Error("digest still enabled after Off")
	}
	if got := send.answered[len(send.answered)-2:]; got[0] != "c1:Digest off (not persisted: no config path)" || got[1] != "c2:Digest is already off" {
		t.Errorf("answered = %v", got)
	}

	// Hour wraps around midnight in both directions, following the
	// buttons each fresh screen offers.
	for i := range 10 {
		press(a, fmt.Sprint("m", i), digestRow(send.lastEdit().kb)[1].Data)
	}
	if _, hour := a.digestCfg(); hour != 23 {
		t.Errorf("hour after 10x −1h from 9: got %d, want 23", hour)
	}
	press(a, "p", digestRow(send.lastEdit().kb)[3].Data)
	if _, hour := a.digestCfg(); hour != 0 {
		t.Errorf("hour after +1h from 23: got %d, want 0", hour)
	}
	// The hour label explains itself and changes nothing.
	before := send.editCount()
	press(a, "l", "~1dh")
	if send.editCount() != before || send.answered[len(send.answered)-1] != "l:Tap −1h or +1h to move the daily digest." {
		t.Errorf("hour label: answered %v", send.answered[len(send.answered)-1])
	}
	// Forged values are refused.
	for _, data := range []string{"~1dg", "~1dg|maybe", "~1dh|24", "~1dh|-1", "~1dh|07", "~1dh|1|2"} {
		press(a, "f", data)
		if send.answered[len(send.answered)-1] != "f:"+outdatedToast {
			t.Errorf("%s: answered %v", data, send.answered[len(send.answered)-1])
		}
	}
	if enabled, hour := a.digestCfg(); enabled || hour != 0 {
		t.Errorf("forged presses changed the digest: %v %d", enabled, hour)
	}
}

// The digest buttons of older versions apply their step once per press.
func TestDigestLegacyButtons(t *testing.T) {
	a := testAgent(&fakeSender{})
	ctx := context.Background()
	if _, _, toast, handled := a.handleSettingsCallback(ctx, "dg:toggle"); !handled || !strings.Contains(toast, "off") {
		t.Errorf("toggle: handled=%v toast=%q", handled, toast)
	}
	if enabled, _ := a.digestCfg(); enabled {
		t.Error("digest still enabled after toggle")
	}
	for range 10 {
		a.handleSettingsCallback(ctx, "dg:hour:-1")
	}
	if _, hour := a.digestCfg(); hour != 23 {
		t.Errorf("hour after 10x -1 from 9: got %d, want 23", hour)
	}
	a.handleSettingsCallback(ctx, "dg:hour:+1")
	if _, hour := a.digestCfg(); hour != 0 {
		t.Errorf("hour after +1 from 23: got %d, want 0", hour)
	}
	// Only the steps the old keyboard emitted are accepted.
	for _, data := range []string{"dg:hour:+5", "dg:hour:-24", "dg:hour:x"} {
		if _, _, toast, _ := a.handleSettingsCallback(ctx, data); toast != "bad action" {
			t.Errorf("%s: toast %q", data, toast)
		}
	}
	if _, hour := a.digestCfg(); hour != 0 {
		t.Errorf("rejected steps moved the hour to %d", hour)
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
