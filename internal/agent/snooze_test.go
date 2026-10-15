package agent

import (
	"context"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/eliau2005/statixagent/internal/alert"
	"github.com/eliau2005/statixagent/internal/collect"
	"github.com/eliau2005/statixagent/internal/procfs"
	"github.com/eliau2005/statixagent/internal/telegram"
	"github.com/eliau2005/statixagent/internal/tgui"
)

// snoozed reports whether key is silenced at now.
func snoozed(a *Agent, key string, now time.Time) bool {
	_, ok := a.engine.SnoozedUntil(key, now)
	return ok
}

// buttonData is the data of the button labelled label in kb, or "".
func buttonData(kb telegram.Keyboard, label string) string {
	for _, row := range kb {
		for _, b := range row {
			if b.Text == label {
				return b.Data
			}
		}
	}
	return ""
}

func TestSnoozeCallback(t *testing.T) {
	send := &fakeSender{}
	a := testAgent(send)
	ctx := context.Background()
	hot := collect.Snapshot{CPUTotal: collect.CPUUsage{Percent: 97}, Mem: procfs.MemInfo{Total: 100, Available: 60}}

	a.handleCallback(ctx, &telegram.Callback{ID: "cb1", ChatID: 42, MessageID: 7, Data: buttonData(a.alertKeyboard("cpu"), "🔕 1h")})

	send.mu.Lock()
	answered := append([]string(nil), send.answered...)
	send.mu.Unlock()
	if len(answered) == 0 || !strings.Contains(answered[0], "Snoozed for 1h") {
		t.Fatalf("snooze toast = %v", answered)
	}

	// The snoozed key stays quiet; everything else still evaluates.
	// Run the full sustain window so the rule would otherwise fire.
	now := time.Now()
	step := a.cfg.SampleInterval.Duration
	for i := range systemSustainN(a) {
		if al := keyed(a.evalSystem(hot, now.Add(time.Duration(i)*step)), "cpu"); al != nil {
			t.Fatalf("cpu alerted while snoozed: %+v", al)
		}
	}

	// Foreign chats cannot snooze.
	a.handleCallback(ctx, &telegram.Callback{ID: "cb2", ChatID: 999, MessageID: 7, Data: buttonData(a.alertKeyboard("mem"), "🔕 1h")})
	if keyed(evalSustained(a, collect.Snapshot{Mem: procfs.MemInfo{Total: 100, Available: 5}}, time.Now()), "mem") == nil {
		t.Fatal("mem did not alert; foreign-chat snooze was honored")
	}
}

// §3.11: 1h, 8h or 24h; the press changes only the alert's keyboard, whose
// snooze row becomes an Undo that lifts the snooze and brings it back.
func TestSnoozeChoicesAndUndo(t *testing.T) {
	for _, tc := range []struct {
		label string
		d     time.Duration
		until string
	}{
		{"🔕 1h", time.Hour, "🔔 Snoozed until 15:05 · Undo"},
		{"🔕 8h", 8 * time.Hour, "🔔 Snoozed until 22:05 · Undo"},
		{"🔕 24h", 24 * time.Hour, "🔔 Snoozed until Fri 14:05 · Undo"},
	} {
		send := &fakeSender{}
		a := testAgent(send)
		a.now = func() time.Time { return screenEpoch }
		ctx := context.Background()
		alertID, err := a.pushAlertKB(ctx, alert.Alert{Key: "disk:/", Title: "Disk space /", Body: "91%"}, a.alertKeyboard("disk:/"))
		if err != nil {
			t.Fatal(err)
		}
		sent := slices.Clone(send.all())
		press := func(id, data string) {
			a.handleCallback(ctx, &telegram.Callback{ID: id, ChatID: 42, ChatType: "private", FromID: 42, MessageID: alertID, Data: data})
		}

		press("s", buttonData(send.keyboards[0], tc.label))
		if !snoozed(a, "disk:/", screenEpoch.Add(tc.d-time.Second)) || snoozed(a, "disk:/", screenEpoch.Add(tc.d)) {
			t.Errorf("%s: snoozed for the wrong time", tc.label)
		}
		if len(send.markups) != 1 || send.markups[0].id != alertID {
			t.Fatalf("%s: markup edits %v", tc.label, send.markups)
		}
		kb := send.markups[0].kb
		undo := buttonData(kb, tc.until)
		if undo == "" || len(kb) != 2 || dumpKeyboard(kb[:1]) != dumpKeyboard(send.keyboards[0][:1]) {
			t.Fatalf("%s: snoozed keyboard\n%s", tc.label, dumpKeyboard(kb))
		}

		// Undo, twice: the second finds nothing to lift and is harmless.
		press("u1", undo)
		press("u2", undo)
		if snoozed(a, "disk:/", screenEpoch) {
			t.Errorf("%s: still snoozed after Undo", tc.label)
		}
		if got := dumpKeyboard(send.markups[len(send.markups)-1].kb); got != dumpKeyboard(send.keyboards[0]) {
			t.Errorf("%s: Undo restored\n%s\nwant\n%s", tc.label, got, dumpKeyboard(send.keyboards[0]))
		}
		want := []string{"s:🔕 Snoozed for " + strings.TrimPrefix(tc.label, "🔕 "), "u1:🔔 Alerts are on again", "u2:🔔 Alerts are on again"}
		if !slices.Equal(send.answered, want) {
			t.Errorf("%s: answered %v", tc.label, send.answered)
		}
		// The alert's text is a record: never edited, nothing new sent.
		if len(send.edits) != 0 || !slices.Equal(send.all(), sent) {
			t.Errorf("%s: alert edited %v or sent %v", tc.label, send.edits, send.all())
		}
	}
}

// A plain login alert keeps its source row through snooze and Undo.
func TestSnoozeKeepsLoginKeyboard(t *testing.T) {
	send := &fakeSender{}
	a := testAgent(send)
	ctx := context.Background()
	a.handleAuthLine(ctx, "Accepted publickey for alice from 203.0.113.9 port 22 ssh2", time.Now())
	sentKB := lastKeyboard(send)
	alertID := int64(1000 + len(send.all())) // fakeSender numbers messages from 1001
	press := func(data string) {
		a.handleCallback(ctx, &telegram.Callback{ID: "c", ChatID: 42, ChatType: "private", FromID: 42, MessageID: alertID, Data: data})
	}
	press(buttonData(sentKB, "🔕 8h"))
	kb := send.markups[0].kb
	if len(kb) != 3 || buttonData(kb, "🤝 Trust this IP") == "" || !strings.HasPrefix(kb[2][0].Text, "🔔 Snoozed until") {
		t.Fatalf("snoozed login keyboard:\n%s", dumpKeyboard(kb))
	}
	press(kb[2][0].Data)
	if got := dumpKeyboard(send.markups[1].kb); got != dumpKeyboard(sentKB) {
		t.Errorf("after Undo:\n%s\nwant\n%s", got, dumpKeyboard(sentKB))
	}
}

// Snooze buttons carry the key itself, escaped, so they survive a
// restart; a key too long for that falls back to a digest.
func TestSnoozeButtonsSurviveRestart(t *testing.T) {
	before := testAgent(&fakeSender{})
	for _, key := range []string{"ssh-login:alice@2001:db8::1", "docker:api", "ssh-newkey:bob SHA256:ab+c/d*e", "keys:/root/.ssh/authorized_keys"} {
		data := buttonData(before.alertKeyboard(key), "🔕 24h")
		c, err := tgui.Decode(data)
		if err != nil || c.Act != cfgSnooze || c.Args[1] != snoozeKeyed {
			t.Fatalf("%q: data %q (%v)", key, data, err)
		}
		// A fresh agent has no digests, just as after a restart.
		after := testAgent(&fakeSender{})
		after.handleCallback(context.Background(), &telegram.Callback{ID: "cb", ChatID: 42, MessageID: 1, Data: data})
		if !snoozed(after, key, time.Now()) {
			t.Errorf("%q: not snoozed after restart (data %q)", key, data)
		}
	}
	long := "disk:/var/lib/docker/overlay2/0123456789abcdef0123456789abcdef/merged"
	data := buttonData(before.alertKeyboard(long), "🔕 24h")
	if len(data) > tgui.MaxData || !strings.HasPrefix(data, "~1sz|24h|h|") {
		t.Fatalf("long key data = %q", data)
	}
	before.handleCallback(context.Background(), &telegram.Callback{ID: "cb", ChatID: 42, MessageID: 1, Data: data})
	if !snoozed(before, long, time.Now()) {
		t.Error("long key not snoozed")
	}
	send := &fakeSender{}
	after := testAgent(send)
	after.handleCallback(context.Background(), &telegram.Callback{ID: "cb", ChatID: 42, MessageID: 1, Data: data})
	if !slices.Equal(send.answered, []string{"cb:" + staleSnoozeToast}) || snoozed(after, long, time.Now()) {
		t.Errorf("hashed key after restart: answered %v", send.answered)
	}
}

func TestSnoozeKeyEscaping(t *testing.T) {
	for _, key := range []string{"cpu", "ssh-login:alice@203.0.113.9", "a b*c", "é", "x%2Ay"} {
		esc := escapeKey(key)
		for i := 0; i < len(esc); i++ {
			if c := esc[i]; !keyArgByte(c) && c != '*' {
				t.Errorf("%q escapes to %q with %q", key, esc, c)
			}
		}
		if got, ok := unescapeKey(esc); !ok || got != key {
			t.Errorf("%q round-trips to %q, %v", key, got, ok)
		}
	}
	// Only escapeKey's own output decodes: one form per key.
	for _, s := range []string{"", "*", "*4", "*4g", "*40x*", "*61", "a*2a", "a**"} {
		if got, ok := unescapeKey(s); ok {
			t.Errorf("unescapeKey(%q) = %q", s, got)
		}
	}
}

// Forged snooze data is refused without snoozing anything.
func TestSnoozeForged(t *testing.T) {
	for _, data := range []string{"~1sz", "~1sz|2h|k|cpu", "~1sz|1h|k", "~1sz|1h|x|cpu", "~1sz|1h|k|cp*75", "~1sz|1h|h|xyz",
		"~1sz|1h|k|cpu|x", "~1uz", "~1uz|k", "~1uz|q|cpu"} {
		send := &fakeSender{}
		a := testAgent(send)
		press(a, "c", data)
		if !slices.Equal(send.answered, []string{"c:" + outdatedToast}) || snoozed(a, "cpu", time.Now()) || len(send.markups) != 0 {
			t.Errorf("%q: answered %v, markups %v", data, send.answered, send.markups)
		}
	}
}

// Snooze changes the bot's settings: group viewers are refused.
func TestSnoozeNeedsAdmin(t *testing.T) {
	send := &fakeSender{}
	a, _ := authAgent(t, send, -100, 7)
	data := buttonData(a.alertKeyboard("cpu"), "🔕 1h")
	a.handleCallback(context.Background(), &telegram.Callback{ID: "v", ChatID: -100, ChatType: "supergroup", FromID: 5, MessageID: 3, Data: data})
	if snoozed(a, "cpu", time.Now()) || !slices.Equal(send.answered, []string{"v:" + adminOnlyToast}) {
		t.Errorf("viewer snoozed: answered %v", send.answered)
	}
}

// The snooze buttons of older versions still snooze, for an hour.
func TestSnoozeShortKeySurvivesRestart(t *testing.T) {
	// A fresh agent has no hash map entries, just as after a restart.
	send := &fakeSender{}
	after := testAgent(send)
	after.handleCallback(context.Background(), &telegram.Callback{
		ID: "cb", ChatID: 42, MessageID: 1, Data: "snz:d:docker:api",
	})
	if al := after.engine.Event("docker:api", "t", "b", alert.Warning, time.Now(), 0); al != nil {
		t.Fatalf("short key should be snoozed after restart, got %+v", al)
	}
}

func TestSnoozeLegacyHashedDigest(t *testing.T) {
	send := &fakeSender{}
	a := testAgent(send)
	long := "docker-restart:myproject-very-long-service-name-worker-queue-1"
	// The digest is issued when an alert keyboard for the key is built.
	a.alertKeyboard(long)
	a.handleCallback(context.Background(), &telegram.Callback{ID: "cb", ChatID: 42, MessageID: 1, Data: "snz:h:" + callbackDigest(long)})
	if al := a.engine.Event(long, "t", "b", alert.Warning, time.Now(), 0); al != nil {
		t.Fatalf("long key should be snoozed, got %+v", al)
	}
}

func TestSnoozeStaleHash(t *testing.T) {
	send := &fakeSender{}
	a := testAgent(send)
	ctx := context.Background()
	a.handleCallback(ctx, &telegram.Callback{ID: "cb", ChatID: 42, MessageID: 1, Data: "snz:h:deadbeefdeadbeef"})
	send.mu.Lock()
	answered := append([]string(nil), send.answered...)
	send.mu.Unlock()
	if len(answered) == 0 || !strings.Contains(answered[0], "stale snooze") {
		t.Fatalf("want stale snooze toast, got %v", answered)
	}
}

func TestSnoozeLegacyDirectCallback(t *testing.T) {
	send := &fakeSender{}
	a := testAgent(send)
	ctx := context.Background()
	// Pre-#69 wire format: snz:<key> (no d: namespace).
	a.handleCallback(ctx, &telegram.Callback{ID: "cb", ChatID: 42, MessageID: 1, Data: "snz:cpu"})
	send.mu.Lock()
	answered := append([]string(nil), send.answered...)
	send.mu.Unlock()
	if len(answered) == 0 || !strings.Contains(answered[0], "Snoozed for 1h") {
		t.Fatalf("legacy direct snooze toast = %v", answered)
	}
	if al := a.engine.Event("cpu", "t", "b", alert.Warning, time.Now(), 0); al != nil {
		t.Fatalf("legacy snz:cpu should snooze, got %+v", al)
	}
}

func TestSnoozeLegacyHashedCallback(t *testing.T) {
	send := &fakeSender{}
	a := testAgent(send)
	ctx := context.Background()
	long := "docker-restart:myproject-very-long-service-name-worker-queue-1"
	crc := legacyCRC32Hex(long)
	a.mu.Lock()
	a.snoozeKeys[crc] = long
	a.mu.Unlock()

	data := "snz:h" + crc
	if len(data) != len("snz:h")+8 {
		t.Fatalf("legacy hashed callback shape = %q", data)
	}
	a.handleCallback(ctx, &telegram.Callback{ID: "cb", ChatID: 42, MessageID: 1, Data: data})
	if al := a.engine.Event(long, "t", "b", alert.Warning, time.Now(), 0); al != nil {
		t.Fatalf("legacy snz:hCRC32 should snooze long key, got %+v", al)
	}
}

// New keyboards emit only the "~1" snooze forms.
func TestSnoozeEmitOnlyNewForms(t *testing.T) {
	a := testAgent(&fakeSender{})
	for _, key := range []string{"cpu", "docker-restart:myproject-very-long-service-name-worker-queue-1-and-then-some"} {
		for _, b := range a.alertKeyboard(key)[1] {
			if !strings.HasPrefix(b.Data, "~1sz|") {
				t.Errorf("%q: snooze button %q sends %q", key, b.Text, b.Data)
			}
		}
	}
}
