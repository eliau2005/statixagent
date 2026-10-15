package agent

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/eliau2005/statixagent/internal/telegram"
	"github.com/eliau2005/statixagent/internal/tgui"
)

// unlimitPresses lifts the press limit for a test that walks more screens
// in a moment than any person could tap.
func unlimitPresses(a *Agent) {
	a.presses = &pressLimiter{burst: 1 << 20, every: time.Second}
}

func TestPressLimiterBuckets(t *testing.T) {
	t0 := time.Date(2026, 10, 15, 14, 5, 0, 0, time.UTC)
	l := &pressLimiter{burst: 3, every: time.Second}
	steps := []struct {
		actor int64
		at    time.Duration
		want  bool
	}{
		{1, 0, true}, {1, 0, true}, {1, 0, true},
		{1, 0, false},                      // burst spent
		{2, 0, true},                       // another actor has its own bucket
		{1, 500 * time.Millisecond, false}, // half a press refilled
		{1, time.Second, true},             // one press refilled
		{1, time.Second, false},
		{1, 10 * time.Second, true}, // full again, never above the burst
		{1, 10 * time.Second, true},
		{1, 10 * time.Second, true},
		{1, 10 * time.Second, false},
	}
	for i, s := range steps {
		if got := l.allow(s.actor, t0.Add(s.at)); got != s.want {
			t.Errorf("step %d: actor %d at +%v allowed = %v, want %v", i, s.actor, s.at, got, s.want)
		}
	}
	// Actor 2's bucket refilled long ago, so it was dropped.
	if _, ok := l.actors[2]; ok || len(l.actors) != 1 {
		t.Errorf("actors = %v, want only actor 1", l.actors)
	}
}

// TestPressRateLimitToast: past the burst a press only gets the toast;
// confirm presses count and are audited, their token stays usable, and a
// foreign chat is neither answered nor counted.
func TestPressRateLimitToast(t *testing.T) {
	send := &fakeSender{}
	a := testAgent(send)
	now := time.Date(2026, 10, 15, 14, 5, 0, 0, time.UTC)
	a.now = func() time.Time { return now }
	path := filepath.Join(t.TempDir(), "audit", "actions.jsonl")
	a.audit = newAuditLog(path)
	ctx := context.Background()
	at := func(id, data string) {
		a.handleCallback(ctx, &telegram.Callback{ID: id, ChatID: 42, ChatType: "private", FromID: 42, MessageID: 4, Data: data})
	}

	for range 20 {
		a.handleCallback(ctx, &telegram.Callback{ID: "foreign", ChatID: 99, FromID: 99, MessageID: 4, Data: "~1v|cpu"})
	}
	at("ask", "~1cc") // a confirm screen: one press
	no := tokenData(lastEditKB(send), tgui.ActNo)
	if no == "" {
		t.Fatal("clear-chat ask showed no Cancel button")
	}
	for range pressBurst - 2 {
		at("view", "~1v|cpu")
	}
	at("legacy", "cpu") // legacy data counts too: the burst is spent
	edits := send.editCount()
	at("over", "~1v|cpu")
	at("no", no)
	if send.editCount() != edits {
		t.Error("a press over the limit edited the message")
	}
	now = now.Add(pressEvery)
	at("later", no)

	send.mu.Lock()
	answered := send.answered
	send.mu.Unlock()
	if len(answered) != pressBurst+3 {
		t.Errorf("answered %d presses, want %d: %v", len(answered), pressBurst+3, answered)
	}
	tail := strings.Join(answered[max(0, len(answered)-4):], " | ")
	if want := "legacy: | over:" + slowDownToast + " | no:" + slowDownToast + " | later:Cancelled"; tail != want {
		t.Errorf("last answers = %q, want %q", tail, want)
	}
	for _, ans := range answered {
		if strings.HasPrefix(ans, "foreign") {
			t.Errorf("a foreign chat was answered: %v", answered)
		}
	}

	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var phases []string
	for line := range strings.SplitSeq(strings.TrimSpace(string(raw)), "\n") {
		var r auditRecord
		if err := json.Unmarshal([]byte(line), &r); err != nil {
			t.Fatalf("line %q: %v", line, err)
		}
		phases = append(phases, r.Phase)
		if r.Phase == phaseRateLimited && (r.NonceHash != nonceHash(strings.TrimPrefix(no, "~1n|")) || r.ActorID != 42 || r.MessageID != 4) {
			t.Errorf("rate-limited record = %+v", r)
		}
	}
	if got, want := strings.Join(phases, " "), "requested rate_limited cancelled"; got != want {
		t.Errorf("phases = %s, want %s", got, want)
	}
}
