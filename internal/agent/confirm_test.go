package agent

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/eliau2005/statixagent/internal/sshwatch"
	"github.com/eliau2005/statixagent/internal/telegram"
	"github.com/eliau2005/statixagent/internal/tgui"
)

// tokenData returns the data of kb's Yes (act "y") or Cancel (act "n")
// button, or "" when it has none.
func tokenData(kb telegram.Keyboard, act string) string {
	for _, row := range kb {
		for _, b := range row {
			if strings.HasPrefix(b.Data, "~1"+act+"|") {
				return b.Data
			}
		}
	}
	return ""
}

// lastEditKB is the keyboard of the last edit, nil when there is none.
func lastEditKB(send *fakeSender) telegram.Keyboard {
	send.mu.Lock()
	defer send.mu.Unlock()
	if len(send.edits) == 0 {
		return nil
	}
	return send.edits[len(send.edits)-1].kb
}

// lastSentID is the message ID the fake gave the last message sent.
func lastSentID(send *fakeSender) int64 {
	send.mu.Lock()
	defer send.mu.Unlock()
	return send.nextID + 1000
}

// confirmThrough presses askData on message msg, then every Yes the
// confirm screens offer: one, or two for a double confirm. The presses
// have IDs "ask", "yes1" and "yes2"; it returns the last Yes's ID.
func confirmThrough(t *testing.T, a *Agent, send *fakeSender, askData string, msg int64) string {
	t.Helper()
	ctx := context.Background()
	a.handleCallback(ctx, &telegram.Callback{ID: "ask", ChatID: 42, MessageID: msg, Data: askData})
	id := ""
	for i := 1; ; i++ {
		yes := tokenData(lastEditKB(send), tgui.ActYes)
		if yes == "" {
			break
		}
		if i > 2 {
			t.Fatalf("%q asked more than twice", askData)
		}
		id = fmt.Sprintf("yes%d", i)
		a.handleCallback(ctx, &telegram.Callback{ID: id, ChatID: 42, MessageID: msg, Data: yes})
	}
	if id == "" {
		t.Fatalf("%q offered no Yes: %+v", askData, lastEditKB(send))
	}
	return id
}

// kickAgent has alice and bob logged in, a pkill that succeeds, and a
// clock fixed at noon UTC.
func kickAgent(t *testing.T, live *[]sshwatch.Session) (*Agent, *fakeSender, *kickRunner) {
	t.Helper()
	send := &fakeSender{}
	a := testAgent(send)
	runner := &kickRunner{}
	a.src.Runner = runner
	a.src.Sessions = sessionsFrom(live)
	noon := time.Date(2026, 10, 15, 12, 0, 0, 0, time.UTC)
	a.now = func() time.Time { return noon }
	return a, send, runner
}

// TestConfirmTokenSuite is §4.4's token suite, end to end: a Yes runs
// only for the user who asked, on the message it was shown on, within
// the TTL, once, in this boot, and only on the target it was asked for.
func TestConfirmTokenSuite(t *testing.T) {
	alice, bob := sshTestSessions()[0], sshTestSessions()[1]
	ask := sessionCallbackData("sk:", 1, alice)
	cases := []struct {
		name string
		// press runs between the ask (message 7, user 0) and the Yes;
		// it may change the Yes press.
		press     func(a *Agent, live *[]sshwatch.Session, cb *telegram.Callback)
		wantKill  bool
		wantToast string // the Yes press's answer
		wantText  string // in the last edit; "" = not checked
	}{
		{"asker on its message", func(*Agent, *[]sshwatch.Session, *telegram.Callback) {},
			true, "Working…", "🧾 alice disconnected"},
		{"expired", func(a *Agent, _ *[]sshwatch.Session, _ *telegram.Callback) {
			later := a.now().Add(tgui.TokenTTL + time.Second)
			a.now = func() time.Time { return later }
		}, false, staleToast, staleText},
		{"wrong message", func(_ *Agent, _ *[]sshwatch.Session, cb *telegram.Callback) {
			cb.MessageID = 8
		}, false, staleToast, staleText},
		{"wrong actor", func(_ *Agent, _ *[]sshwatch.Session, cb *telegram.Callback) {
			cb.FromID = 99
		}, false, wrongActorToast, ""},
		{"previous boot", func(a *Agent, _ *[]sshwatch.Session, _ *telegram.Callback) {
			// A restart: the store and its epoch are new.
			a.tokens = tgui.NewTokens(a.now, strings.NewReader(strings.Repeat("\xa5", 64)))
		}, false, staleToast, staleText},
		{"target drift", func(_ *Agent, live *[]sshwatch.Session, _ *telegram.Callback) {
			re := alice
			re.Since = re.Since.Add(time.Minute) // alice logged out; a new login on pts/0
			*live = []sshwatch.Session{re, bob}
		}, false, "Working…", sessionGoneToast},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			live := []sshwatch.Session{alice, bob}
			a, send, runner := kickAgent(t, &live)
			ctx := context.Background()
			a.handleCallback(ctx, &telegram.Callback{ID: "ask", ChatID: 42, MessageID: 7, Data: ask})
			cb := &telegram.Callback{ID: "yes", ChatID: 42, MessageID: 7, Data: tokenData(lastEditKB(send), tgui.ActYes)}
			if cb.Data == "" {
				t.Fatal("ask offered no Yes")
			}
			tc.press(a, &live, cb)
			a.handleCallback(ctx, cb)
			if killed := len(runner.calls) > 0; killed != tc.wantKill {
				t.Fatalf("pkill ran = %v (%v), want %v", killed, runner.calls, tc.wantKill)
			}
			send.mu.Lock()
			answers := slices.DeleteFunc(slices.Clone(send.answered), func(s string) bool { return !strings.HasPrefix(s, "yes:") })
			send.mu.Unlock()
			if !slices.Equal(answers, []string{"yes:" + tc.wantToast}) {
				t.Errorf("answers = %v, want one %q", answers, tc.wantToast)
			}
			if tc.wantText != "" && !strings.Contains(send.lastEdit().html, tc.wantText) {
				t.Errorf("last edit = %q, want %q", send.lastEdit().html, tc.wantText)
			}
		})
	}
}

// TestConfirmDoubleTap: the second tap on the same Yes never acts again.
func TestConfirmDoubleTap(t *testing.T) {
	live := sshTestSessions()
	a, send, runner := kickAgent(t, &live)
	yes1 := confirmThrough(t, a, send, sessionCallbackData("sk:", 1, live[0]), 7)
	send.mu.Lock()
	yes := ""
	for _, e := range send.edits {
		if d := tokenData(e.kb, tgui.ActYes); d != "" {
			yes = d
		}
	}
	send.mu.Unlock()
	a.handleCallback(context.Background(), &telegram.Callback{ID: "again", ChatID: 42, MessageID: 7, Data: yes})
	if len(runner.calls) != 1 {
		t.Fatalf("pkill calls = %v, want exactly one", runner.calls)
	}
	send.mu.Lock()
	defer send.mu.Unlock()
	if got := send.answered[len(send.answered)-1]; got != "again:"+doneToast {
		t.Errorf("second tap answered %q (after %s)", got, yes1)
	}
}

// TestKickOnlySessionDoubleConfirm: kicking the only session listed (it
// may be the user's own) takes a second, differently worded confirm.
func TestKickOnlySessionDoubleConfirm(t *testing.T) {
	live := sshTestSessions()[:1]
	a, send, runner := kickAgent(t, &live)
	ctx := context.Background()
	a.handleCallback(ctx, &telegram.Callback{ID: "ask", ChatID: 42, MessageID: 7, Data: sessionCallbackData("sk:", 1, live[0])})
	yes1 := tokenData(lastEditKB(send), tgui.ActYes)
	a.handleCallback(ctx, &telegram.Callback{ID: "yes1", ChatID: 42, MessageID: 7, Data: yes1})
	if len(runner.calls) != 0 {
		t.Fatalf("first Yes ran pkill: %v", runner.calls)
	}
	second := send.lastEdit()
	yes2 := tokenData(second.kb, tgui.ActYes)
	if !strings.Contains(second.html, "only SSH session") || yes2 == "" || yes2 == yes1 || second.kb[0][0].Text != "✅ Yes, cut the only session" {
		t.Fatalf("second confirm = %q %+v", second.html, second.kb)
	}
	// The first token is spent: pressing it again does not skip a step.
	a.handleCallback(ctx, &telegram.Callback{ID: "old", ChatID: 42, MessageID: 7, Data: yes1})
	a.handleCallback(ctx, &telegram.Callback{ID: "yes2", ChatID: 42, MessageID: 7, Data: yes2})
	if len(runner.calls) != 1 {
		t.Fatalf("pkill calls = %v", runner.calls)
	}
	if out := slowOutcome(t, send, "yes2"); !strings.Contains(out, "alice disconnected") {
		t.Errorf("outcome = %q", out)
	}

	// With two sessions listed one confirm is enough.
	live = sshTestSessions()
	a, send, runner = kickAgent(t, &live)
	if id := confirmThrough(t, a, send, sessionCallbackData("sk:", 2, live[1]), 7); id != "yes1" || len(runner.calls) != 1 {
		t.Errorf("two sessions: last Yes %s, pkill %v", id, runner.calls)
	}
}

// TestLegacyDestructiveDataReprompts: Yes buttons of older versions carry
// the action itself. They only ever open a fresh confirm screen.
func TestLegacyDestructiveDataReprompts(t *testing.T) {
	alice := sshTestSessions()[0]
	cases := []struct{ data, want, toast string }{
		{sessionCallbackData("skk:", 1, alice), "Disconnect SSH session?", reconfirmToast},
		{"skk:1", "Disconnect SSH session?", reconfirmToast},
		{"fw_open", "Open SSH port 22?", reconfirmToast},
		{"fw_close", "Close SSH port 22?", reconfirmToast},
		{cbUpdateYes, "Install the update?", reconfirmToast},
		{cbClearYes, "Delete recent messages?", reconfirmToast},
		{"update_confirm", "Install the update?", ""},
	}
	for _, tc := range cases {
		t.Run(tc.data, func(t *testing.T) {
			live := sshTestSessions()
			a, send, runner := kickAgent(t, &live)
			a.cfg.Firewall.AllowCloseSSH = true
			applied := false
			a.src.UpdateCheck = func(context.Context) (string, bool, error) { return "v2", true, nil }
			a.src.UpdateApply = func(context.Context) error { applied = true; return nil }
			a.handleCallback(context.Background(), &telegram.Callback{ID: "c1", ChatID: 42, MessageID: 5, Data: tc.data})
			send.mu.Lock()
			defer send.mu.Unlock()
			if len(runner.calls) != 0 || applied || len(send.deleted) != 0 {
				t.Fatalf("legacy %q acted: runs=%v applied=%v deleted=%d", tc.data, runner.calls, applied, len(send.deleted))
			}
			if len(send.edits) != 1 || !strings.Contains(send.edits[0].html, tc.want) ||
				tokenData(send.edits[0].kb, tgui.ActYes) == "" || tokenData(send.edits[0].kb, tgui.ActNo) == "" {
				t.Fatalf("edits = %+v, want a fresh confirm screen", send.edits)
			}
			if !slices.Equal(send.answered, []string{"c1:" + tc.toast}) {
				t.Errorf("answered = %v", send.answered)
			}
		})
	}
}

// TestConfirmReceipt: the confirm message becomes a receipt of what ran,
// on what, by whom, when and how it ended.
func TestConfirmReceipt(t *testing.T) {
	live := sshTestSessions()
	a, send, _ := kickAgent(t, &live)
	id := confirmThrough(t, a, send, sessionCallbackData("sk:", 1, live[0]), 7)
	out := slowOutcome(t, send, id)
	first, rest, _ := strings.Cut(out, "\n")
	if !strings.HasPrefix(first, "🧾 alice disconnected · alice pts/0 from 10.0.0.5 · by 0 · 12:00:00 UTC · ") || !strings.HasSuffix(first, "s · ok") {
		t.Errorf("receipt = %q", first)
	}
	if !strings.Contains(rest, "Active sessions") {
		t.Errorf("the view follows the receipt: %q", rest)
	}

	send = &fakeSender{}
	a = testAgent(send)
	a.src.Runner = failingUFW{}
	allowFw(t, a)
	id = confirmThrough(t, a, send, "fw_open_ask", 4)
	if first, _, _ := strings.Cut(slowOutcome(t, send, id), "\n"); !strings.HasPrefix(first, "🧾 Firewall change failed · port 22/tcp · by 0 · ") ||
		!strings.HasSuffix(first, " · failed") {
		t.Errorf("failure receipt = %q", first)
	}
}

// TestConfirmCancel: Cancel spends the token and returns to the view.
func TestConfirmCancel(t *testing.T) {
	live := sshTestSessions()
	a, send, runner := kickAgent(t, &live)
	ctx := context.Background()
	a.handleCallback(ctx, &telegram.Callback{ID: "ask", ChatID: 42, MessageID: 7, Data: sessionCallbackData("sk:", 1, live[0])})
	kb := lastEditKB(send)
	a.handleCallback(ctx, &telegram.Callback{ID: "stranger", ChatID: 42, FromID: 99, MessageID: 7, Data: tokenData(kb, tgui.ActNo)})
	a.handleCallback(ctx, &telegram.Callback{ID: "no", ChatID: 42, MessageID: 7, Data: tokenData(kb, tgui.ActNo)})
	if !strings.Contains(send.lastEdit().html, "Active sessions") {
		t.Errorf("Cancel edit = %q", send.lastEdit().html)
	}
	a.handleCallback(ctx, &telegram.Callback{ID: "yes", ChatID: 42, MessageID: 7, Data: tokenData(kb, tgui.ActYes)})
	if len(runner.calls) != 0 || !strings.Contains(send.lastEdit().html, staleText) {
		t.Errorf("Yes after Cancel: pkill %v, edit %q", runner.calls, send.lastEdit().html)
	}
	// A Cancel after a restart has nothing to undo.
	a.handleCallback(ctx, &telegram.Callback{ID: "old", ChatID: 42, MessageID: 7, Data: "~1n|AAAAAAAAAAAA"})
	send.mu.Lock()
	defer send.mu.Unlock()
	want := []string{"ask:", "stranger:" + wrongActorToast, "no:Cancelled", "yes:" + staleToast, "old:"}
	if !slices.Equal(send.answered, want) {
		t.Errorf("answered = %v, want %v", send.answered, want)
	}
	if last := send.edits[len(send.edits)-1]; last.html != cancelledText {
		t.Errorf("stale Cancel edit = %q", last.html)
	}
}

// TestConfirmGroupActor: in a group only the admin who asked may press
// Yes (Decision 3); another admin is refused and the token stays good.
func TestConfirmGroupActor(t *testing.T) {
	ctx := context.Background()
	send := &fakeSender{}
	a, _ := authAgent(t, send, -100, 7, 8)
	applied := 0
	a.src.UpdateCheck = func(context.Context) (string, bool, error) { return "v2", true, nil }
	a.src.UpdateApply = func(context.Context) error { applied++; return nil }
	press := func(id string, from int64, data string) {
		a.handleCallback(ctx, &telegram.Callback{ID: id, ChatID: -100, ChatType: "supergroup", FromID: from, MessageID: 5, Data: data})
	}
	press("ask", 7, "update_confirm")
	yes := tokenData(lastEditKB(send), tgui.ActYes)
	press("member", 5, yes)
	press("other", 8, yes)
	a.handleCallback(ctx, &telegram.Callback{ID: "chat", ChatID: 666, ChatType: "supergroup", FromID: 7, MessageID: 5, Data: yes})
	if applied != 0 {
		t.Fatal("Yes ran for someone other than the asker")
	}
	press("asker", 7, yes)
	if applied != 1 {
		t.Fatalf("asker's Yes applied %d times", applied)
	}
	send.mu.Lock()
	defer send.mu.Unlock()
	want := []string{"ask:", "member:" + adminOnlyToast, "other:" + wrongActorToast, "asker:Working…"}
	if !slices.Equal(send.answered, want) {
		t.Errorf("answered = %v, want %v", send.answered, want)
	}
}

// TestTypedConfirmBoundToReply: a typed command's prompt is bound to the
// message it went out in and to the user who typed it.
func TestTypedConfirmBoundToReply(t *testing.T) {
	send := &fakeSender{}
	a := testAgent(send)
	a.src.OffsetPath = filepath.Join(t.TempDir(), "tg-offset")
	ctx := context.Background()
	a.handleUpdate(ctx, telegram.Update{ChatID: 42, ChatType: "private", FromID: 42, Text: "/clear_chat"})
	msg := lastSentID(send)
	yes := tokenData(lastKeyboard(send), tgui.ActYes)
	press := func(id string, msgID int64) {
		a.handleCallback(ctx, &telegram.Callback{ID: id, ChatID: 42, ChatType: "private", FromID: 42, MessageID: msgID, Data: yes})
	}
	press("elsewhere", msg+1)
	if len(send.deleted) != 0 {
		t.Fatal("Yes on another message cleared the chat")
	}
	press("here", msg)
	if len(send.deleted) != 301 {
		t.Fatalf("deleted %d, want 301", len(send.deleted))
	}
}

// TestConfirmFollowsEditFallback: when the confirm screen cannot be edited
// in and is sent as a new message, its token moves with it.
func TestConfirmFollowsEditFallback(t *testing.T) {
	send := &fakeSender{editErr: errors.New("Bad Request: message to edit not found")}
	a := testAgent(send)
	applied := 0
	a.src.UpdateCheck = func(context.Context) (string, bool, error) { return "v2", true, nil }
	a.src.UpdateApply = func(context.Context) error { applied++; return nil }
	ctx := context.Background()
	a.handleCallback(ctx, &telegram.Callback{ID: "ask", ChatID: 42, MessageID: 5, Data: "update_confirm"})
	yes := tokenData(lastKeyboard(send), tgui.ActYes)
	a.handleCallback(ctx, &telegram.Callback{ID: "old", ChatID: 42, MessageID: 5, Data: yes})
	if applied != 0 {
		t.Fatal("Yes ran on the message the screen never reached")
	}
	a.handleCallback(ctx, &telegram.Callback{ID: "new", ChatID: 42, MessageID: 1001, Data: yes})
	if applied != 1 {
		t.Errorf("Yes on the fallback message applied %d times", applied)
	}
}

// TestAuditTrail: every step lands in the audit file as JSON, the token
// and nonce never do, and the executed step carries the command.
func TestAuditTrail(t *testing.T) {
	live := sshTestSessions()
	a, send, _ := kickAgent(t, &live)
	path := filepath.Join(t.TempDir(), "audit", "actions.jsonl")
	a.audit = newAuditLog(path)
	ctx := context.Background()

	a.handleCallback(ctx, &telegram.Callback{ID: "ask", ChatID: 42, MessageID: 7, Data: sessionCallbackData("sk:", 1, live[0])})
	kb := lastEditKB(send)
	yes, no := tokenData(kb, tgui.ActYes), tokenData(kb, tgui.ActNo)
	a.handleCallback(ctx, &telegram.Callback{ID: "stranger", ChatID: 42, FromID: 99, MessageID: 7, Data: yes})
	a.handleCallback(ctx, &telegram.Callback{ID: "yes", ChatID: 42, MessageID: 7, Data: yes})
	a.handleCallback(ctx, &telegram.Callback{ID: "again", ChatID: 42, MessageID: 7, Data: yes})
	a.handleCallback(ctx, &telegram.Callback{ID: "forged", ChatID: 42, MessageID: 7, Data: "~1y|" + a.tokens.Epoch() + "AAAAAAAAAAAA"})

	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	nonce := strings.TrimPrefix(no, "~1n|")
	for _, secret := range []string{nonce, strings.TrimPrefix(yes, "~1y|"), yes, no} {
		if bytes.Contains(raw, []byte(secret)) {
			t.Errorf("audit log contains token material %q:\n%s", secret, raw)
		}
	}
	var phases []string
	var executed auditRecord
	for line := range strings.SplitSeq(strings.TrimSpace(string(raw)), "\n") {
		var r auditRecord
		if err := json.Unmarshal([]byte(line), &r); err != nil {
			t.Fatalf("line %q: %v", line, err)
		}
		if r.BootEpoch != a.tokens.Epoch() || r.Action != actKick && r.Phase != phaseStale {
			t.Errorf("record %+v", r)
		}
		phases = append(phases, r.Phase)
		if r.Phase == phaseExecuted {
			executed = r
		}
	}
	want := []string{phaseRequested, phaseDenied, phaseConfirmed, phaseExecuted, phaseDenied, phaseStale}
	if !slices.Equal(phases, want) {
		t.Errorf("phases = %v, want %v", phases, want)
	}
	if !slices.Equal(executed.Argv, []string{"pkill", "-KILL", "-t", "pts/0"}) || executed.ExitCode == nil || *executed.ExitCode != 0 ||
		executed.NonceHash != nonceHash(nonce) || len(executed.OutputSHA256) != 64 || executed.Target != "alice pts/0 from 10.0.0.5" ||
		executed.ActorID != 0 || executed.ChatID != 42 || executed.MessageID != 7 {
		t.Errorf("executed record = %+v", executed)
	}
}

// TestAuditFailureDoesNotBlock: an unwritable audit file is logged and
// the action still runs.
func TestAuditFailureDoesNotBlock(t *testing.T) {
	live := sshTestSessions()
	a, send, runner := kickAgent(t, &live)
	blocker := filepath.Join(t.TempDir(), "file")
	if err := os.WriteFile(blocker, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	a.audit = newAuditLog(filepath.Join(blocker, "audit", "actions.jsonl")) // a file where a directory must be
	confirmThrough(t, a, send, sessionCallbackData("sk:", 1, live[0]), 7)
	if len(runner.calls) != 1 {
		t.Errorf("pkill calls = %v", runner.calls)
	}
}
