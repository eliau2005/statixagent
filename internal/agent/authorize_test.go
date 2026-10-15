package agent

import (
	"context"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/eliau2005/statixagent/internal/bot"
	"github.com/eliau2005/statixagent/internal/telegram"
)

// authAgent builds a test agent for chatID with the given admins and a
// "/act" command that changes state, returning its run counter.
func authAgent(t *testing.T, send *fakeSender, chatID int64, admins ...int64) (*Agent, *int) {
	t.Helper()
	cfg := testConfig()
	cfg.Telegram.ChatID = chatID
	cfg.Telegram.AdminUserIDs = admins
	src := testAgent(send).src
	src.OffsetPath = filepath.Join(t.TempDir(), "tg-offset")
	a := New(cfg, send, nil, src)
	return a, countHandler(a, "act")
}

func TestAuthorizePrivateChatRequiresOwner(t *testing.T) {
	ctx := context.Background()
	send := &fakeSender{}
	a, acts := authAgent(t, send, 42)

	a.handleUpdate(ctx, telegram.Update{ID: 1, ChatID: 42, ChatType: "private", FromID: 99, Text: "/act"})
	a.handleUpdate(ctx, telegram.Update{ID: 2, ChatID: 42, ChatType: "private", FromID: 99, Text: "/status"})
	a.handleCallback(ctx, &telegram.Callback{ID: "c1", ChatID: 42, ChatType: "private", FromID: 99, MessageID: 4, Data: "cpu"})
	if *acts != 0 || len(send.all()) != 0 || len(send.edits) != 0 || len(send.answered) != 0 {
		t.Fatalf("foreign sender got through: acts=%d sent=%v edits=%v answered=%v", *acts, send.all(), send.edits, send.answered)
	}

	// The chat's own user, the only sender Telegram allows there, works as before.
	a.handleUpdate(ctx, telegram.Update{ID: 3, ChatID: 42, ChatType: "private", FromID: 42, Text: "/act"})
	a.handleCallback(ctx, &telegram.Callback{ID: "c2", ChatID: 42, ChatType: "private", FromID: 42, MessageID: 4, Data: "cpu"})
	if *acts != 1 || len(send.edits) != 1 || !slices.Equal(send.answered, []string{"c2:"}) {
		t.Errorf("owner: acts=%d edits=%d answered=%v", *acts, len(send.edits), send.answered)
	}
}

func TestAuthorizeIgnoresRelayedCommands(t *testing.T) {
	ctx := context.Background()
	send := &fakeSender{}
	a, _ := authAgent(t, send, 42)
	ran := 0
	a.router.Handle("update_confirm", bot.Text(func(context.Context, []string) string { ran++; return "installing" }))

	base := telegram.Update{ChatID: 42, ChatType: "private", FromID: 42, Text: "/update_confirm"}
	for name, mod := range map[string]func(*telegram.Update){
		"forwarded":   func(u *telegram.Update) { u.Forwarded = true },
		"via bot":     func(u *telegram.Update) { u.ViaBot = true },
		"sender chat": func(u *telegram.Update) { u.SenderChat = true },
	} {
		u := base
		mod(&u)
		a.handleUpdate(ctx, u)
		if ran != 0 || len(send.all()) != 0 {
			t.Fatalf("%s /update_confirm ran=%d sent=%v", name, ran, send.all())
		}
	}
	a.handleUpdate(ctx, base)
	if ran != 1 {
		t.Errorf("direct /update_confirm ran %d times, want 1", ran)
	}
}

func TestAuthorizeChatCheckFirst(t *testing.T) {
	ctx := context.Background()
	send := &fakeSender{}
	a, acts := authAgent(t, send, -100)
	// A foreign group never gets the admin notice nor any answer.
	a.handleUpdate(ctx, telegram.Update{ChatID: -200, ChatType: "group", FromID: 5, Text: "/act"})
	a.handleCallback(ctx, &telegram.Callback{ID: "c1", ChatID: -200, ChatType: "group", FromID: 5, Data: "cpu", Inaccessible: true})
	if *acts != 0 || len(send.all()) != 0 || len(send.answered) != 0 || a.groupNoticeSent {
		t.Errorf("foreign chat: acts=%d sent=%v answered=%v notice=%v", *acts, send.all(), send.answered, a.groupNoticeSent)
	}
}

func TestAuthorizeGroupWithoutAdmins(t *testing.T) {
	ctx := context.Background()
	send := &fakeSender{}
	a, acts := authAgent(t, send, -100)

	a.handleUpdate(ctx, telegram.Update{ID: 1, ChatID: -100, ChatType: "supergroup", FromID: 5, Text: "/act"})
	a.handleUpdate(ctx, telegram.Update{ID: 2, ChatID: -100, ChatType: "supergroup", FromID: 6, Text: "/act"})
	a.handleCallback(ctx, &telegram.Callback{ID: "c1", ChatID: -100, ChatType: "supergroup", FromID: 7, MessageID: 4, Data: "settings"})
	if *acts != 2 || len(send.edits) != 1 {
		t.Errorf("members must keep full access for now: acts=%d edits=%d", *acts, len(send.edits))
	}
	notices := 0
	for _, s := range send.all() {
		if strings.Contains(s, "admin_user_ids") {
			notices++
		}
	}
	if notices != 1 {
		t.Errorf("admin_user_ids notice sent %d times, want once: %v", notices, send.all())
	}
}

func TestAuthorizeGroupAdmins(t *testing.T) {
	ctx := context.Background()
	send := &fakeSender{}
	a, acts := authAgent(t, send, -100, 7)
	msg := func(from int64, text string) telegram.Update {
		return telegram.Update{ChatID: -100, ChatType: "group", FromID: from, Text: text}
	}

	a.handleUpdate(ctx, msg(5, "/act"))
	if *acts != 0 || len(send.all()) != 1 || !strings.Contains(send.all()[0], "⛔") {
		t.Fatalf("non-admin /act: acts=%d sent=%v", *acts, send.all())
	}
	// Views stay open to every member; arguments that change state do not.
	a.handleUpdate(ctx, msg(5, "/status"))
	a.handleUpdate(ctx, msg(5, "/ssl add example.com"))
	if sent := send.all(); len(sent) != 3 || strings.Contains(sent[1], "⛔") || !strings.Contains(sent[2], "⛔") {
		t.Errorf("non-admin view/ssl add: %v", sent)
	}
	a.handleUpdate(ctx, msg(7, "/act"))
	if *acts != 1 {
		t.Errorf("admin /act ran %d times, want 1", *acts)
	}
	if a.groupNoticeSent {
		t.Error("notice sent although admin_user_ids is set")
	}

	press := func(id string, from int64, data string) {
		a.handleCallback(ctx, &telegram.Callback{ID: id, ChatID: -100, ChatType: "group", FromID: from, MessageID: 4, Data: data})
	}
	press("c1", 5, "cpu")      // navigation view: allowed
	press("c2", 5, "settings") // anything else: admins only
	press("c3", 5, "fw_close")
	press("c4", 7, "settings")
	want := []string{"c1:", "c2:" + adminOnlyToast, "c3:" + adminOnlyToast, "c4:"}
	if !slices.Equal(send.answered, want) || len(send.edits) != 2 {
		t.Errorf("answered = %v (want %v), edits = %d (want 2)", send.answered, want, len(send.edits))
	}
}

func TestInaccessibleCallbackAnswered(t *testing.T) {
	ctx := context.Background()
	send := &fakeSender{}
	a, _ := authAgent(t, send, 42)
	a.handleCallback(ctx, &telegram.Callback{ID: "c1", ChatID: 42, ChatType: "private", FromID: 42, MessageID: 4, Data: "fw_close", Inaccessible: true})
	if !slices.Equal(send.answered, []string{"c1:" + inaccessibleToast}) || len(send.edits) != 0 || len(send.all()) != 0 {
		t.Errorf("answered = %v, edits = %v, sent = %v", send.answered, send.edits, send.all())
	}
	// With no message at all the chat is unknown, so the press stays unanswered.
	a.handleCallback(ctx, &telegram.Callback{ID: "c2", FromID: 42, Data: "cpu", Inaccessible: true})
	if len(send.answered) != 1 {
		t.Errorf("chatless press answered: %v", send.answered)
	}
}
