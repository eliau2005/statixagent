package agent

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/eliau2005/statixagent/internal/telegram"
	"github.com/eliau2005/statixagent/internal/tgui"
)

// press sends one owner press of data in a private chat.
func press(a *Agent, id, data string) {
	a.handleCallback(context.Background(), &telegram.Callback{
		ID: id, ChatID: 42, ChatType: "private", FromID: 42, MessageID: 4, Data: data,
	})
}

func TestCallHomeToCPUAndBack(t *testing.T) {
	send := &fakeSender{}
	a := testAgent(send)
	status, _ := a.router.Invoke(context.Background(), "status", nil)
	cpu, _ := a.router.Invoke(context.Background(), "cpu", nil)

	press(a, "c1", "~1v|home")
	home := send.lastEdit()
	if home.html != status {
		t.Errorf("home text = %q, want the /status reply", home.html)
	}
	want := "[🖥 CPU] → ~1v|cpu\n[🔄 Refresh] → ~1v|home\n"
	if got := dumpKeyboard(home.kb); got != want {
		t.Errorf("home keyboard:\n%s\nwant:\n%s", got, want)
	}

	// Follow the buttons the screens themselves emitted.
	press(a, "c2", home.kb[0][0].Data)
	cpuEdit := send.lastEdit()
	if cpuEdit.html != cpu {
		t.Errorf("cpu text = %q, want the /cpu reply", cpuEdit.html)
	}
	want = "[⬅️ Back] → ~1v|home  [🏠 Home] → ~1v|home  [🔄 Refresh] → ~1v|cpu\n"
	if got := dumpKeyboard(cpuEdit.kb); got != want {
		t.Errorf("cpu keyboard:\n%s\nwant:\n%s", got, want)
	}

	press(a, "c3", cpuEdit.kb[0][0].Data)
	if send.lastEdit().html != status {
		t.Errorf("Back did not return home: %q", send.lastEdit().html)
	}
	if !slices.Equal(send.answered, []string{"c1:", "c2:", "c3:"}) {
		t.Errorf("answered = %v, want each press answered once", send.answered)
	}
	if len(send.all()) != 0 {
		t.Errorf("views must edit in place, sent %v", send.all())
	}
}

func TestCallKeepsFrom(t *testing.T) {
	send := &fakeSender{}
	a := testAgent(send)
	a.ui.AddScreen(tgui.Screen{ID: "al", Render: func(context.Context, tgui.Call) tgui.View { return tgui.View{Text: "alert"} }})

	// Opened from another screen, Back and Refresh both remember it.
	press(a, "c1", "~1v|cpu^al")
	want := "[⬅️ Back] → ~1v|al  [🏠 Home] → ~1v|home  [🔄 Refresh] → ~1v|cpu^al\n"
	if got := dumpKeyboard(send.lastEdit().kb); got != want {
		t.Errorf("keyboard:\n%s\nwant:\n%s", got, want)
	}
}

func TestCallOutdated(t *testing.T) {
	for _, data := range []string{"~1zz", "~1v|nope", "~1v", "~1v|cpu^", "~2v|cpu", "~", "~1v|<b>"} {
		send := &fakeSender{}
		a := testAgent(send)
		press(a, "c", data)
		if !slices.Equal(send.answered, []string{"c:" + outdatedToast}) {
			t.Errorf("%q: answered = %v", data, send.answered)
		}
		if len(send.edits) != 0 || len(send.all()) != 0 {
			t.Errorf("%q: outdated data changed the chat: edits %v sent %v", data, send.edits, send.all())
		}
	}
}

func TestCallAuthorize(t *testing.T) {
	ctx := context.Background()
	cases := []struct {
		name   string
		admins []int64
		cb     telegram.Callback
		answer []string // nil: ignored, not even answered
		edited bool
	}{
		{"foreign chat", nil,
			telegram.Callback{ID: "c", ChatID: 7, ChatType: "private", FromID: 7, Data: "~1v|cpu"}, nil, false},
		{"foreign chat, unknown act", nil,
			telegram.Callback{ID: "c", ChatID: 7, ChatType: "private", FromID: 7, Data: "~1zz"}, nil, false},
		{"impostor in private chat", nil,
			telegram.Callback{ID: "c", ChatID: 42, ChatType: "private", FromID: 99, Data: "~1v|cpu"}, nil, false},
		{"group viewer opens a view", []int64{1},
			telegram.Callback{ID: "c", ChatID: 42, ChatType: "group", FromID: 99, Data: "~1v|cpu"}, []string{"c:"}, true},
		{"group viewer, unknown act", []int64{1},
			telegram.Callback{ID: "c", ChatID: 42, ChatType: "group", FromID: 99, Data: "~1zz"}, []string{"c:" + adminOnlyToast}, false},
		{"group viewer, config action", []int64{1},
			telegram.Callback{ID: "c", ChatID: 42, ChatType: "group", FromID: 99, Data: "~1cf"}, []string{"c:" + adminOnlyToast}, false},
		{"group admin, config action", []int64{1},
			telegram.Callback{ID: "c", ChatID: 42, ChatType: "group", FromID: 1, Data: "~1cf"}, []string{"c:"}, true},
		{"inaccessible message", nil,
			telegram.Callback{ID: "c", ChatID: 42, ChatType: "private", FromID: 42, Data: "~1v|cpu", Inaccessible: true},
			[]string{"c:" + inaccessibleToast}, false},
	}
	for _, tc := range cases {
		send := &fakeSender{}
		a, _ := authAgent(t, send, 42, tc.admins...)
		// The class authorize sees comes from the registered action.
		a.ui.AddScreen(tgui.Screen{ID: "cfg", Render: func(context.Context, tgui.Call) tgui.View { return tgui.View{Text: "changed"} }})
		a.ui.AddAction(tgui.Action{ID: "cf", Class: tgui.ClassConfig, Screen: "cfg"})
		cb := tc.cb
		cb.MessageID = 4
		a.handleCallback(ctx, &cb)
		if !slices.Equal(send.answered, tc.answer) {
			t.Errorf("%s: answered = %v, want %v", tc.name, send.answered, tc.answer)
		}
		if (len(send.edits) > 0) != tc.edited {
			t.Errorf("%s: edits = %v, want edited %v", tc.name, send.edits, tc.edited)
		}
	}
}

func TestCallRenderFailure(t *testing.T) {
	send := &fakeSender{}
	a := testAgent(send)
	a.ui.AddScreen(tgui.Screen{ID: "big", Render: func(context.Context, tgui.Call) tgui.View {
		return tgui.View{Text: "big", Rows: [][]tgui.Button{{{Label: "x", Call: tgui.Open(strings.Repeat("a", 64))}}}}
	}})
	press(a, "c", "~1v|big")
	if !slices.Equal(send.answered, []string{"c:" + renderFailedToast}) || len(send.edits) != 0 {
		t.Errorf("answered = %v, edits = %v", send.answered, send.edits)
	}
}

func TestCallEditFailureFallsBack(t *testing.T) {
	send := &fakeSender{editErr: errors.New("Bad Request: message to edit not found")}
	a := testAgent(send)
	press(a, "c", "~1v|cpu")
	if len(send.all()) != 1 || !strings.Contains(dumpKeyboard(send.keyboards[0]), "~1v|cpu") {
		t.Errorf("failed edit must resend the view: sent %v", send.all())
	}
	if !slices.Equal(send.answered, []string{"c:" + editFailedToast}) {
		t.Errorf("answered = %v", send.answered)
	}
	if got := strings.Join(send.eventLog(), ","); got != "edit,send,answer" {
		t.Errorf("events = %s, want the answer after the fallback", got)
	}
}

// Every screen this agent registers encodes all its buttons within 64
// bytes, and they all lead to registered screens.
func TestCallScreensEncode(t *testing.T) {
	send := &fakeSender{}
	a := testAgent(send)
	for _, data := range []string{"~1v|home", "~1v|cpu"} {
		press(a, "c", data)
		for _, row := range send.lastEdit().kb {
			for _, b := range row {
				if len(b.Data) > tgui.MaxData {
					t.Errorf("%s: %q is over 64 bytes", data, b.Data)
				}
				res, err := a.ui.Dispatch(context.Background(), b.Data, func(tgui.Class) bool { return true })
				if err != nil || res.Outcome != tgui.Shown {
					t.Errorf("%s: button %q leads nowhere: %+v %v", data, b.Data, res.Outcome, err)
				}
			}
		}
	}
}

// Nothing the bot sends today carries tgui data but confirm tokens: the
// goldens pin every keyboard, and none of them has another "~" button.
func TestNoKeyboardEmitsCalls(t *testing.T) {
	tokens := strings.NewReplacer("→ ~1y|", "", "→ ~1n|", "")
	files, err := filepath.Glob(filepath.Join("testdata", "*.golden"))
	if err != nil || len(files) == 0 {
		t.Fatalf("no goldens: %v", err)
	}
	for _, f := range files {
		b, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(tokens.Replace(string(b)), "→ ~") {
			t.Errorf("%s has a tgui button", f)
		}
	}
}
