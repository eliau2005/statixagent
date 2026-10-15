package agent

import (
	"context"
	"log"

	"github.com/eliau2005/statixagent/internal/telegram"
	"github.com/eliau2005/statixagent/internal/tgui"
)

// Screens on the tgui callback layer. They reuse the router's existing
// renderers for their text; only the keyboard is new. No keyboard sent
// today carries "~" data, so these are reached only from each other until
// the navigation moves over.

// renderFailedToast answers a press whose screen could not be built.
const renderFailedToast = "Couldn't show this view. Send /status for a fresh one."

// buildScreens registers the tgui screens.
func (a *Agent) buildScreens() *tgui.Registry {
	r := tgui.NewRegistry()
	view := func(ctx context.Context, cmd string) string {
		text, _ := a.router.Invoke(ctx, cmd, nil)
		return text
	}
	r.AddScreen(tgui.Screen{ID: "home", Render: func(ctx context.Context, _ tgui.Call) tgui.View {
		return tgui.View{Text: view(ctx, "status"), Rows: [][]tgui.Button{
			{{Label: "🖥 CPU", Call: tgui.Open("cpu")}},
			{{Label: "🔄 Refresh", Call: tgui.Open("home")}},
		}}
	}})
	r.AddScreen(tgui.Screen{ID: "cpu", Parent: "home", Render: func(ctx context.Context, c tgui.Call) tgui.View {
		back, _ := r.Back("cpu", c)
		return tgui.View{Text: view(ctx, "cpu"), Rows: [][]tgui.Button{{
			{Label: "⬅️ Back", Call: back},
			{Label: "🏠 Home", Call: tgui.Open("home")},
			{Label: "🔄 Refresh", Call: c},
		}}}
	}})
	return r
}

// handleCall runs a press whose data is in the tgui format. authorize
// runs first, through the dispatcher's gate, with the class of the
// registered action: foreign chats and impostors are ignored unanswered,
// as for legacy data. Every other press is answered exactly once.
func (a *Agent) handleCall(ctx context.Context, cb *telegram.Callback) {
	gate := func(c tgui.Class) bool {
		v := a.authorize(ctx, sender{chatID: cb.ChatID, fromID: cb.FromID, chatType: cb.ChatType}, c == tgui.ClassView)
		switch {
		case v == ignored:
			return false
		case cb.Inaccessible:
			a.answer(ctx, cb, inaccessibleToast)
			return false
		case v == adminOnly:
			a.answer(ctx, cb, adminOnlyToast)
			return false
		}
		return true
	}
	// Yes and Cancel name a confirm token, not a screen. Decoding is pure,
	// so the gate still runs before anything else.
	if c, err := tgui.Decode(cb.Data); err == nil && (c.Act == tgui.ActYes || c.Act == tgui.ActNo) {
		if gate(tgui.ClassMutate) {
			a.confirmPress(ctx, cb, c)
		}
		return
	}
	res, err := a.ui.Dispatch(ctx, cb.Data, gate)
	switch {
	case err != nil:
		log.Printf("agent: rendering callback: %v", err)
		a.answer(ctx, cb, renderFailedToast)
	case res.Outcome == tgui.Outdated:
		log.Printf("agent: refusing callback data of %d bytes that no button emits", len(cb.Data))
		a.answer(ctx, cb, outdatedToast)
	case res.Outcome == tgui.Shown:
		a.finishCallback(ctx, cb, false, res.Text, res.Keyboard, "")
	}
}
