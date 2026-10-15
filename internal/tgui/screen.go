package tgui

import (
	"context"

	"github.com/eliau2005/statixagent/internal/telegram"
)

// Button is one inline button. Its Call is encoded only when the view is
// turned into a keyboard.
type Button struct {
	Label string
	Call  Call
	// Legacy is pre-"~1" callback data, sent instead of Call, for the
	// actions whose handlers still live in the legacy table.
	Legacy string
	// Copy makes a copy_text button: no Call, no round trip.
	Copy string
	// Style is the button colour, "danger", "success" or "primary". It is
	// decoration only: the label must say the same without it.
	Style string
}

// View is a rendered screen: HTML text (the client fits it to Telegram's
// limit when editing) and its button rows.
type View struct {
	Text string
	Rows [][]Button
}

// Keyboard encodes the view's buttons, leaving out empty rows. An
// unencodable Call is a bug in the screen, reported rather than sent as
// a button that cannot work.
func (v View) Keyboard() (telegram.Keyboard, error) {
	var kb telegram.Keyboard
	for _, row := range v.Rows {
		var btns []telegram.Button
		for _, b := range row {
			btn := telegram.Button{Text: b.Label, Data: b.Legacy, Copy: b.Copy, Style: b.Style}
			if b.Legacy == "" && b.Copy == "" {
				data, err := Encode(b.Call)
				if err != nil {
					return nil, err
				}
				btn.Data = data
			}
			btns = append(btns, btn)
		}
		if len(btns) > 0 {
			kb = append(kb, btns)
		}
	}
	return kb, nil
}

// Screen is a destination the view action can open.
type Screen struct {
	// ID names the screen in callback data; it must be a valid argument.
	// Screens that may be a Back target ("^from") need a 1-3 letter ID.
	ID string
	// Parent is where Back leads when the call names no From; "" for a
	// root screen.
	Parent string
	// Render reads current state and builds the view. It must not change
	// state: views run for any authorized chat member.
	Render func(ctx context.Context, c Call) View
	// Slow screens take seconds to build (network, sampling): the press
	// is answered before Render runs, so the client spinner stops.
	Slow bool
}

// HomeID is the root screen every Home button opens.
const HomeID = "home"

// Open is the call that shows screen id.
func Open(id string) Call {
	return Call{Act: ActView, Args: []string{id}}
}

// OpenNew is the call that shows screen id in a new message replying to
// the pressed one, which keeps its text and keyboard: an alert stays a
// record of what happened.
func OpenNew(id string) Call {
	return Call{Act: ActOpen, Args: []string{id}}
}

// Footer is the fixed last row of every screen but Home: Back, Home and
// Refresh, which re-opens the screen as c opened it.
func (r *Registry) Footer(id string, c Call) []Button {
	refresh := c
	refresh.Act = ActView
	row := []Button{{Label: "🏠 Home", Call: Open(HomeID)}, {Label: "🔄 Refresh", Call: refresh}}
	if back, ok := r.Back(id, c); ok {
		row = append([]Button{{Label: "⬅️ Back", Call: back}}, row...)
	}
	return row
}
