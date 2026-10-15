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
}

// View is a rendered screen: HTML text (the client fits it to Telegram's
// limit when editing) and its button rows.
type View struct {
	Text string
	Rows [][]Button
}

// Keyboard encodes the view's buttons. An unencodable Call is a bug in
// the screen, reported rather than sent as a button that cannot work.
func (v View) Keyboard() (telegram.Keyboard, error) {
	var kb telegram.Keyboard
	for _, row := range v.Rows {
		var btns []telegram.Button
		for _, b := range row {
			data, err := Encode(b.Call)
			if err != nil {
				return nil, err
			}
			btns = append(btns, telegram.Button{Text: b.Label, Data: data})
		}
		kb = append(kb, btns)
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
}

// Open is the call that shows screen id.
func Open(id string) Call {
	return Call{Act: ActView, Args: []string{id}}
}
