package tgui

import (
	"context"
	"fmt"

	"github.com/eliau2005/statixagent/internal/telegram"
)

// Class is how much an action may change, which decides who may run it.
type Class uint8

const (
	// ClassView only reads state; a replay is harmless.
	ClassView Class = iota
	// ClassConfig changes the bot's own settings, reversibly.
	ClassConfig
	// ClassMutate changes the host.
	ClassMutate
)

// ActView is the built-in action that opens the screen named by its first
// argument: "~1v|cpu".
const ActView = "v"

// Action is a registered act. IDs are append-only: a retired ID is never
// given new meaning, because old keyboards keep sending it.
type Action struct {
	ID    string
	Class Class
	// Screen is the screen the action shows. Empty only for ActView,
	// whose call names the screen.
	Screen string
}

// Registry holds the screens and actions one bot understands. It is
// built once at startup and only read afterwards.
type Registry struct {
	screens map[string]Screen
	actions map[string]Action
}

// NewRegistry returns a registry holding only the view action.
func NewRegistry() *Registry {
	return &Registry{
		screens: map[string]Screen{},
		actions: map[string]Action{ActView: {ID: ActView, Class: ClassView}},
	}
}

// AddScreen registers s. A parent must be registered first. Mistakes here
// are programming errors in a fixed table, so they panic at startup.
func (r *Registry) AddScreen(s Screen) {
	switch _, dup := r.screens[s.ID]; {
	case !validArg(s.ID):
		panic(fmt.Sprintf("tgui: invalid screen ID %q", s.ID))
	case dup:
		panic(fmt.Sprintf("tgui: duplicate screen %q", s.ID))
	case s.Render == nil:
		panic(fmt.Sprintf("tgui: screen %q has no Render", s.ID))
	}
	if _, ok := r.screens[s.Parent]; s.Parent != "" && !ok {
		panic(fmt.Sprintf("tgui: screen %q has unknown parent %q", s.ID, s.Parent))
	}
	r.screens[s.ID] = s
}

// AddAction registers a, whose screen must already be registered.
func (r *Registry) AddAction(a Action) {
	switch _, dup := r.actions[a.ID]; {
	case !validID(a.ID):
		panic(fmt.Sprintf("tgui: invalid action ID %q", a.ID))
	case dup:
		panic(fmt.Sprintf("tgui: duplicate action %q", a.ID))
	}
	if _, ok := r.screens[a.Screen]; !ok {
		panic(fmt.Sprintf("tgui: action %q has unknown screen %q", a.ID, a.Screen))
	}
	r.actions[a.ID] = a
}

// Back is the call a Back button on screen id makes, given the call that
// opened it: the registered screen named by From, else the static parent.
// ok is false for a root screen opened without a From.
func (r *Registry) Back(id string, c Call) (Call, bool) {
	if _, ok := r.screens[c.From]; ok && c.From != id {
		return Open(c.From), true
	}
	if s, ok := r.screens[id]; ok && s.Parent != "" {
		return Open(s.Parent), true
	}
	return Call{}, false
}

// Outcome is what Dispatch did with a press.
type Outcome uint8

const (
	// Shown: a view was rendered for the caller to edit into the message.
	Shown Outcome = iota
	// Refused: the gate stopped the press and has answered (or
	// deliberately ignored) it.
	Refused
	// Outdated: data no registered action or screen understands, such as
	// a button from a newer or retired version, or forged data.
	Outdated
)

// Result is the outcome of one press.
type Result struct {
	Outcome  Outcome
	Call     Call // the decoded call, when it decoded
	Text     string
	Keyboard telegram.Keyboard
}

// Dispatch handles one press of data. gate authorizes it for the action's
// class before anything else happens; data that names no registered
// action is gated as ClassMutate, the strictest class. Decoding and
// lookup are pure, so the gate's chat check still precedes every side
// effect. The error reports a screen that rendered an unencodable button.
func (r *Registry) Dispatch(ctx context.Context, data string, gate func(Class) bool) (Result, error) {
	c, err := Decode(data)
	act, known := r.actions[c.Act]
	known = known && err == nil
	class := ClassMutate
	if known {
		class = act.Class
	}
	if !gate(class) {
		return Result{Outcome: Refused}, nil
	}
	if !known {
		return Result{Outcome: Outdated}, nil
	}
	id := act.Screen
	if act.ID == ActView {
		if len(c.Args) == 0 {
			return Result{Outcome: Outdated, Call: c}, nil
		}
		id = c.Args[0]
	}
	s, ok := r.screens[id]
	if !ok {
		return Result{Outcome: Outdated, Call: c}, nil
	}
	v := s.Render(ctx, c)
	kb, err := v.Keyboard()
	if err != nil {
		return Result{Call: c}, fmt.Errorf("screen %q: %w", id, err)
	}
	return Result{Outcome: Shown, Call: c, Text: v.Text, Keyboard: kb}, nil
}
