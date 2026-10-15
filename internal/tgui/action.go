package tgui

import (
	"context"
	"fmt"
	"maps"
	"slices"

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

// Built-in actions that open the screen named by their first argument:
// ActView in the pressed message ("~1v|cpu"), ActOpen in a new one
// ("~1o|cpu"), for buttons on messages that must not change.
const (
	ActView = "v"
	ActOpen = "o"
)

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
		actions: map[string]Action{ActView: {ID: ActView, Class: ClassView}, ActOpen: {ID: ActOpen, Class: ClassView}},
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

// Screens returns the registered screen IDs, for tests that walk them all.
func (r *Registry) Screens() []string {
	return slices.Sorted(maps.Keys(r.screens))
}

// Known reports whether act is registered.
func (r *Registry) Known(act string) bool {
	_, ok := r.actions[act]
	return ok
}

// Slow reports whether c opens a Slow screen.
func (r *Registry) Slow(c Call) bool {
	s, ok := r.screens[r.target(c)]
	return ok && s.Slow
}

// target is the screen c opens, or "" when it names none.
func (r *Registry) target(c Call) string {
	act, ok := r.actions[c.Act]
	switch {
	case !ok:
		return ""
	case act.ID == ActView || act.ID == ActOpen:
		if len(c.Args) == 0 {
			return ""
		}
		return c.Args[0]
	}
	return act.Screen
}

// Show renders the screen c opens. A press of ActOpen renders as ActView,
// so the buttons of the new message act on it in place.
func (r *Registry) Show(ctx context.Context, c Call) (Result, error) {
	id := r.target(c)
	s, ok := r.screens[id]
	if !ok {
		return Result{Outcome: Outdated, Call: c}, nil
	}
	render := c
	if c.Act == ActOpen {
		render.Act = ActView
	}
	v := s.Render(ctx, render)
	kb, err := v.Keyboard()
	if err != nil {
		return Result{Call: c}, fmt.Errorf("screen %q: %w", id, err)
	}
	return Result{Outcome: Shown, Call: c, Text: v.Text, Keyboard: kb, New: c.Act == ActOpen}, nil
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
	// New: show it in a new message replying to the pressed one.
	New bool
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
	return r.Show(ctx, c)
}
