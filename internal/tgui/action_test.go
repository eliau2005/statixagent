package tgui

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"testing"

	"github.com/eliau2005/statixagent/internal/telegram"
)

// testRegistry has a root "home", a "cpu" child and a Config action "th"
// showing a "set" screen. Each screen echoes its call in the text.
func testRegistry() *Registry {
	r := NewRegistry()
	echo := func(c Call) string { return c.Act + " " + strings.Join(c.Args, ",") + " ^" + c.From }
	r.AddScreen(Screen{ID: "home", Render: func(_ context.Context, c Call) View {
		return View{Text: "home: " + echo(c), Rows: [][]Button{{{Label: "CPU", Call: Open("cpu")}}}}
	}})
	r.AddScreen(Screen{ID: "cpu", Parent: "home", Render: func(_ context.Context, c Call) View {
		back, _ := r.Back("cpu", c)
		return View{Text: "cpu: " + echo(c), Rows: [][]Button{{{Label: "Back", Call: back}, {Label: "Refresh", Call: c}}}}
	}})
	r.AddScreen(Screen{ID: "set", Parent: "home", Render: func(_ context.Context, c Call) View {
		return View{Text: "set: " + echo(c)}
	}})
	r.AddAction(Action{ID: "th", Class: ClassConfig, Screen: "set"})
	return r
}

// gateLog records each class a gate is asked about and allows as told.
type gateLog struct {
	allow   bool
	classes []Class
}

func (g *gateLog) gate(c Class) bool {
	g.classes = append(g.classes, c)
	return g.allow
}

func TestDispatch(t *testing.T) {
	r := testRegistry()
	cases := []struct {
		name  string
		data  string
		class Class // what the gate must be asked
		want  Outcome
		text  string
		kb    telegram.Keyboard
	}{
		{"home", "~1v|home", ClassView, Shown, "home: v home ^",
			telegram.Keyboard{{{Text: "CPU", Data: "~1v|cpu"}}}},
		{"cpu back to parent", "~1v|cpu", ClassView, Shown, "cpu: v cpu ^",
			telegram.Keyboard{{{Text: "Back", Data: "~1v|home"}, {Text: "Refresh", Data: "~1v|cpu"}}}},
		{"cpu back to from", "~1v|cpu^set", ClassView, Shown, "cpu: v cpu ^set",
			telegram.Keyboard{{{Text: "Back", Data: "~1v|set"}, {Text: "Refresh", Data: "~1v|cpu^set"}}}},
		{"unregistered from falls back to parent", "~1v|cpu^zz", ClassView, Shown, "cpu: v cpu ^zz",
			telegram.Keyboard{{{Text: "Back", Data: "~1v|home"}, {Text: "Refresh", Data: "~1v|cpu^zz"}}}},
		{"fixed-screen action", "~1th|cpu|85", ClassConfig, Shown, "set: th cpu,85 ^", nil},
		{"unknown screen", "~1v|nope", ClassView, Outdated, "", nil},
		{"view without screen", "~1v", ClassView, Outdated, "", nil},
		{"unknown act", "~1zz|cpu", ClassMutate, Outdated, "", nil},
		{"malformed", "~1v|cpu^", ClassMutate, Outdated, "", nil},
		{"other version", "~2v|cpu", ClassMutate, Outdated, "", nil},
		{"legacy data", "status", ClassMutate, Outdated, "", nil},
	}
	for _, tc := range cases {
		g := &gateLog{allow: true}
		res, err := r.Dispatch(context.Background(), tc.data, g.gate)
		if err != nil {
			t.Errorf("%s: %v", tc.name, err)
			continue
		}
		if !reflect.DeepEqual(g.classes, []Class{tc.class}) {
			t.Errorf("%s: gate asked %v, want exactly [%v]", tc.name, g.classes, tc.class)
		}
		if res.Outcome != tc.want || res.Text != tc.text || !reflect.DeepEqual(res.Keyboard, tc.kb) {
			t.Errorf("%s: got %v %q %v; want %v %q %v", tc.name, res.Outcome, res.Text, res.Keyboard, tc.want, tc.text, tc.kb)
		}
	}
}

func TestDispatchRefusedRendersNothing(t *testing.T) {
	r := NewRegistry()
	rendered := false
	r.AddScreen(Screen{ID: "home", Render: func(context.Context, Call) View {
		rendered = true
		return View{Text: "home"}
	}})
	for _, data := range []string{"~1v|home", "~1zz", "garbage"} {
		g := &gateLog{allow: false}
		res, err := r.Dispatch(context.Background(), data, g.gate)
		if err != nil || res.Outcome != Refused || res.Text != "" || len(g.classes) != 1 {
			t.Errorf("%q: %+v, %v, gate %v", data, res, err, g.classes)
		}
	}
	if rendered {
		t.Error("a refused press must not render")
	}
}

func TestDispatchUnencodableButton(t *testing.T) {
	r := NewRegistry()
	r.AddScreen(Screen{ID: "big", Render: func(context.Context, Call) View {
		return View{Text: "big", Rows: [][]Button{{{Label: "x", Call: Call{Act: "v", Args: []string{strings.Repeat("a", 70)}}}}}}
	}})
	_, err := r.Dispatch(context.Background(), "~1v|big", func(Class) bool { return true })
	if !errors.Is(err, ErrTooLong) {
		t.Errorf("err = %v, want ErrTooLong", err)
	}
}

func TestBack(t *testing.T) {
	r := testRegistry()
	cases := []struct {
		id   string
		call Call
		want string // encoded Back call; "" for none
	}{
		{"home", Open("home"), ""},
		{"cpu", Open("cpu"), "~1v|home"},
		{"cpu", Call{Act: "v", Args: []string{"cpu"}, From: "set"}, "~1v|set"},
		{"cpu", Call{Act: "v", Args: []string{"cpu"}, From: "cpu"}, "~1v|home"}, // never Back to itself
		{"nope", Open("nope"), ""},
	}
	for _, tc := range cases {
		c, ok := r.Back(tc.id, tc.call)
		got := ""
		if ok {
			got, _ = Encode(c)
		}
		if got != tc.want {
			t.Errorf("Back(%q, %+v) = %q, want %q", tc.id, tc.call, got, tc.want)
		}
	}
}

func TestRegistryPanicsOnBadTables(t *testing.T) {
	render := func(context.Context, Call) View { return View{} }
	cases := []struct {
		name string
		add  func(r *Registry)
	}{
		{"invalid screen ID", func(r *Registry) { r.AddScreen(Screen{ID: "a|b", Render: render}) }},
		{"empty screen ID", func(r *Registry) { r.AddScreen(Screen{Render: render}) }},
		{"duplicate screen", func(r *Registry) {
			r.AddScreen(Screen{ID: "a", Render: render})
			r.AddScreen(Screen{ID: "a", Render: render})
		}},
		{"no render", func(r *Registry) { r.AddScreen(Screen{ID: "a"}) }},
		{"unknown parent", func(r *Registry) { r.AddScreen(Screen{ID: "a", Parent: "b", Render: render}) }},
		{"invalid action ID", func(r *Registry) { r.AddAction(Action{ID: "four"}) }},
		{"duplicate view action", func(r *Registry) {
			r.AddScreen(Screen{ID: "a", Render: render})
			r.AddAction(Action{ID: ActView, Screen: "a"})
		}},
		{"action without screen", func(r *Registry) { r.AddAction(Action{ID: "x", Screen: "a"}) }},
	}
	for _, tc := range cases {
		func() {
			defer func() {
				if recover() == nil {
					t.Errorf("%s: no panic", tc.name)
				}
			}()
			tc.add(NewRegistry())
		}()
	}
}
