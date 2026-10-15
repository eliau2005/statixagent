package tgui

import (
	"context"
	"reflect"
	"slices"
	"testing"

	"github.com/eliau2005/statixagent/internal/telegram"
)

func TestKeyboardButtonKinds(t *testing.T) {
	v := View{Rows: [][]Button{
		{{Label: "CPU", Call: Open("cpu")}, {Label: "Kick", Call: Call{Act: "kk", Args: []string{"ab"}}, Style: "danger"}},
		nil, // empty rows are left out
		{{Label: "Live", Legacy: "live"}, {Label: "Copy IP", Copy: "2001:db8::1"}},
	}}
	kb, err := v.Keyboard()
	if err != nil {
		t.Fatal(err)
	}
	want := telegram.Keyboard{
		{{Text: "CPU", Data: "~1v|cpu"}, {Text: "Kick", Data: "~1kk|ab", Style: "danger"}},
		{{Text: "Live", Data: "live"}, {Text: "Copy IP", Copy: "2001:db8::1"}},
	}
	if !reflect.DeepEqual(kb, want) {
		t.Errorf("keyboard = %+v, want %+v", kb, want)
	}
}

func TestFooter(t *testing.T) {
	r := testRegistry()
	cases := []struct {
		id   string
		call Call
		want []string // labels and encoded calls
	}{
		{"cpu", Open("cpu"), []string{"⬅️ Back", "~1v|home", "🏠 Home", "~1v|home", "🔄 Refresh", "~1v|cpu"}},
		{"cpu", Call{Act: ActView, Args: []string{"cpu", "2"}, From: "set"},
			[]string{"⬅️ Back", "~1v|set", "🏠 Home", "~1v|home", "🔄 Refresh", "~1v|cpu|2^set"}},
		// Opened in a new message, Refresh then works in place.
		{"cpu", OpenNew("cpu"), []string{"⬅️ Back", "~1v|home", "🏠 Home", "~1v|home", "🔄 Refresh", "~1v|cpu"}},
		// A root screen has nowhere to go Back to.
		{"home", Open("home"), []string{"🏠 Home", "~1v|home", "🔄 Refresh", "~1v|home"}},
	}
	for _, tc := range cases {
		var got []string
		for _, b := range r.Footer(tc.id, tc.call) {
			data, err := Encode(b.Call)
			if err != nil {
				t.Fatal(err)
			}
			got = append(got, b.Label, data)
		}
		if !slices.Equal(got, tc.want) {
			t.Errorf("Footer(%q, %+v) = %v, want %v", tc.id, tc.call, got, tc.want)
		}
	}
}

func TestDispatchOpenNew(t *testing.T) {
	r := testRegistry()
	g := &gateLog{allow: true}
	res, err := r.Dispatch(context.Background(), "~1o|cpu", g.gate)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(g.classes, []Class{ClassView}) {
		t.Errorf("gate asked %v, want a view", g.classes)
	}
	// The screen renders as an in-place view of the new message.
	if res.Outcome != Shown || !res.New || res.Text != "cpu: v cpu ^" ||
		!reflect.DeepEqual(res.Keyboard, telegram.Keyboard{{{Text: "Back", Data: "~1v|home"}, {Text: "Refresh", Data: "~1v|cpu"}}}) {
		t.Errorf("res = %+v", res)
	}
	for _, data := range []string{"~1o", "~1o|nope"} {
		if res, _ := r.Dispatch(context.Background(), data, g.gate); res.Outcome != Outdated {
			t.Errorf("%q: %v, want outdated", data, res.Outcome)
		}
	}
	if res, _ := r.Dispatch(context.Background(), "~1v|cpu", g.gate); res.New {
		t.Error("a view press must edit in place")
	}
}

func TestRegistryLookups(t *testing.T) {
	r := testRegistry()
	r.AddScreen(Screen{ID: "top", Parent: "home", Slow: true, Render: func(context.Context, Call) View { return View{} }})
	if got := r.Screens(); !slices.Equal(got, []string{"cpu", "home", "set", "top"}) {
		t.Errorf("Screens = %v", got)
	}
	for act, want := range map[string]bool{ActView: true, ActOpen: true, "th": true, "zz": false, ActYes: false} {
		if r.Known(act) != want {
			t.Errorf("Known(%q) = %v", act, !want)
		}
	}
	for _, tc := range []struct {
		c    Call
		slow bool
	}{
		{Open("top"), true},
		{OpenNew("top"), true},
		{Open("cpu"), false},
		{Call{Act: ActView}, false},
		{Call{Act: "zz", Args: []string{"top"}}, false},
	} {
		if r.Slow(tc.c) != tc.slow {
			t.Errorf("Slow(%+v) = %v", tc.c, !tc.slow)
		}
	}
}
