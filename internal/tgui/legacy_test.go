package tgui

import (
	"context"
	"strings"
	"testing"

	"github.com/eliau2005/statixagent/internal/telegram"
)

func nopLegacy(context.Context, *telegram.Callback, bool) {}

func TestLegacyLookupFirstClaimWins(t *testing.T) {
	table := NewLegacyTable(
		LegacyRule{Name: "exact", Exact: []string{"ab:x"}, Handle: nopLegacy},
		LegacyRule{Name: "long", Prefixes: []string{"ab:cd:"}, Handle: nopLegacy},
		LegacyRule{Name: "short", Exact: []string{"ab"}, Prefixes: []string{"ab:", "zz:"}, Slow: true, Ack: "Working…", Handle: nopLegacy},
	)
	cases := []struct{ data, want string }{
		{"ab:x", "exact"},
		{"ab:cd:1", "long"},
		{"ab:cd", "short"}, // not the longer prefix
		{"ab:", "short"},
		{"ab", "short"},
		{"zz:9", "short"},
		{"abc", ""},
		{"a", ""},
		{"", ""},
		{"~1v|ab", ""},
	}
	for _, tc := range cases {
		rule, ok := table.Lookup(tc.data)
		if ok != (tc.want != "") || rule.Name != tc.want {
			t.Errorf("Lookup(%q) = %q, %v; want %q", tc.data, rule.Name, ok, tc.want)
		}
	}
	if rule, _ := table.Lookup("zz:1"); !rule.Slow || rule.Ack != "Working…" || rule.Handle == nil {
		t.Errorf("Lookup returned %+v without its Slow, Ack and Handle", rule)
	}
}

func TestNewLegacyTableRejectsBadTables(t *testing.T) {
	cases := []struct {
		name  string
		rules []LegacyRule
		want  string
	}{
		{"exact shadowed by earlier prefix", []LegacyRule{
			{Name: "a", Prefixes: []string{"dg:"}, Handle: nopLegacy},
			{Name: "b", Exact: []string{"dg:toggle"}, Handle: nopLegacy},
		}, `"dg:toggle" is shadowed by "a"`},
		{"longer prefix after shorter", []LegacyRule{
			{Name: "a", Prefixes: []string{"tip"}, Handle: nopLegacy},
			{Name: "b", Prefixes: []string{"tipk:"}, Handle: nopLegacy},
		}, `prefix "tipk:" is shadowed by "a"`},
		{"same exact twice", []LegacyRule{
			{Name: "a", Exact: []string{"ssh"}, Handle: nopLegacy},
			{Name: "b", Exact: []string{"status", "ssh"}, Handle: nopLegacy},
		}, `"ssh" is shadowed by "a"`},
		{"same prefix twice", []LegacyRule{
			{Name: "a", Prefixes: []string{"sk:"}, Handle: nopLegacy},
			{Name: "b", Prefixes: []string{"sk:"}, Handle: nopLegacy},
		}, `prefix "sk:" is shadowed by "a"`},
		{"no handler", []LegacyRule{{Name: "a", Exact: []string{"x"}}}, "needs a handler"},
		{"no claim", []LegacyRule{{Name: "a", Handle: nopLegacy}}, "needs a handler and a claim"},
		{"empty prefix", []LegacyRule{{Name: "a", Prefixes: []string{""}, Handle: nopLegacy}}, `claims ""`},
		{"tgui format", []LegacyRule{{Name: "a", Prefixes: []string{"~1"}, Handle: nopLegacy}}, `claims "~1"`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			defer func() {
				msg, _ := recover().(string)
				if !strings.Contains(msg, tc.want) {
					t.Errorf("panic = %q, want it to mention %q", msg, tc.want)
				}
			}()
			NewLegacyTable(tc.rules...)
		})
	}
}

func TestNewLegacyTableAllowsExactBeforePrefix(t *testing.T) {
	// The more specific claim first is the required order, including an
	// exact datum equal to a later prefix.
	table := NewLegacyTable(
		LegacyRule{Name: "a", Exact: []string{"dg:hour:"}, Handle: nopLegacy},
		LegacyRule{Name: "b", Prefixes: []string{"dg:hour:"}, Handle: nopLegacy},
	)
	if rule, _ := table.Lookup("dg:hour:1"); rule.Name != "b" {
		t.Errorf("dg:hour:1 claimed by %q, want b", rule.Name)
	}
}
