package tgui

import (
	"context"
	"fmt"
	"slices"
	"strings"

	"github.com/eliau2005/statixagent/internal/telegram"
)

// Legacy data is everything that predates the "~1" format: bare command
// words and "xx:" prefixes. Telegram keeps keyboards on old messages
// indefinitely, so it is decoded forever (docs/telegram-ux-redesign.md
// §4.2) by an ordered table of rules, most specific first.

// LegacyHandler runs a press a rule claimed. answered reports that the
// rule was slow and the press has already been answered with its Ack.
type LegacyHandler func(ctx context.Context, cb *telegram.Callback, answered bool)

// LegacyRule claims one family of legacy data.
type LegacyRule struct {
	// Name identifies the rule in tests.
	Name string
	// Exact lists data the rule claims whole; Prefixes, data starting
	// with any of them. A rule needs at least one of the two.
	Exact    []string
	Prefixes []string
	// Slow presses are answered with Ack before Handle runs, so the
	// client spinner stops while seconds of work go on.
	Slow   bool
	Ack    string
	Handle LegacyHandler
}

func (r LegacyRule) claims(data string) bool {
	return slices.Contains(r.Exact, data) || hasPrefix(data, r.Prefixes)
}

// hasPrefix reports whether s starts with any of prefixes.
func hasPrefix(s string, prefixes []string) bool {
	return slices.ContainsFunc(prefixes, func(p string) bool { return strings.HasPrefix(s, p) })
}

// LegacyTable is an ordered list of legacy rules; the first rule that
// claims the data handles it.
type LegacyTable struct {
	rules []LegacyRule
}

// NewLegacyTable checks rules and returns them as a table. A rule an
// earlier one shadows, in whole or in part, would silently change what
// a button does, so the more specific rule must come first: a prefix
// that covers a later rule's exact data or longer prefix panics, as does
// data two rules claim exactly, a rule without a handler or claims, and
// a claim that could collide with the "~" format.
func NewLegacyTable(rules ...LegacyRule) *LegacyTable {
	for i, r := range rules {
		if r.Handle == nil || len(r.Exact)+len(r.Prefixes) == 0 {
			panic(fmt.Sprintf("tgui: legacy rule %q needs a handler and a claim", r.Name))
		}
		for _, c := range slices.Concat(r.Exact, r.Prefixes) {
			if c == "" || IsCall(c) {
				panic(fmt.Sprintf("tgui: legacy rule %q claims %q", r.Name, c))
			}
		}
		for _, prev := range rules[:i] {
			for _, d := range r.Exact {
				if prev.claims(d) {
					panic(fmt.Sprintf("tgui: legacy rule %q: %q is shadowed by %q", r.Name, d, prev.Name))
				}
			}
			for _, p := range r.Prefixes {
				if hasPrefix(p, prev.Prefixes) {
					panic(fmt.Sprintf("tgui: legacy rule %q: prefix %q is shadowed by %q", r.Name, p, prev.Name))
				}
			}
		}
	}
	return &LegacyTable{rules: rules}
}

// Lookup returns the rule that handles data; ok is false when none claims
// it, which makes the data outdated.
func (t *LegacyTable) Lookup(data string) (rule LegacyRule, ok bool) {
	for _, r := range t.rules {
		if r.claims(data) {
			return r, true
		}
	}
	return LegacyRule{}, false
}
