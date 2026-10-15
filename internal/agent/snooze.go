package agent

import (
	"context"
	"fmt"
	"log"
	"strconv"
	"strings"
	"time"

	"github.com/eliau2005/statixagent/internal/telegram"
	"github.com/eliau2005/statixagent/internal/tgui"
)

// Snooze on alerts (§3.11): a row of [🔕 1h] [🔕 8h] [🔕 24h] under the
// alert's views. A press silences the alert's key and changes only the
// alert's keyboard: the row becomes [🔔 Snoozed until 15:02 · Undo], and
// Undo lifts the snooze and brings the row back. The alert's text is
// never touched.

// snoozeChoices are the snooze buttons, in order.
var snoozeChoices = []string{"1h", "8h", "24h"}

// snoozeFor maps a snooze button's argument to its duration.
var snoozeFor = map[string]time.Duration{"1h": time.Hour, "8h": 8 * time.Hour, "24h": 24 * time.Hour}

// staleSnoozeToast answers a snooze button whose key is no longer known:
// a hashed key from before a restart.
const staleSnoozeToast = "stale snooze"

// Snooze buttons name the alert key in one of two forms: "k|<key>", the
// key itself with every byte outside the argument charset escaped as *XX
// (hex), which survives restarts; or, for a key too long for that,
// "h|<digest>", resolved through a.snoozeKeys while this process runs.
const (
	snoozeKeyed  = "k"
	snoozeHashed = "h"
	// snoozeRoom is what the longest snooze data leaves for the key.
	snoozeRoom = tgui.MaxData - len("~1sz|24h|k|")
)

// keyArgByte reports whether c may stand for itself in an escaped key.
// '*' may not: it starts an escape.
func keyArgByte(c byte) bool {
	return 'a' <= c && c <= 'z' || 'A' <= c && c <= 'Z' || '0' <= c && c <= '9' || strings.IndexByte("._:/-", c) >= 0
}

// escapeKey writes an alert key in the callback argument charset.
func escapeKey(key string) string {
	var b strings.Builder
	for i := 0; i < len(key); i++ {
		if c := key[i]; keyArgByte(c) {
			b.WriteByte(c)
		} else {
			fmt.Fprintf(&b, "*%02X", c)
		}
	}
	return b.String()
}

// unescapeKey reverses escapeKey. It accepts only escapeKey's own output,
// so every key has exactly one form.
func unescapeKey(s string) (string, bool) {
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c != '*' {
			b.WriteByte(c)
			continue
		}
		if i+2 >= len(s) || !isUpperHex(s[i+1]) || !isUpperHex(s[i+2]) {
			return "", false
		}
		x, _ := strconv.ParseUint(s[i+1:i+3], 16, 8)
		b.WriteByte(byte(x))
		i += 2
	}
	key := b.String()
	return key, key != "" && escapeKey(key) == s
}

func isUpperHex(c byte) bool {
	return '0' <= c && c <= '9' || 'A' <= c && c <= 'F'
}

// snoozeRef names key in a snooze button's arguments.
func (a *Agent) snoozeRef(key string) []string {
	if esc := escapeKey(key); len(esc) <= snoozeRoom {
		return []string{snoozeKeyed, esc}
	}
	digest := callbackDigest(key)
	a.mu.Lock()
	a.snoozeKeys[digest] = key
	a.mu.Unlock()
	return []string{snoozeHashed, digest}
}

// resolveSnoozeRef reads the key a snooze button names. valid is false
// for arguments no button emits; found is false for a digest this
// process never issued.
func (a *Agent) resolveSnoozeRef(args []string) (key string, valid, found bool) {
	if len(args) != 2 {
		return "", false, false
	}
	switch args[0] {
	case snoozeKeyed:
		key, ok := unescapeKey(args[1])
		return key, ok, ok
	case snoozeHashed:
		if len(args[1]) != 16 || !isHex(args[1]) {
			return "", false, false
		}
		a.mu.Lock()
		key, ok := a.snoozeKeys[args[1]]
		a.mu.Unlock()
		return key, true, ok
	}
	return "", false, false
}

// snoozeRow is an alert's snooze row: the choices, or, while key is
// snoozed, when it ends and the way to undo it.
func (a *Agent) snoozeRow(key string) []telegram.Button {
	ref := a.snoozeRef(key)
	now := a.now()
	if until, ok := a.engine.SnoozedUntil(key, now); ok {
		return []telegram.Button{{
			Text: "🔔 Snoozed until " + untilLabel(now, until) + " · Undo",
			Data: callData(tgui.Call{Act: cfgUnsnooze, Args: ref}),
		}}
	}
	var row []telegram.Button
	for _, d := range snoozeChoices {
		row = append(row, telegram.Button{Text: "🔕 " + d, Data: callData(tgui.Call{Act: cfgSnooze, Args: append([]string{d}, ref...)})})
	}
	return row
}

// untilLabel is when a snooze ends: the time, and the weekday when that
// is not today.
func untilLabel(now, until time.Time) string {
	if dayStamp(until) != dayStamp(now) {
		return until.Format("Mon 15:04")
	}
	return until.Format("15:04")
}

// snoozePress handles "~1sz|<duration>|<key ref>": it snoozes the key and
// swaps the alert's snooze row for its Undo.
func (a *Agent) snoozePress(ctx context.Context, cb *telegram.Callback, c tgui.Call) {
	if len(c.Args) != 3 {
		a.refuseCallback(ctx, cb, false)
		return
	}
	d, ok := snoozeFor[c.Args[0]]
	key, valid, found := a.resolveSnoozeRef(c.Args[1:])
	switch {
	case !ok || !valid:
		a.refuseCallback(ctx, cb, false)
		return
	case !found:
		a.answer(ctx, cb, staleSnoozeToast)
		return
	}
	a.engine.Snooze(key, a.now().Add(d))
	a.answer(ctx, cb, "🔕 Snoozed for "+c.Args[0])
	a.editAlertMarkup(ctx, cb, key)
}

// unsnoozePress handles "~1uz|<key ref>": it lifts the key's snooze and
// brings the alert's snooze row back. Undoing twice is harmless.
func (a *Agent) unsnoozePress(ctx context.Context, cb *telegram.Callback, c tgui.Call) {
	key, valid, found := a.resolveSnoozeRef(c.Args)
	switch {
	case !valid:
		a.refuseCallback(ctx, cb, false)
		return
	case !found:
		a.answer(ctx, cb, staleSnoozeToast)
		return
	}
	a.engine.Unsnooze(key)
	a.answer(ctx, cb, "🔔 Alerts are on again")
	a.editAlertMarkup(ctx, cb, key)
}

// editAlertMarkup rebuilds the keyboard of the alert key in the pressed
// message, as it was sent: a plain login alert this process sent keeps
// its source row.
func (a *Agent) editAlertMarkup(ctx context.Context, cb *telegram.Callback, key string) {
	a.mu.Lock()
	sent, login := a.trustAlerts[cb.MessageID]
	a.mu.Unlock()
	kb := a.alertKeyboard(key)
	if login && sent == key {
		kb = a.loginKeyboard(key, key[strings.LastIndex(key, "@")+1:])
	}
	if err := a.send.EditMessageMarkup(ctx, cb.ChatID, cb.MessageID, kb); err != nil {
		log.Printf("agent: snooze: %v", err)
	}
}
