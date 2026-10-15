// Package tgui is the agent's small Telegram UI layer: a versioned
// callback format, registries of screens and actions, and a dispatcher
// that turns a button press into a rendered view. It sits on the existing
// telegram client, which keeps doing the sending, HTML-safe fitting and
// token redaction.
package tgui

import (
	"errors"
	"fmt"
	"strings"
)

// Callback data format (see docs/telegram-ux-redesign.md §4.2):
//
//	~ <ver> <act> ( "|" <arg> )* [ "^" <from> ]
//	ver  = "1"
//	act  = [a-z]{1,3}             registered action ID, never reused
//	arg  = [A-Za-z0-9._:/*-]{1,}  values, digests and short IDs only
//	from = [a-z]{1,3}             screen to go Back to (optional)
//
// "~" never starts legacy data (lowercase words or "xx:" prefixes), so the
// two formats cannot collide. "|" keeps IPv6 arguments intact.
const prefix = "~1"

// MaxData is Telegram's limit on callback_data, in bytes.
const MaxData = 64

var (
	// ErrTooLong is data over MaxData bytes.
	ErrTooLong = errors.New("tgui: callback data over 64 bytes")
	// ErrMalformed is data that does not follow the format, including
	// any other version. Errors never quote the data: it may be forged.
	ErrMalformed = errors.New("tgui: malformed callback data")
)

// Call is one decoded button press.
type Call struct {
	Act  string   // registered action ID
	Args []string // nil when there are none
	From string   // one-hop Back target; "" means the screen's static parent
}

// IsCall reports whether data is in this format rather than legacy data.
func IsCall(data string) bool {
	return strings.HasPrefix(data, "~")
}

// Encode renders c as callback data. It fails on a field outside its
// charset or a result over MaxData bytes; tests building every keyboard
// turn either into a failure long before a user could see it.
func Encode(c Call) (string, error) {
	if !validID(c.Act) {
		return "", fmt.Errorf("%w: act must be 1-3 lowercase letters", ErrMalformed)
	}
	if c.From != "" && !validID(c.From) {
		return "", fmt.Errorf("%w: from must be 1-3 lowercase letters", ErrMalformed)
	}
	var b strings.Builder
	b.WriteString(prefix)
	b.WriteString(c.Act)
	for _, arg := range c.Args {
		if !validArg(arg) {
			return "", fmt.Errorf("%w: arg must be non-empty [A-Za-z0-9._:/*-]", ErrMalformed)
		}
		b.WriteByte('|')
		b.WriteString(arg)
	}
	if c.From != "" {
		b.WriteByte('^')
		b.WriteString(c.From)
	}
	if b.Len() > MaxData {
		return "", ErrTooLong
	}
	return b.String(), nil
}

// Decode parses callback data. It accepts only the canonical form, so
// every accepted Call encodes back to exactly the same data.
func Decode(data string) (Call, error) {
	if len(data) > MaxData {
		return Call{}, ErrTooLong
	}
	rest, ok := strings.CutPrefix(data, prefix)
	if !ok {
		return Call{}, ErrMalformed
	}
	var c Call
	rest, c.From, ok = strings.Cut(rest, "^")
	if ok && !validID(c.From) {
		return Call{}, ErrMalformed
	}
	parts := strings.Split(rest, "|")
	c.Act = parts[0]
	if !validID(c.Act) {
		return Call{}, ErrMalformed
	}
	for _, arg := range parts[1:] {
		if !validArg(arg) {
			return Call{}, ErrMalformed
		}
	}
	if len(parts) > 1 {
		c.Args = parts[1:]
	}
	return c, nil
}

// validID matches [a-z]{1,3}: action IDs and Back targets.
func validID(s string) bool {
	if len(s) < 1 || len(s) > 3 {
		return false
	}
	for i := 0; i < len(s); i++ {
		if s[i] < 'a' || s[i] > 'z' {
			return false
		}
	}
	return true
}

// validArg matches [A-Za-z0-9._:/*-]{1,}.
func validArg(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case 'a' <= c && c <= 'z', 'A' <= c && c <= 'Z', '0' <= c && c <= '9':
		case strings.IndexByte("._:/*-", c) >= 0:
		default:
			return false
		}
	}
	return true
}
