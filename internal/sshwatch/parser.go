// Package sshwatch implements MVP §3's SSH & security monitoring: parsing
// sshd log lines into events, brute-force detection, live sessions from
// utmp, authorized_keys change watching, and cached geo-IP lookups.
package sshwatch

import (
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"
)

// EventKind classifies one sshd log event.
type EventKind int

const (
	EventLogin EventKind = iota
	EventFailed
	EventInvalidUser
	EventDisconnect
)

func (k EventKind) String() string {
	switch k {
	case EventLogin:
		return "login"
	case EventFailed:
		return "failed"
	case EventInvalidUser:
		return "invalid-user"
	case EventDisconnect:
		return "disconnect"
	default:
		return "unknown"
	}
}

// Event is one parsed sshd occurrence.
type Event struct {
	Kind        EventKind
	User        string
	IP          string
	Port        int
	Method      string // "publickey", "password", "keyboard-interactive"
	KeyPrint    string // SHA256:... fingerprint for key logins
	InvalidUser bool   // failed attempt against a nonexistent account
	Root        bool   // convenience: User == "root"
	At          time.Time
}

var (
	// syslogPrefix matches "Jun 12 17:00:01 host sshd[1234]: " and the
	// journalctl short format alike; submatch 1 is the message.
	syslogPrefix = regexp.MustCompile(`sshd(?:-session)?\[\d+\]:\s+(.*)$`)

	acceptedRe = regexp.MustCompile(`^Accepted (\S+) for (\S+) from (\S+) port (\d+)(?:.*?(SHA256:\S+))?`)
	failedRe   = regexp.MustCompile(`^Failed (\S+) for (?:(invalid user) )?(\S+) from (\S+) port (\d+)`)
	invalidRe  = regexp.MustCompile(`^Invalid user (\S*) from (\S+)(?: port (\d+))?`)
	disconnRe  = regexp.MustCompile(`^Disconnected from (?:user (\S+) )?(\S+) port (\d+)`)
)

// ParseLine parses one sshd log line (raw message or with syslog/journal
// prefix). It returns the event and true, or false for lines the agent
// does not care about.
func ParseLine(line string, at time.Time) (Event, bool) {
	msg := line
	if m := syslogPrefix.FindStringSubmatch(line); m != nil {
		msg = m[1]
	}
	msg = strings.TrimSpace(msg)

	if m := acceptedRe.FindStringSubmatch(msg); m != nil {
		port, _ := strconv.Atoi(m[4])
		e := Event{
			Kind: EventLogin, Method: m[1], User: m[2], IP: m[3], Port: port,
			KeyPrint: m[5], Root: m[2] == "root", At: at,
		}
		return e, true
	}
	if m := failedRe.FindStringSubmatch(msg); m != nil {
		port, _ := strconv.Atoi(m[5])
		e := Event{
			Kind: EventFailed, Method: m[1], User: m[3], IP: m[4], Port: port,
			InvalidUser: m[2] != "", Root: m[3] == "root", At: at,
		}
		return e, true
	}
	if m := invalidRe.FindStringSubmatch(msg); m != nil {
		port, _ := strconv.Atoi(m[3])
		return Event{
			Kind: EventInvalidUser, User: m[1], IP: m[2], Port: port,
			InvalidUser: true, At: at,
		}, true
	}
	if m := disconnRe.FindStringSubmatch(msg); m != nil {
		port, _ := strconv.Atoi(m[3])
		return Event{Kind: EventDisconnect, User: m[1], IP: m[2], Port: port, At: at}, true
	}
	return Event{}, false
}

// History is a fixed-capacity ring of recent events for the bot's
// /ssh history and /ssh fails commands.
type History struct {
	mu     sync.RWMutex
	cap    int
	events []Event
}

// NewHistory returns a ring keeping at most capacity events.
func NewHistory(capacity int) *History {
	return &History{cap: capacity}
}

// Add appends an event, evicting the oldest beyond capacity.
func (h *History) Add(e Event) {
	h.mu.Lock()
	defer h.mu.Unlock()

	h.events = append(h.events, e)
	if len(h.events) > h.cap {
		h.events = h.events[len(h.events)-h.cap:]
	}
}

// Recent returns up to n latest events matching the filter (nil = all),
// newest first.
func (h *History) Recent(n int, match func(Event) bool) []Event {
	h.mu.RLock()
	events := append([]Event(nil), h.events...)
	h.mu.RUnlock()

	var out []Event
	for i := len(events) - 1; i >= 0 && len(out) < n; i-- {
		if match == nil || match(events[i]) {
			out = append(out, events[i])
		}
	}
	return out
}
