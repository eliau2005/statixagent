package sshwatch

import (
	"context"
	"strings"
	"time"
)

// RunFunc executes an external command and returns its combined output.
// It mirrors services.Runner without importing it.
type RunFunc func(ctx context.Context, name string, args ...string) (string, error)

// SessionsFromLoginctl lists remote sessions via systemd-logind. It is the
// fallback for systems without /var/run/utmp (Ubuntu 24.10+, Fedora with
// wtmpdb): logind tracks every PAM session, and sshd registers there.
func SessionsFromLoginctl(ctx context.Context, run RunFunc) ([]Session, error) {
	list, err := run(ctx, "loginctl", "list-sessions", "--no-legend")
	if err != nil {
		return nil, err
	}
	var out []Session
	for _, line := range strings.Split(list, "\n") {
		fields := strings.Fields(line)
		if len(fields) == 0 {
			continue
		}
		id := fields[0]
		show, err := run(ctx, "loginctl", "show-session", id,
			"-p", "Name", "-p", "TTY", "-p", "RemoteHost", "-p", "Remote", "-p", "Timestamp")
		if err != nil {
			continue // session may have ended between list and show
		}
		props := map[string]string{}
		for _, pl := range strings.Split(show, "\n") {
			if k, v, ok := strings.Cut(strings.TrimSpace(pl), "="); ok {
				props[k] = v
			}
		}
		if props["Remote"] != "yes" {
			continue // console/seat session, not SSH
		}
		s := Session{
			User: props["Name"],
			TTY:  props["TTY"],
			Host: props["RemoteHost"],
		}
		if ts, err := parseLoginctlTime(props["Timestamp"]); err == nil {
			s.Since = ts
		}
		out = append(out, s)
	}
	return out, nil
}

// parseLoginctlTime parses logind's Timestamp format:
// "Thu 2026-06-12 18:33:07 UTC" (the zone may be a local abbreviation, in
// which case the machine's own zone applies — good enough for durations).
func parseLoginctlTime(s string) (time.Time, error) {
	s = strings.TrimSpace(s)
	if t, err := time.Parse("Mon 2006-01-02 15:04:05 MST", s); err == nil {
		return t, nil
	}
	return time.ParseInLocation("Mon 2006-01-02 15:04:05", trimZone(s), time.Local)
}

// trimZone drops a trailing zone word that time.Parse could not resolve.
func trimZone(s string) string {
	if i := strings.LastIndexByte(s, ' '); i > 0 {
		if last := s[i+1:]; len(last) >= 2 && last[0] >= 'A' && last[0] <= 'Z' {
			return s[:i]
		}
	}
	return s
}
