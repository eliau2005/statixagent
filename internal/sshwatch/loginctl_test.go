package sshwatch

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"
)

func fakeLoginctl(t *testing.T) RunFunc {
	t.Helper()
	return func(_ context.Context, name string, args ...string) (string, error) {
		if name != "loginctl" {
			t.Fatalf("unexpected command %s", name)
		}
		switch args[0] {
		case "list-sessions":
			return "  5 1000 eliau seat0  tty2 \n 12 1000 eliau -  pts/0 \n 14 0 root -  pts/1 \n", nil
		case "show-session":
			switch args[1] {
			case "5": // local console session — must be filtered
				return "Name=eliau\nTTY=tty2\nRemoteHost=\nRemote=no\nTimestamp=Thu 2026-06-12 08:00:01 UTC", nil
			case "12":
				return "Name=eliau\nTTY=pts/0\nRemoteHost=100.76.125.103\nRemote=yes\nTimestamp=Thu 2026-06-12 18:33:07 UTC", nil
			case "14":
				return "Name=root\nTTY=pts/1\nRemoteHost=203.0.113.7\nRemote=yes\nTimestamp=Thu 2026-06-12 18:40:00 IDT", nil
			}
		}
		return "", errors.New("unexpected args")
	}
}

func TestSessionsFromLoginctl(t *testing.T) {
	sessions, err := SessionsFromLoginctl(context.Background(), fakeLoginctl(t))
	if err != nil {
		t.Fatal(err)
	}
	if len(sessions) != 2 {
		t.Fatalf("sessions = %+v, want 2 (console filtered)", sessions)
	}
	s := sessions[0]
	if s.User != "eliau" || s.TTY != "pts/0" || s.Host != "100.76.125.103" {
		t.Errorf("session 0 = %+v", s)
	}
	want := time.Date(2026, 6, 12, 18, 33, 7, 0, time.UTC)
	if !s.Since.Equal(want) {
		t.Errorf("since = %s, want %s", s.Since, want)
	}
	// Unknown zone abbreviation (IDT) must still yield a usable time.
	if sessions[1].Since.IsZero() {
		t.Errorf("session with odd zone has zero time: %+v", sessions[1])
	}
}

func TestSessionsFromLoginctlListError(t *testing.T) {
	run := func(_ context.Context, _ string, _ ...string) (string, error) {
		return "", errors.New("loginctl: command not found")
	}
	if _, err := SessionsFromLoginctl(context.Background(), run); err == nil {
		t.Error("list failure must propagate")
	}
}

func TestSessionsFromLoginctlVanishedSession(t *testing.T) {
	run := func(_ context.Context, _ string, args ...string) (string, error) {
		if args[0] == "list-sessions" {
			return "7 1000 alice - pts/0\n", nil
		}
		return "", errors.New("No session '7' known") // ended between calls
	}
	sessions, err := SessionsFromLoginctl(context.Background(), run)
	if err != nil || len(sessions) != 0 {
		t.Errorf("vanished session must be skipped quietly: %v %v", sessions, err)
	}
}

func TestParseLoginctlTime(t *testing.T) {
	if _, err := parseLoginctlTime("Thu 2026-06-12 18:33:07 UTC"); err != nil {
		t.Errorf("UTC form: %v", err)
	}
	got, err := parseLoginctlTime("Thu 2026-06-12 18:33:07 XYZT")
	if err != nil {
		t.Errorf("unknown zone must fall back to local: %v", err)
	}
	if got.Hour() != 18 || got.Minute() != 33 {
		t.Errorf("fallback time = %s", got)
	}
	if !strings.Contains(trimZone("Thu 2026-06-12 18:33:07 XYZT"), "18:33:07") {
		t.Error("trimZone broke the time part")
	}
}
