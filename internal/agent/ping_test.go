package agent

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"
)

func TestPingCommand(t *testing.T) {
	send := &fakeSender{}
	a := testAgent(send)

	// Not wired (non-linux test build).
	if reply := dispatchText(t, a, "/ping example.com"); !strings.Contains(reply, "not available") {
		t.Errorf("/ping without source: %q", reply)
	}

	a.src.Latency = func(_ context.Context, addr string) (time.Duration, error) {
		switch addr {
		case "db.example:5432":
			return 12300 * time.Microsecond, nil
		case "fast.example":
			return 480 * time.Microsecond, nil
		default:
			return 0, errors.New("connect: connection refused")
		}
	}

	if reply := dispatchText(t, a, "/ping"); !strings.Contains(reply, "Usage:") {
		t.Errorf("/ping usage: %q", reply)
	}
	if reply := dispatchText(t, a, "/ping db.example:5432"); !strings.Contains(reply, "12ms") {
		t.Errorf("/ping ms: %q", reply)
	}
	if reply := dispatchText(t, a, "/ping fast.example"); !strings.Contains(reply, "0.48ms") {
		t.Errorf("/ping sub-ms: %q", reply)
	}
	if reply := dispatchText(t, a, "/ping gone.example"); !strings.Contains(reply, "unreachable") {
		t.Errorf("/ping error: %q", reply)
	}
}

func TestFmtLatency(t *testing.T) {
	cases := []struct {
		d    time.Duration
		want string
	}{
		{480 * time.Microsecond, "0.48ms"},
		{12 * time.Millisecond, "12ms"},
		{1500 * time.Millisecond, "1.5s"},
	}
	for _, c := range cases {
		if got := fmtLatency(c.d); got != c.want {
			t.Errorf("fmtLatency(%v) = %q, want %q", c.d, got, c.want)
		}
	}
}
