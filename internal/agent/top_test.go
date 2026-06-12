package agent

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/eliau2005/statixagent/internal/collect"
	"github.com/eliau2005/statixagent/internal/telegram"
)

func dispatchText(t *testing.T, a *Agent, text string) string {
	t.Helper()
	reply, _, ok := a.router.Dispatch(context.Background(), telegram.Update{ChatID: 42, Text: text})
	if !ok {
		t.Fatalf("Dispatch(%q): not handled", text)
	}
	return reply
}

func TestTopCommand(t *testing.T) {
	send := &fakeSender{}
	a := testAgent(send)
	a.src.TopProcs = func(ctx context.Context) ([]collect.Proc, error) {
		return []collect.Proc{
			{PID: 9, Comm: "stress", CPUPercent: 88, RSSBytes: 1 << 30},
		}, nil
	}
	reply := dispatchText(t, a, "/top")
	if !strings.Contains(reply, "stress") || !strings.Contains(reply, "88.0%") {
		t.Errorf("/top reply: %q", reply)
	}
}

func TestTopCommandUnavailable(t *testing.T) {
	send := &fakeSender{}
	a := testAgent(send) // src.TopProcs left nil
	if reply := dispatchText(t, a, "/top"); !strings.Contains(reply, "not available") {
		t.Errorf("/top without source: %q", reply)
	}
}

func TestTopCommandError(t *testing.T) {
	send := &fakeSender{}
	a := testAgent(send)
	a.src.TopProcs = func(ctx context.Context) ([]collect.Proc, error) {
		return nil, errors.New("proc walk failed")
	}
	if reply := dispatchText(t, a, "/top"); !strings.Contains(reply, "proc walk failed") {
		t.Errorf("/top error: %q", reply)
	}
}

func TestAlertKeyboardOffersTop(t *testing.T) {
	for _, key := range []string{"cpu", "mem"} {
		kb := alertKeyboard(key)
		found := false
		for _, row := range kb {
			for _, b := range row {
				if b.Data == "top" {
					found = true
				}
			}
		}
		if !found {
			t.Errorf("alertKeyboard(%q) has no Top button: %v", key, kb)
		}
	}
}
