package agent

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/eliau2005/statixagent/internal/collect"
	"github.com/eliau2005/statixagent/internal/procfs"
	"github.com/eliau2005/statixagent/internal/telegram"
)

func TestSnoozeCallback(t *testing.T) {
	send := &fakeSender{}
	a := testAgent(send)
	ctx := context.Background()
	hot := collect.Snapshot{CPUTotal: collect.CPUUsage{Percent: 97}, Mem: procfs.MemInfo{Total: 100, Available: 60}}

	a.handleCallback(ctx, &telegram.Callback{ID: "cb1", ChatID: 42, MessageID: 7, Data: "snz:cpu"})

	send.mu.Lock()
	answered := append([]string(nil), send.answered...)
	send.mu.Unlock()
	if len(answered) == 0 || !strings.Contains(answered[0], "Snoozed for 1h") {
		t.Fatalf("snooze toast = %v", answered)
	}

	// The snoozed key stays quiet; everything else still evaluates.
	for _, al := range a.evalSystem(hot, time.Now()) {
		if al != nil && al.Key == "cpu" {
			t.Fatalf("cpu alerted while snoozed: %+v", al)
		}
	}

	// Foreign chats cannot snooze.
	a.handleCallback(ctx, &telegram.Callback{ID: "cb2", ChatID: 999, MessageID: 7, Data: "snz:mem"})
	for _, al := range a.evalSystem(collect.Snapshot{Mem: procfs.MemInfo{Total: 100, Available: 5}}, time.Now()) {
		if al != nil && al.Key == "mem" {
			return // mem still alerts — foreign snooze was ignored
		}
	}
	t.Fatal("mem did not alert; foreign-chat snooze was honored")
}
