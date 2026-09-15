package agent

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/eliau2005/statixagent/internal/alert"
	"github.com/eliau2005/statixagent/internal/collect"
	"github.com/eliau2005/statixagent/internal/procfs"
	"github.com/eliau2005/statixagent/internal/telegram"
)

func TestSnoozeCallback(t *testing.T) {
	send := &fakeSender{}
	a := testAgent(send)
	ctx := context.Background()
	hot := collect.Snapshot{CPUTotal: collect.CPUUsage{Percent: 97}, Mem: procfs.MemInfo{Total: 100, Available: 60}}

	a.handleCallback(ctx, &telegram.Callback{ID: "cb1", ChatID: 42, MessageID: 7, Data: a.snoozeCallbackData("cpu")})

	send.mu.Lock()
	answered := append([]string(nil), send.answered...)
	send.mu.Unlock()
	if len(answered) == 0 || !strings.Contains(answered[0], "Snoozed for 1h") {
		t.Fatalf("snooze toast = %v", answered)
	}

	// The snoozed key stays quiet; everything else still evaluates.
	// Run the full sustain window so the rule would otherwise fire.
	now := time.Now()
	step := a.cfg.SampleInterval.Duration
	for i := range systemSustainN(a) {
		if al := keyed(a.evalSystem(hot, now.Add(time.Duration(i)*step)), "cpu"); al != nil {
			t.Fatalf("cpu alerted while snoozed: %+v", al)
		}
	}

	// Foreign chats cannot snooze.
	a.handleCallback(ctx, &telegram.Callback{ID: "cb2", ChatID: 999, MessageID: 7, Data: a.snoozeCallbackData("mem")})
	if keyed(evalSustained(a, collect.Snapshot{Mem: procfs.MemInfo{Total: 100, Available: 5}}, time.Now()), "mem") == nil {
		t.Fatal("mem did not alert; foreign-chat snooze was honored")
	}
}

func TestSnoozeShortKeySurvivesRestart(t *testing.T) {
	before := testAgent(&fakeSender{})
	data := before.snoozeCallbackData("docker:api")
	if data != "snz:docker:api" {
		t.Fatalf("short snooze callback = %q", data)
	}

	// A fresh agent has no hash map entries, just as after a restart.
	send := &fakeSender{}
	after := testAgent(send)
	after.handleCallback(context.Background(), &telegram.Callback{
		ID: "cb", ChatID: 42, MessageID: 1, Data: data,
	})
	if al := after.engine.Event("docker:api", "t", "b", alert.Warning, time.Now(), 0); al != nil {
		t.Fatalf("short key should be snoozed after restart, got %+v", al)
	}
}

func TestSnoozeLongKeyFitsCallbackData(t *testing.T) {
	send := &fakeSender{}
	a := testAgent(send)
	long := "docker-restart:myproject-very-long-service-name-worker-queue-1"
	if len("snz:"+long) <= 64 {
		t.Fatalf("fixture should exceed 64 as raw snz data; got %d", len("snz:"+long))
	}
	kb := a.alertKeyboard(long)
	found := ""
	for _, row := range kb {
		for _, b := range row {
			if strings.HasPrefix(b.Data, "snz:") {
				found = b.Data
			}
		}
	}
	if found == "" {
		t.Fatal("missing snooze button")
	}
	if len(found) > 64 {
		t.Fatalf("snooze callback_data %q is %d bytes", found, len(found))
	}
	ctx := context.Background()
	a.handleCallback(ctx, &telegram.Callback{ID: "cb", ChatID: 42, MessageID: 1, Data: found})
	// Resolve must have snoozed the original long key.
	if al := a.engine.Event(long, "t", "b", alert.Warning, time.Now(), 0); al != nil {
		t.Fatalf("long key should be snoozed, got %+v", al)
	}
}

func TestSnoozeStaleHash(t *testing.T) {
	send := &fakeSender{}
	a := testAgent(send)
	ctx := context.Background()
	a.handleCallback(ctx, &telegram.Callback{ID: "cb", ChatID: 42, MessageID: 1, Data: "snz:hdeadbeef"})
	send.mu.Lock()
	answered := append([]string(nil), send.answered...)
	send.mu.Unlock()
	if len(answered) == 0 || !strings.Contains(answered[0], "stale snooze") {
		t.Fatalf("want stale snooze toast, got %v", answered)
	}
}
