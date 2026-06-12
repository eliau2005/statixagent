package agent

import (
	"context"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/eliau2005/statixagent/internal/alert"
	"github.com/eliau2005/statixagent/internal/collect"
	"github.com/eliau2005/statixagent/internal/config"
	"github.com/eliau2005/statixagent/internal/procfs"
	"github.com/eliau2005/statixagent/internal/sysfs"
	"github.com/eliau2005/statixagent/internal/telegram"
)

type fakeSender struct {
	mu   sync.Mutex
	sent []string
}

func (f *fakeSender) SendMessage(_ context.Context, _ int64, html string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.sent = append(f.sent, html)
	return nil
}

func (f *fakeSender) all() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.sent...)
}

func (f *fakeSender) find(sub string) bool {
	for _, s := range f.all() {
		if strings.Contains(s, sub) {
			return true
		}
	}
	return false
}

func testConfig() config.Config {
	c := config.Default()
	c.Telegram.Token = "t"
	c.Telegram.ChatID = 42
	c.SampleInterval = config.Duration{Duration: time.Second}
	return c
}

func testAgent(send *fakeSender) *Agent {
	src := Sources{
		Hostname: "testhost",
		Sample: func(ctx context.Context) (collect.Sample, error) {
			return collect.Sample{
				At:   time.Now(),
				Stat: procfs.Stat{Aggregate: procfs.CPUStat{Name: "cpu", User: 100, Idle: 900}},
				Mem:  procfs.MemInfo{Total: 8 << 30, Available: 4 << 30},
			}, nil
		},
		Thermal: func() (sysfs.Thermal, error) { return sysfs.Thermal{}, nil },
		Power:   func() (sysfs.Power, error) { return sysfs.Power{}, nil },
	}
	return New(testConfig(), send, nil, src)
}

func TestThresholdAlertPushed(t *testing.T) {
	send := &fakeSender{}
	a := testAgent(send)
	now := time.Now()

	hot := collect.Snapshot{CPUTotal: collect.CPUUsage{Percent: 97}, Mem: procfs.MemInfo{Total: 100, Available: 60}}
	for _, al := range a.evalSystem(hot, now) {
		if al != nil {
			a.push(context.Background(), "ALERT:"+al.Title)
		}
	}
	if !send.find("ALERT:CPU usage") {
		t.Errorf("cpu alert not pushed: %v", send.all())
	}
	if send.find("ALERT:Memory") {
		t.Errorf("memory at 40%% must not alert: %v", send.all())
	}
}

func TestPowerLossAlert(t *testing.T) {
	send := &fakeSender{}
	a := testAgent(send)
	now := time.Now()

	plugged := sysfs.Power{HasAC: true, ACOnline: true, HasBattery: true,
		Batteries: []sysfs.Battery{{Percent: 80}}}
	unplugged := sysfs.Power{HasAC: true, ACOnline: false, HasBattery: true,
		Batteries: []sysfs.Battery{{Percent: 79, TimeToEmpty: 3 * time.Hour}}}

	if als := a.evalPower(plugged, now); countNonNil(als) != 0 {
		t.Fatalf("first reading must not alert: %+v", als)
	}
	als := a.evalPower(unplugged, now.Add(time.Minute))
	if countNonNil(als) != 1 {
		t.Fatalf("unplug must alert exactly once: %+v", als)
	}
	if als[0].Severity.String() != "critical" || !strings.Contains(als[0].Body, "79%") {
		t.Errorf("power loss alert = %+v", als[0])
	}
	als = a.evalPower(plugged, now.Add(5*time.Minute))
	found := false
	for _, al := range als {
		if al != nil && al.Title == "Power restored" {
			found = true
		}
	}
	if !found {
		t.Errorf("replug must notify: %+v", als)
	}
}

func TestRootLoginAlertAndBruteForce(t *testing.T) {
	send := &fakeSender{}
	a := testAgent(send)
	ctx := context.Background()
	now := time.Now()

	a.handleAuthLine(ctx, "Accepted publickey for root from 203.0.113.7 port 51234 ssh2: ED25519 SHA256:xyz", now)
	if !send.find("ROOT SSH login") {
		t.Errorf("root login must push critical alert: %v", send.all())
	}

	for i := 0; i < 5; i++ {
		a.handleAuthLine(ctx, "Failed password for invalid user admin from 192.0.2.4 port 33000 ssh2", now.Add(time.Duration(i)*time.Second))
	}
	if !send.find("Brute-force attack") {
		t.Errorf("5 failures must trigger brute alert: %v", send.all())
	}

	if got := len(a.hist.Recent(100, nil)); got != 6 {
		t.Errorf("history = %d events, want 6", got)
	}
}

func TestBotCommandsThroughRouter(t *testing.T) {
	send := &fakeSender{}
	a := testAgent(send)
	ctx := context.Background()

	// Seed a snapshot the handlers can read.
	a.sampleOnce(ctx)

	reply, ok := a.router.Dispatch(ctx, telegram.Update{ChatID: 42, Text: "/status"})
	if !ok || !strings.Contains(reply, "testhost") {
		t.Errorf("/status = %q", reply)
	}
	reply, _ = a.router.Dispatch(ctx, telegram.Update{ChatID: 42, Text: "/help"})
	if !strings.Contains(reply, "/ssh history") || !strings.Contains(reply, "<b>Security</b>") {
		t.Errorf("/help = %q", reply)
	}
	reply, _ = a.router.Dispatch(ctx, telegram.Update{ChatID: 42, Text: "/update"})
	if !strings.Contains(reply, "not configured") {
		t.Errorf("/update without updater = %q", reply)
	}
	reply, _ = a.router.Dispatch(ctx, telegram.Update{ChatID: 42, Text: "/ssh history"})
	if !strings.Contains(reply, "Nothing recorded") {
		t.Errorf("/ssh history empty = %q", reply)
	}
	if _, ok := a.router.Dispatch(ctx, telegram.Update{ChatID: 666, Text: "/status"}); ok {
		t.Error("foreign chat must be ignored")
	}
}

func TestUpdateCommandFlow(t *testing.T) {
	send := &fakeSender{}
	a := testAgent(send)
	applied := false
	a.src.UpdateCheck = func(ctx context.Context) (string, bool, error) { return "v1.2.0", true, nil }
	a.src.UpdateApply = func(ctx context.Context) error { applied = true; return nil }
	ctx := context.Background()

	reply, _ := a.router.Dispatch(ctx, telegram.Update{ChatID: 42, Text: "/update"})
	if !strings.Contains(reply, "v1.2.0") || !strings.Contains(reply, "/update confirm") {
		t.Errorf("/update = %q", reply)
	}
	if applied {
		t.Fatal("/update alone must not apply (MVP §7 confirmation rule)")
	}
	reply, _ = a.router.Dispatch(ctx, telegram.Update{ChatID: 42, Text: "/update confirm"})
	if !applied || !strings.Contains(reply, "restart") {
		t.Errorf("confirm: applied=%v reply=%q", applied, reply)
	}
}

func TestRunStartsAndStops(t *testing.T) {
	send := &fakeSender{}
	a := testAgent(send)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- a.Run(ctx) }()

	deadline := time.After(3 * time.Second)
	for !send.find("statix-agent started") {
		select {
		case <-deadline:
			t.Fatal("startup message not sent")
		case <-time.After(10 * time.Millisecond):
		}
	}
	cancel()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("Run did not stop on cancel")
	}
}

func countNonNil(als []*alert.Alert) int {
	n := 0
	for _, a := range als {
		if a != nil {
			n++
		}
	}
	return n
}
