package bot

import (
	"context"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/eliau2005/statixagent/internal/alert"
	"github.com/eliau2005/statixagent/internal/collect"
	"github.com/eliau2005/statixagent/internal/procfs"
	"github.com/eliau2005/statixagent/internal/services"
	"github.com/eliau2005/statixagent/internal/sshwatch"
	"github.com/eliau2005/statixagent/internal/sysfs"
	"github.com/eliau2005/statixagent/internal/telegram"
)

func TestRouterAllowlistAndDispatch(t *testing.T) {
	r := NewRouter(42)
	r.Handle("status", func(ctx context.Context, args []string) string { return "STATUS" })
	r.Handle("ssh", func(ctx context.Context, args []string) string {
		return "SSH:" + strings.Join(args, ",")
	})

	if _, _, ok := r.Dispatch(context.Background(), telegram.Update{ChatID: 999, Text: "/status"}); ok {
		t.Fatal("foreign chat must be dropped silently")
	}
	if _, _, ok := r.Dispatch(context.Background(), telegram.Update{ChatID: 42, Text: "hello"}); ok {
		t.Fatal("non-command text must be ignored")
	}
	reply, cmd, ok := r.Dispatch(context.Background(), telegram.Update{ChatID: 42, Text: "/status"})
	if !ok || reply != "STATUS" || cmd != "status" {
		t.Fatalf("dispatch = %q, %q, %v", reply, cmd, ok)
	}
	reply, _, _ = r.Dispatch(context.Background(), telegram.Update{ChatID: 42, Text: "/ssh history extra"})
	if reply != "SSH:history,extra" {
		t.Fatalf("args = %q", reply)
	}
	reply, cmd, _ = r.Dispatch(context.Background(), telegram.Update{ChatID: 42, Text: "/STATUS@mybot"})
	if reply != "STATUS" || cmd != "status" {
		t.Fatalf("case/@bot form = %q, %q", reply, cmd)
	}
	reply, _, ok = r.Dispatch(context.Background(), telegram.Update{ChatID: 42, Text: "/nope"})
	if !ok || !strings.Contains(reply, "Unknown command") {
		t.Fatalf("unknown = %q, %v", reply, ok)
	}

	// Invoke runs handlers directly for keyboard callbacks.
	reply, ok = r.Invoke(context.Background(), "status", nil)
	if !ok || reply != "STATUS" {
		t.Fatalf("Invoke = %q, %v", reply, ok)
	}
	if _, ok := r.Invoke(context.Background(), "ghost", nil); ok {
		t.Fatal("Invoke of unknown command must report false")
	}
}

func TestFormatHelpers(t *testing.T) {
	if got := Bytes(1536); got != "1.5 KiB" {
		t.Errorf("Bytes = %q", got)
	}
	if got := BytesShort(8 << 30); got != "8.0G" {
		t.Errorf("BytesShort = %q", got)
	}
	if got := BytesShort(312); got != "312B" {
		t.Errorf("BytesShort small = %q", got)
	}
	if got := Dur(26*time.Hour + 10*time.Minute); got != "1d 2h" {
		t.Errorf("Dur = %q", got)
	}
	if got := bar(73); got != "▰▰▰▰▰▰▰▱▱▱" {
		t.Errorf("bar = %q", got)
	}
	if got := pad("abc", 5); got != "abc  " {
		t.Errorf("pad right = %q", got)
	}
	if got := pad("abc", -5); got != "  abc" {
		t.Errorf("pad left = %q", got)
	}
	if got := pad("abcdefgh", 4); got != "abcd" {
		t.Errorf("pad truncate = %q", got)
	}
}

func sampleSnapshot() collect.Snapshot {
	return collect.Snapshot{
		CPUTotal: collect.CPUUsage{Name: "cpu", Percent: 42.5},
		PerCore: []collect.CPUUsage{
			{Name: "cpu0", Percent: 80},
			{Name: "cpu1", Percent: 5},
		},
		Load: procfs.LoadAvg{Load1: 0.52, Load5: 0.58, Load15: 0.59},
		Mem: procfs.MemInfo{
			Total: 8 << 30, Available: 4 << 30, Free: 1 << 30,
			Buffers: 1 << 29, Cached: 1 << 30, SwapTotal: 2 << 30, SwapFree: 2 << 30,
		},
		Net: []collect.NetRate{
			{Name: "eth0", RxBytesPerSec: 1 << 20, TxBytesPerSec: 1 << 18, RxTotal: 5 << 30, TxTotal: 1 << 30},
			{Name: "docker0"}, // zero traffic — hidden from /status
		},
		Mounts: []collect.MountUsage{
			{MountPoint: "/", TotalBytes: 40 << 30, FreeBytes: 10 << 30, UsedPercent: 75},
			{MountPoint: "/boot", TotalBytes: 2 << 30, FreeBytes: 1 << 30, UsedPercent: 16},
		},
		Uptime:  73 * time.Hour,
		NumProc: 142,
		FileNR:  procfs.FileNR{Allocated: 2080, Max: 9000},
	}
}

func TestStatusFormat(t *testing.T) {
	th := sysfs.Thermal{Sensors: []sysfs.TempSensor{{Label: "pkg", Celsius: 61}}, Throttled: true}
	pw := sysfs.Power{HasAC: true, ACOnline: false, HasBattery: true,
		Batteries: []sysfs.Battery{{Name: "BAT0", Percent: 73, Status: "Discharging", TimeToEmpty: 4 * time.Hour}}}
	out := Status("myvps", sampleSnapshot(), th, pw)
	for _, want := range []string{
		"<b>myvps</b>", "⏱ 3d 1h", "<pre>",
		"CPU   ▰▰▰▰▱▱▱▱▱▱", "RAM   ▰▰▰▰▰▱▱▱▱▱", "4.0G/8.0G",
		"DISK", "75%", "/boot",
		"🌐 eth0", "🌡 61°C ⚠️", "🔋 73% ⚡4h 0m",
		"142 procs · 2080 fds · load 0.52",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("Status missing %q in:\n%s", want, out)
		}
	}
}

// /boot must never appear outside <pre>/<code>, or Telegram renders it as
// a clickable bot command (the bug seen in the real chat export).
func TestPathsNeverLinkifyAsCommands(t *testing.T) {
	outsidePre := regexp.MustCompile(`(?s)</?pre>|<code>.*?</code>`)
	for name, out := range map[string]string{
		"Status": Status("h", sampleSnapshot(), sysfs.Thermal{}, sysfs.Power{}),
		"Disk":   Disk(sampleSnapshot()),
	} {
		stripped := outsidePre.ReplaceAllString(out, "")
		// Remove everything inside pre blocks.
		if i := strings.Index(out, "<pre>"); i >= 0 {
			j := strings.LastIndex(out, "</pre>")
			stripped = out[:i] + out[j+len("</pre>"):]
		}
		if strings.Contains(stripped, "/boot") {
			t.Errorf("%s leaks /boot outside <pre>:\n%s", name, out)
		}
	}
}

func TestStatusHidesIdleInterfaces(t *testing.T) {
	out := Status("h", sampleSnapshot(), sysfs.Thermal{}, sysfs.Power{})
	if strings.Contains(out, "docker0") {
		t.Errorf("zero-traffic interface must be hidden from /status:\n%s", out)
	}
	// But /net still lists it under idle.
	if net := Net(sampleSnapshot()); !strings.Contains(net, "idle: docker0") {
		t.Errorf("/net must list idle interfaces:\n%s", net)
	}
}

func TestSpark(t *testing.T) {
	if got := Spark(nil, 100); got != "" {
		t.Errorf("empty = %q", got)
	}
	if got := Spark([]float64{0, 50, 100}, 100); got != "▁▅█" {
		t.Errorf("ramp = %q", got)
	}
	// Autoscale: peak maps to the top level.
	if got := Spark([]float64{1, 2, 4}, 0); got != "▃▅█" {
		t.Errorf("autoscale = %q", got)
	}
	if got := Spark([]float64{0, 0}, 0); got != "▁▁" {
		t.Errorf("all-zero = %q", got)
	}
}

func TestSectionFormats(t *testing.T) {
	s := sampleSnapshot()
	if out := CPU(s, "▁▂▃"); !strings.Contains(out, "cpu0") || !strings.Contains(out, "trend ▁▂▃") {
		t.Errorf("CPU:\n%s", out)
	}
	if out := CPU(s, ""); strings.Contains(out, "trend") {
		t.Errorf("CPU without trend:\n%s", out)
	}
	if out := Mem(s, "▁▂▃"); !strings.Contains(out, "available") || !strings.Contains(out, "trend ▁▂▃") {
		t.Errorf("Mem:\n%s", out)
	}
	if out := Disk(s); !strings.Contains(out, "10.0G free of 40.0G") {
		t.Errorf("Disk:\n%s", out)
	}
	if out := Net(s); !strings.Contains(out, "Σ↓") || !strings.Contains(out, "5.0G") {
		t.Errorf("Net:\n%s", out)
	}
	if out := Temp(sysfs.Thermal{}); !strings.Contains(out, "VPS") {
		t.Errorf("Temp empty:\n%s", out)
	}
	if out := Battery(sysfs.Power{}); !strings.Contains(out, "VPS") {
		t.Errorf("Battery empty:\n%s", out)
	}
}

func TestTempFiltersAndDedupes(t *testing.T) {
	th := sysfs.Thermal{
		Sensors: []sysfs.TempSensor{
			{Label: "acpitz", Celsius: 41},
			{Label: "SEN1", Celsius: 0},          // junk: dropped
			{Label: "SEN2", Celsius: -5},         // junk: dropped
			{Label: "acpitz/temp1", Celsius: 41}, // duplicate of acpitz: dropped
			{Label: "x86_pkg_temp", Celsius: 40},
			{Label: "Core 0", Celsius: 52},
		},
		Fans: []sysfs.Fan{{Label: "cpu_fan", RPM: 2400}},
	}
	out := Temp(th)
	for _, junk := range []string{"SEN1", "SEN2", "acpitz/temp1"} {
		if strings.Contains(out, junk) {
			t.Errorf("Temp must drop %q:\n%s", junk, out)
		}
	}
	if !strings.Contains(out, "acpitz") || !strings.Contains(out, "2400 RPM") {
		t.Errorf("Temp lost real sensors:\n%s", out)
	}
	// Hottest first with the fire marker.
	if !strings.Contains(out, "🔥 Core 0") {
		t.Errorf("hottest sensor must lead with 🔥:\n%s", out)
	}
}

func TestBatteryFormat(t *testing.T) {
	pw := sysfs.Power{HasAC: true, ACOnline: true, HasBattery: true,
		Batteries: []sysfs.Battery{{Name: "BAT0", Percent: 79, Status: "Not charging", HealthPercent: 67}}}
	out := Battery(pw)
	for _, want := range []string{"<b>BAT0</b>", "Not charging", "charge", "79%", "health", "67% of design", "🔌 plugged in"} {
		if !strings.Contains(out, want) {
			t.Errorf("Battery missing %q:\n%s", want, out)
		}
	}
}

func TestServiceAndSSHFormats(t *testing.T) {
	out := ServiceResults([]services.Result{
		{Name: "db.service", State: services.StateDown, Detail: "failed/failed"},
		{Name: "nginx.service", State: services.StateOK, Detail: "active/running"},
	})
	if !strings.Contains(out, "1/2 up") {
		t.Errorf("services header:\n%s", out)
	}
	if strings.Index(out, "nginx") > strings.Index(out, "db.service") {
		t.Errorf("healthy services must sort first:\n%s", out)
	}

	now := time.Date(2026, 6, 12, 18, 0, 0, 0, time.UTC)
	sess := Sessions(
		[]sshwatch.Session{{User: "alice", TTY: "pts/0", Host: "203.0.113.7", Since: now.Add(-30 * time.Minute)}},
		map[string]sshwatch.GeoInfo{"203.0.113.7": {Country: "Germany", City: "Berlin"}},
		now,
	)
	for _, want := range []string{"Active sessions</b> — 1", "alice", "pts/0", "30m 0s", "📍 Berlin, Germany"} {
		if !strings.Contains(sess, want) {
			t.Errorf("sessions missing %q:\n%s", want, sess)
		}
	}

	ev := SSHEvents("Failed attempts", []sshwatch.Event{
		{Kind: sshwatch.EventFailed, User: "root", IP: "192.0.2.4", Method: "password", At: now},
		{Kind: sshwatch.EventInvalidUser, User: "admin<script>", IP: "192.0.2.4", InvalidUser: true, At: now},
	})
	if !strings.Contains(ev, "❌") || !strings.Contains(ev, "invalid user") {
		t.Errorf("events:\n%s", ev)
	}
	if strings.Contains(ev, "<script>") {
		t.Error("usernames must be HTML-escaped")
	}
}

func TestAlertMsg(t *testing.T) {
	a := alert.Alert{Key: "cpu", Severity: alert.Critical, Title: "CPU usage", Body: "97.0% is above the 90.0% threshold"}
	out := AlertMsg("myvps", a)
	for _, want := range []string{"🚨", "<b>CPU usage</b>", "myvps", "<blockquote>97.0%"} {
		if !strings.Contains(out, want) {
			t.Errorf("alert missing %q:\n%s", want, out)
		}
	}
	rec := alert.Alert{Key: "cpu", Title: "CPU usage", Body: "recovered: now 50.0%", Resolved: true}
	if out := AlertMsg("myvps", rec); !strings.Contains(out, "✅") {
		t.Errorf("resolved alert:\n%s", out)
	}
}
