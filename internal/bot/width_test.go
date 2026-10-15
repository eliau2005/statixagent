package bot

import (
	"strings"
	"testing"
	"time"

	"github.com/eliau2005/statixagent/internal/collect"
	"github.com/eliau2005/statixagent/internal/services"
	"github.com/eliau2005/statixagent/internal/sshwatch"
	"github.com/eliau2005/statixagent/internal/sysfs"
)

func TestWidth(t *testing.T) {
	for _, tc := range []struct {
		s    string
		want int
	}{
		{"abc", 3},
		{"✅ ok", 5},
		{"⚠️ x", 4}, // U+26A0 plus a zero-width variation selector
		{"🖥 CPU", 6},
		{"⬅️", 2},
		{"↓1.2 ↑0.3", 9},
		{"▰▱─", 3},
		{"°C", 2},
	} {
		if got := Width(tc.s); got != tc.want {
			t.Errorf("Width(%q) = %d, want %d", tc.s, got, tc.want)
		}
	}
}

func TestClip(t *testing.T) {
	if got := Clip("short", 10); got != "short" {
		t.Errorf("Clip short = %q", got)
	}
	if got := Clip("/var/lib/docker/overlay", 10); got != "/var/lib/…" || Width(got) != 10 {
		t.Errorf("Clip long = %q", got)
	}
	if got := Clip("✅✅✅✅", 5); Width(got) > 5 {
		t.Errorf("Clip emoji = %q (%d columns)", got, Width(got))
	}
}

func TestWrap(t *testing.T) {
	ip := "   from ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff"
	rows := Wrap(ip)
	if len(rows) < 2 || strings.ReplaceAll(strings.Join(rows, ""), " ", "") != strings.ReplaceAll(ip, " ", "") {
		t.Errorf("Wrap lost text: %q", rows)
	}
	long := " ✅ " + strings.Repeat("x", 250) + " detail words here"
	for _, r := range append(rows, Wrap(long)...) {
		if Width(r) > PreCols {
			t.Errorf("row %q is %d columns", r, Width(r))
		}
	}
	if got := Wrap("fits"); len(got) != 1 || got[0] != "fits" {
		t.Errorf("Wrap short = %q", got)
	}
}

// Every <pre> row a formatter builds fits a phone, however long the input.
func TestFormatsFitPhone(t *testing.T) {
	s := sampleSnapshot()
	s.Mounts = append(s.Mounts, collect.MountUsage{MountPoint: "/var/lib/docker/overlay2/" + strings.Repeat("a", 64), UsedPercent: 100})
	s.Disks = []collect.DiskRate{{Name: "nvme0n1p12", ReadBytesPerSec: 999 << 20, WriteBytesPerSec: 999 << 20, IOPS: 123456}}
	long := strings.Repeat("n", 80)
	now := time.Date(2026, 6, 12, 18, 0, 0, 0, time.UTC)
	outs := []string{
		Status("h", s, sysfs.Thermal{Sensors: []sysfs.TempSensor{{Label: long, Celsius: 99}}}, sysfs.Power{}),
		CPU(s, "▁▂▃▄▅▆▇█▁▂▃▄▅▆▇█▁▂▃▄▅▆▇█"), Mem(s, ""), Disk(s), Net(s, "", ""),
		Temp(sysfs.Thermal{Sensors: []sysfs.TempSensor{{Label: long, Celsius: 99}}, Throttled: true}),
		Battery(sysfs.Power{HasBattery: true, Batteries: []sysfs.Battery{{Name: "BAT0", Percent: 100, HealthPercent: 100, Watts: 12.5, TimeToEmpty: time.Hour}}}),
		ServiceResults([]services.Result{{Name: long, State: services.StateDown, Detail: long}}),
		Top([]collect.Proc{{PID: 4194304, Comm: long, CPUPercent: 100.0, RSSBytes: 1 << 40}}, 1<<41),
		Sessions([]sshwatch.Session{{User: long, TTY: "pts/100", Host: "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff", Since: now.Add(-50 * time.Hour)}}, nil, now),
		Digest("h", DigestData{Since: now.Add(-24 * time.Hour), Logins: 12345, Fails: 67890, Alerts: 999, Crits: 99}, s, now),
	}
	for _, out := range outs {
		for _, row := range PreRows(out) {
			if Width(row) > PreCols {
				t.Errorf("row %q is %d columns in:\n%s", row, Width(row), out)
			}
		}
	}
}
