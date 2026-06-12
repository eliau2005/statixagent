package bot

import (
	"strings"
	"testing"
	"time"

	"github.com/eliau2005/statixagent/internal/collect"
	"github.com/eliau2005/statixagent/internal/procfs"
)

func TestDigest(t *testing.T) {
	now := time.Date(2026, 6, 13, 9, 0, 0, 0, time.UTC)
	d := DigestData{
		Since:   now.Add(-24 * time.Hour),
		PeakCPU: 87,
		PeakMem: 64,
		Alerts:  3,
		Crits:   1,
		Logins:  2,
		Fails:   12,
	}
	s := collect.Snapshot{
		CPUTotal: collect.CPUUsage{Percent: 12},
		Mem:      procfs.MemInfo{Total: 100, Available: 40},
		Uptime:   30 * 24 * time.Hour,
		Mounts: []collect.MountUsage{
			{MountPoint: "/", UsedPercent: 71},
			{MountPoint: "/home", UsedPercent: 45},
		},
	}
	out := Digest("vps1", d, s, now)
	for _, want := range []string{
		"vps1", "daily digest", "1d 0h", "30d 0h",
		"87%", "64%", "12%", "60%",
		"/ 71%", "/home 45%",
		"2 logins", "12 failed", "3 alerts", "1 critical",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("digest missing %q:\n%s", want, out)
		}
	}
}

func TestDigestQuietDay(t *testing.T) {
	now := time.Now()
	out := Digest("vps1", DigestData{Since: now.Add(-time.Hour)}, collect.Snapshot{}, now)
	if !strings.Contains(out, "no SSH activity") || !strings.Contains(out, "✅ no alerts") {
		t.Errorf("quiet digest: %s", out)
	}
}
