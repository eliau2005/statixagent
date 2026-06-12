package bot

import (
	"strings"
	"testing"

	"github.com/eliau2005/statixagent/internal/collect"
)

func TestTop(t *testing.T) {
	procs := []collect.Proc{
		{PID: 1, Comm: "systemd", CPUPercent: 0.1, RSSBytes: 10 << 20},
		{PID: 200, Comm: "postgres", CPUPercent: 5, RSSBytes: 2 << 30},
		{PID: 300, Comm: "miner", CPUPercent: 95, RSSBytes: 50 << 20},
	}
	out := Top(procs, 8<<30)
	if !strings.Contains(out, "3 running") {
		t.Errorf("missing count: %q", out)
	}
	// miner leads the CPU list, postgres leads the memory list
	cpuIdx := strings.Index(out, "miner")
	memIdx := strings.Index(out, "postgres")
	if cpuIdx < 0 || memIdx < 0 || cpuIdx > memIdx {
		t.Errorf("ordering wrong (miner@%d postgres@%d): %q", cpuIdx, memIdx, out)
	}
	if !strings.Contains(out, "95.0%") {
		t.Errorf("missing cpu percent: %q", out)
	}
	if !strings.Contains(out, "2.0G") {
		t.Errorf("missing rss: %q", out)
	}
	if !strings.Contains(out, "25%") { // 2 GiB of 8 GiB
		t.Errorf("missing memory share: %q", out)
	}
}

func TestTopEmpty(t *testing.T) {
	if out := Top(nil, 0); !strings.Contains(out, "No process data") {
		t.Errorf("empty: %q", out)
	}
}

func TestTopFewerThanFive(t *testing.T) {
	out := Top([]collect.Proc{{PID: 1, Comm: "init", CPUPercent: 1, RSSBytes: 1 << 20}}, 0)
	if !strings.Contains(out, "init") {
		t.Errorf("single proc: %q", out)
	}
}
