package collect

import (
	"fmt"
	"testing"
	"testing/fstest"
	"time"

	"github.com/eliau2005/statixagent/internal/procfs"
)

func fakeStat(pid int, comm string, ticks uint64, rss int64) *fstest.MapFile {
	line := fmt.Sprintf("%d (%s) S 0 0 0 0 0 0 0 0 0 0 %d 0 0 0 0 0 0 0 0 0 %d 0 0 0 0 0 0",
		pid, comm, ticks, rss)
	return &fstest.MapFile{Data: []byte(line)}
}

func TestReadProcStats(t *testing.T) {
	fsys := fstest.MapFS{
		"1/stat":     fakeStat(1, "systemd", 10, 100),
		"42/stat":    fakeStat(42, "nginx", 20, 200),
		"sys/kernel": &fstest.MapFile{Data: []byte("x")}, // non-numeric: skipped
		"99/cmdline": &fstest.MapFile{Data: []byte("x")}, // no stat file: skipped
		"7/stat":     &fstest.MapFile{Data: []byte("garbage")},
	}
	got := ReadProcStats(fsys)
	if len(got) != 2 {
		t.Fatalf("ReadProcStats: got %d procs, want 2: %v", len(got), got)
	}
	if got[42].Comm != "nginx" || got[42].UTime != 20 {
		t.Errorf("pid 42: got %+v", got[42])
	}
}

func TestTopProcs(t *testing.T) {
	prev := map[int]procfs.PIDStat{
		1: {PID: 1, Comm: "idle", UTime: 100, STime: 100},
		2: {PID: 2, Comm: "busy", UTime: 100, STime: 100},
	}
	cur := map[int]procfs.PIDStat{
		1: {PID: 1, Comm: "idle", UTime: 100, STime: 100, RSSPages: 10},
		2: {PID: 2, Comm: "busy", UTime: 130, STime: 120, RSSPages: 256},
		3: {PID: 3, Comm: "new", UTime: 999, STime: 999, RSSPages: 5},
	}
	procs := TopProcs(prev, cur, time.Second, 4096)
	if len(procs) != 3 {
		t.Fatalf("got %d procs, want 3", len(procs))
	}
	byPID := map[int]Proc{}
	for _, p := range procs {
		byPID[p.PID] = p
	}
	// busy gained 50 ticks over 1s at 100 Hz → 50%
	if got := byPID[2].CPUPercent; got < 49.9 || got > 50.1 {
		t.Errorf("busy cpu: got %.2f%%, want 50%%", got)
	}
	if byPID[2].RSSBytes != 256*4096 {
		t.Errorf("busy rss: got %d, want %d", byPID[2].RSSBytes, 256*4096)
	}
	if byPID[1].CPUPercent != 0 {
		t.Errorf("idle cpu: got %.2f%%, want 0", byPID[1].CPUPercent)
	}
	// pid 3 has no previous reading: CPU must be 0, not a since-boot blowup
	if byPID[3].CPUPercent != 0 {
		t.Errorf("new proc cpu: got %.2f%%, want 0", byPID[3].CPUPercent)
	}
}
