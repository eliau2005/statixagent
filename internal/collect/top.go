package collect

import (
	"io/fs"
	"strconv"
	"time"

	"github.com/eliau2005/statixagent/internal/procfs"
)

// Proc is one process's computed usage over a sampling window.
type Proc struct {
	PID        int
	Comm       string
	CPUPercent float64
	RSSBytes   uint64
}

// userHZ is the tick rate of /proc CPU-time counters. The kernel ABI pins
// it at 100 on every architecture Go supports, so it is not probed.
const userHZ = 100

// ReadProcStats reads every numeric /proc/[pid]/stat under fsys once.
// Processes that exit mid-walk or fail to parse are silently skipped.
func ReadProcStats(fsys fs.FS) map[int]procfs.PIDStat {
	entries, err := fs.ReadDir(fsys, ".")
	if err != nil {
		return nil
	}
	out := make(map[int]procfs.PIDStat, len(entries))
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		pid, err := strconv.Atoi(e.Name())
		if err != nil {
			continue
		}
		data, err := fs.ReadFile(fsys, e.Name()+"/stat")
		if err != nil {
			continue
		}
		st, err := procfs.ParsePIDStat(string(data))
		if err != nil {
			continue
		}
		out[pid] = st
	}
	return out
}

// TopProcs derives per-process CPU percentages from two readings taken
// elapsed apart. Processes new since prev report 0% CPU (no delta yet)
// but still carry their memory usage.
func TopProcs(prev, cur map[int]procfs.PIDStat, elapsed time.Duration, pageSize uint64) []Proc {
	sec := elapsed.Seconds()
	out := make([]Proc, 0, len(cur))
	for pid, c := range cur {
		p := Proc{PID: pid, Comm: c.Comm}
		if c.RSSPages > 0 {
			p.RSSBytes = uint64(c.RSSPages) * pageSize
		}
		if pr, ok := prev[pid]; ok && sec > 0 {
			if d := int64(c.UTime+c.STime) - int64(pr.UTime+pr.STime); d > 0 {
				p.CPUPercent = 100 * float64(d) / userHZ / sec
			}
		}
		out = append(out, p)
	}
	return out
}
