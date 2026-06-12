package procfs

import (
	"fmt"
	"strconv"
	"strings"
)

// PIDStat is the subset of /proc/[pid]/stat the agent uses: enough to
// rank processes by CPU time and resident memory.
type PIDStat struct {
	PID      int
	Comm     string
	UTime    uint64 // user-mode ticks, cumulative
	STime    uint64 // kernel-mode ticks, cumulative
	RSSPages int64  // resident set size in pages (signed in the kernel)
}

// ParsePIDStat parses one /proc/[pid]/stat file. comm is found between the
// first '(' and the LAST ')' because process names may themselves contain
// spaces and parentheses ("(sd-pam)", "tmux: server").
func ParsePIDStat(s string) (PIDStat, error) {
	lp := strings.IndexByte(s, '(')
	rp := strings.LastIndexByte(s, ')')
	if lp < 0 || rp < lp {
		return PIDStat{}, fmt.Errorf("procfs: pid stat: no comm field in %q", s)
	}
	pid, err := strconv.Atoi(strings.TrimSpace(s[:lp]))
	if err != nil {
		return PIDStat{}, fmt.Errorf("procfs: pid stat: bad pid: %w", err)
	}
	// rest[0] is field 3 (state); stat field N lives at rest[N-3].
	rest := strings.Fields(s[rp+1:])
	const (
		utimeIdx = 14 - 3
		stimeIdx = 15 - 3
		rssIdx   = 24 - 3
	)
	if len(rest) <= rssIdx {
		return PIDStat{}, fmt.Errorf("procfs: pid stat: short line (%d fields after comm)", len(rest))
	}
	st := PIDStat{PID: pid, Comm: s[lp+1 : rp]}
	if st.UTime, err = strconv.ParseUint(rest[utimeIdx], 10, 64); err != nil {
		return PIDStat{}, fmt.Errorf("procfs: pid stat utime: %w", err)
	}
	if st.STime, err = strconv.ParseUint(rest[stimeIdx], 10, 64); err != nil {
		return PIDStat{}, fmt.Errorf("procfs: pid stat stime: %w", err)
	}
	if st.RSSPages, err = strconv.ParseInt(rest[rssIdx], 10, 64); err != nil {
		return PIDStat{}, fmt.Errorf("procfs: pid stat rss: %w", err)
	}
	return st, nil
}
