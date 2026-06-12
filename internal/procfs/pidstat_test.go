package procfs

import (
	"fmt"
	"strings"
	"testing"
)

// statLine builds a /proc/[pid]/stat line with the given identity, CPU
// ticks (fields 14/15), and rss pages (field 24).
func statLine(pid int, comm string, utime, stime uint64, rss int64) string {
	f := make([]string, 50) // fields 3..52
	for i := range f {
		f[i] = "0"
	}
	f[0] = "S"                       // field 3: state
	f[11] = fmt.Sprintf("%d", utime) // field 14
	f[12] = fmt.Sprintf("%d", stime) // field 15
	f[21] = fmt.Sprintf("%d", rss)   // field 24
	return fmt.Sprintf("%d (%s) %s", pid, comm, strings.Join(f, " "))
}

func TestParsePIDStat(t *testing.T) {
	st, err := ParsePIDStat(statLine(1234, "nginx", 500, 250, 4096))
	if err != nil {
		t.Fatalf("ParsePIDStat: %v", err)
	}
	if st.PID != 1234 || st.Comm != "nginx" {
		t.Errorf("identity: got pid=%d comm=%q", st.PID, st.Comm)
	}
	if st.UTime != 500 || st.STime != 250 {
		t.Errorf("cpu ticks: got utime=%d stime=%d, want 500/250", st.UTime, st.STime)
	}
	if st.RSSPages != 4096 {
		t.Errorf("rss: got %d, want 4096", st.RSSPages)
	}
}

func TestParsePIDStatCommWithSpacesAndParens(t *testing.T) {
	for _, comm := range []string{"tmux: server", "(sd-pam)", "a) b (c"} {
		st, err := ParsePIDStat(statLine(7, comm, 1, 1, 1))
		if err != nil {
			t.Fatalf("comm %q: %v", comm, err)
		}
		if st.Comm != comm {
			t.Errorf("comm: got %q, want %q", st.Comm, comm)
		}
	}
}

func TestParsePIDStatBadInput(t *testing.T) {
	for _, in := range []string{"", "1234 no-comm S 0 0", "1234 (x) S 0 0"} {
		if _, err := ParsePIDStat(in); err == nil {
			t.Errorf("ParsePIDStat(%q): want error, got nil", in)
		}
	}
}
