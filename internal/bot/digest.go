package bot

import (
	"fmt"
	"strings"
	"time"

	"github.com/eliau2005/statixagent/internal/collect"
)

// DigestData is the activity accumulated since the last digest was sent.
type DigestData struct {
	Since   time.Time
	PeakCPU float64
	PeakMem float64
	Alerts  int
	Crits   int
	Logins  int
	Fails   int
}

// Digest renders the daily summary card: the proof of life a healthy,
// otherwise-silent server owes its owner once a day.
func Digest(hostname string, d DigestData, s collect.Snapshot, now time.Time) string {
	header := fmt.Sprintf("📰 <b>%s</b> — daily digest", esc(hostname))
	var L []string
	L = append(L, fmt.Sprintf(" last %s · up %s", Dur(now.Sub(d.Since)), Dur(s.Uptime)))
	L = append(L, divider)
	L = append(L, fmt.Sprintf(" peak  CPU %s  RAM %s",
		pad(fmt.Sprintf("%.0f%%", d.PeakCPU), -4), pad(fmt.Sprintf("%.0f%%", d.PeakMem), -4)))
	L = append(L, fmt.Sprintf(" now   CPU %s  RAM %s",
		pad(fmt.Sprintf("%.0f%%", s.CPUTotal.Percent), -4),
		pad(fmt.Sprintf("%.0f%%", s.Mem.UsedPercent()), -4)))
	if len(s.Mounts) > 0 {
		var parts []string
		for _, m := range s.Mounts {
			parts = append(parts, fmt.Sprintf("%s %.0f%%", m.MountPoint, m.UsedPercent))
		}
		L = append(L, " disk  "+strings.Join(parts, " · "))
	}
	L = append(L, divider)
	if d.Logins == 0 && d.Fails == 0 {
		L = append(L, " 🔐 no SSH activity")
	} else {
		L = append(L, fmt.Sprintf(" 🔐 %d logins · %d failed", d.Logins, d.Fails))
	}
	if d.Alerts == 0 {
		L = append(L, " ✅ no alerts")
	} else {
		L = append(L, fmt.Sprintf(" 🚨 %d alerts (%d critical)", d.Alerts, d.Crits))
	}
	return card(header, L)
}
