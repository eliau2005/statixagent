package bot

import (
	"fmt"
	"sort"

	"github.com/eliau2005/statixagent/internal/netcheck"
)

// SSLCerts renders /ssl: failed checks first, then soonest expiry.
func SSLCerts(sts []netcheck.CertStatus) string {
	if len(sts) == 0 {
		return "🔒 No SSL hosts watched."
	}
	sorted := append([]netcheck.CertStatus(nil), sts...)
	sort.SliceStable(sorted, func(i, j int) bool {
		if (sorted[i].Err != "") != (sorted[j].Err != "") {
			return sorted[i].Err != ""
		}
		return sorted[i].DaysLeft < sorted[j].DaysLeft
	})
	var L []string
	for _, s := range sorted {
		if s.Err != "" {
			L = append(L, " ❌ "+s.Host, "    "+s.Err)
			continue
		}
		icon := "✅"
		switch {
		case s.DaysLeft <= 3:
			icon = "🚨"
		case s.DaysLeft <= 21:
			icon = "⚠️"
		}
		// A negative count is an already-expired cert; say so rather than
		// making the reader decode "-5d".
		left := fmt.Sprintf("%dd", s.DaysLeft)
		if s.DaysLeft < 0 {
			left = "expired"
		}
		L = append(L, fmt.Sprintf(" %s %s %s %s", icon, pad(s.Host, 18),
			pad(left, -7), s.NotAfter.Format("Jan 02 2006")))
	}
	return card("🔒 <b>Certificates</b>", L)
}
