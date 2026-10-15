package bot

import (
	"fmt"

	"github.com/eliau2005/statixagent/internal/netcheck"
)

// CertLeft is a certificate's line on the Certificates list: the days
// left and the expiry date, "12d · Oct 27", or the check's error. An
// expired certificate says so rather than making the reader decode
// "-5d".
func CertLeft(s netcheck.CertStatus) string {
	switch {
	case s.Err != "":
		return s.Err
	case s.DaysLeft < 0:
		return "expired · " + s.NotAfter.Format("Jan 02")
	}
	return fmt.Sprintf("%dd · %s", s.DaysLeft, s.NotAfter.Format("Jan 02"))
}
