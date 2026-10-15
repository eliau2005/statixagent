package bot

import (
	"testing"
	"time"

	"github.com/eliau2005/statixagent/internal/netcheck"
)

func TestCertLeft(t *testing.T) {
	at := time.Date(2026, 10, 27, 0, 0, 0, 0, time.UTC)
	for _, tc := range []struct {
		st   netcheck.CertStatus
		want string
	}{
		{netcheck.CertStatus{Host: "ok", DaysLeft: 12, NotAfter: at}, "12d · Oct 27"},
		{netcheck.CertStatus{Host: "today", DaysLeft: 0, NotAfter: at}, "0d · Oct 27"},
		{netcheck.CertStatus{Host: "dead", DaysLeft: -5, NotAfter: at}, "expired · Oct 27"},
		{netcheck.CertStatus{Host: "down", Err: "i/o timeout"}, "i/o timeout"},
	} {
		if got := CertLeft(tc.st); got != tc.want {
			t.Errorf("%s: CertLeft = %q, want %q", tc.st.Host, got, tc.want)
		}
	}
}
