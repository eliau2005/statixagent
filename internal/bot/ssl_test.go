package bot

import (
	"strings"
	"testing"
	"time"

	"github.com/eliau2005/statixagent/internal/netcheck"
)

func TestSSLCerts(t *testing.T) {
	out := SSLCerts([]netcheck.CertStatus{
		{Host: "ok.example", DaysLeft: 120, NotAfter: time.Date(2026, 10, 11, 0, 0, 0, 0, time.UTC)},
		{Host: "warn.example", DaysLeft: 10, NotAfter: time.Date(2026, 6, 23, 0, 0, 0, 0, time.UTC)},
		{Host: "crit.example", DaysLeft: 1, NotAfter: time.Date(2026, 6, 14, 0, 0, 0, 0, time.UTC)},
		{Host: "dead.example", DaysLeft: -5, NotAfter: time.Date(2026, 6, 8, 0, 0, 0, 0, time.UTC)},
		{Host: "down.example", Err: "i/o timeout"},
	})
	for _, want := range []string{"✅", "⚠️", "🚨", "❌", "120d", "expired", "i/o timeout", "Oct 11 2026"} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q:\n%s", want, out)
		}
	}
	// Order: failed first, then by days left ascending.
	idx := func(s string) int { return strings.Index(out, s) }
	if strings.Contains(out, "-5d") {
		t.Errorf("expired cert rendered as a negative count:\n%s", out)
	}
	if !(idx("down.example") < idx("dead.example") && idx("dead.example") < idx("crit.example") && idx("crit.example") < idx("warn.example") && idx("warn.example") < idx("ok.example")) {
		t.Errorf("wrong order:\n%s", out)
	}
}

func TestSSLCertsEmpty(t *testing.T) {
	if out := SSLCerts(nil); !strings.Contains(out, "No SSL hosts") {
		t.Errorf("empty: %q", out)
	}
}
