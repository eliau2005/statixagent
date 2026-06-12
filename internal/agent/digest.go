package agent

import (
	"context"
	"time"

	"github.com/eliau2005/statixagent/internal/alert"
	"github.com/eliau2005/statixagent/internal/bot"
	"github.com/eliau2005/statixagent/internal/sshwatch"
)

// digestStats accumulates activity between daily digests. Guarded by a.mu.
type digestStats struct {
	since   time.Time
	peakCPU float64
	peakMem float64
	alerts  int
	crits   int
	logins  int
	fails   int
}

// noteAlert counts a fired alert toward the next digest. Resolutions and
// Info-severity notices (routine logins, power restored) are not problems
// and would only inflate the count.
func (a *Agent) noteAlert(al alert.Alert) {
	if al.Resolved || al.Severity == alert.Info {
		return
	}
	a.mu.Lock()
	a.digest.alerts++
	if al.Severity == alert.Critical {
		a.digest.crits++
	}
	a.mu.Unlock()
}

// noteSSHEvent counts login activity toward the next digest.
func (a *Agent) noteSSHEvent(kind sshwatch.EventKind) {
	a.mu.Lock()
	switch kind {
	case sshwatch.EventLogin:
		a.digest.logins++
	case sshwatch.EventFailed, sshwatch.EventInvalidUser:
		a.digest.fails++
	}
	a.mu.Unlock()
}

// digestView renders the accumulated digest. reset starts a new window —
// the scheduled daily send resets; the on-demand /digest command does not.
func (a *Agent) digestView(reset bool) string {
	now := time.Now()
	a.mu.Lock()
	d := bot.DigestData{
		Since:   a.digest.since,
		PeakCPU: a.digest.peakCPU,
		PeakMem: a.digest.peakMem,
		Alerts:  a.digest.alerts,
		Crits:   a.digest.crits,
		Logins:  a.digest.logins,
		Fails:   a.digest.fails,
	}
	snap := a.snap
	if reset {
		a.digest = digestStats{since: now}
	}
	a.mu.Unlock()
	return bot.Digest(a.src.Hostname, d, snap, now)
}

// digestCfg returns the current digest settings under the lock; they are
// mutable at runtime via the /settings buttons.
func (a *Agent) digestCfg() (enabled bool, hour int) {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.cfg.Digest.Enabled, a.cfg.Digest.Hour
}

// dayStamp identifies a calendar day for once-per-day bookkeeping.
func dayStamp(t time.Time) int { return t.Year()*1000 + t.YearDay() }

// digestDue reports whether the daily digest should fire at now: the local
// hour matches and nothing was sent today. It returns the updated day stamp.
func digestDue(now time.Time, hour, lastDay int) (int, bool) {
	if day := dayStamp(now); now.Hour() == hour && day != lastDay {
		return day, true
	}
	return lastDay, false
}

// digestLoop polls instead of sleeping until a precomputed instant so that
// /settings changes to the hour or the on/off toggle take effect without a
// restart. Starting mid-slot does not replay today's already-passed hour.
func (a *Agent) digestLoop(ctx context.Context) {
	lastDay := 0
	now := time.Now()
	if _, hour := a.digestCfg(); now.Hour() >= hour {
		lastDay = dayStamp(now)
	}
	tick := time.NewTicker(a.digestPoll)
	defer tick.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
			enabled, hour := a.digestCfg()
			if !enabled {
				continue
			}
			var due bool
			if lastDay, due = digestDue(time.Now(), hour, lastDay); due {
				a.push(ctx, a.digestView(true))
			}
		}
	}
}
