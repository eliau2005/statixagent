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

// nextDigestTime returns the next local occurrence of hour:00 after now.
func nextDigestTime(now time.Time, hour int) time.Time {
	next := time.Date(now.Year(), now.Month(), now.Day(), hour, 0, 0, 0, now.Location())
	if !next.After(now) {
		next = next.AddDate(0, 0, 1)
	}
	return next
}

// digestLoop sends the summary at the configured hour, every day.
func (a *Agent) digestLoop(ctx context.Context) {
	for {
		wait := time.Until(nextDigestTime(time.Now(), a.cfg.Digest.Hour))
		select {
		case <-ctx.Done():
			return
		case <-time.After(wait):
			a.push(ctx, a.digestView(true))
		}
	}
}
