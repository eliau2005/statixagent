package agent

import (
	"context"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/eliau2005/statixagent/internal/alert"
)

// Certificate expiry watching: /ssl opens the Certificates list (svhub.go)
// and /ssl add|remove manage it; sslLoop re-checks twice a day and alerts
// as expiry approaches. Wired from config watch.ssl_hosts.

// Re-alert just under the check cadence so an expiring cert nags once per
// check round until renewed, not once ever.
const sslAlertCooldown = 11 * time.Hour

// sslUsage is HTML: raw angle brackets would make Telegram reject the reply.
const sslUsage = "Usage: /ssl add &lt;host[:port]&gt; · /ssl remove &lt;host&gt;"

// sslManage handles "/ssl add <host>" and "/ssl remove <host>".
func (a *Agent) sslManage(args []string) string {
	if len(args) != 2 {
		return sslUsage
	}
	verb, host := strings.ToLower(args[0]), args[1]
	switch verb {
	case "add":
		a.mu.Lock()
		if slices.Contains(a.cfg.Watch.SSLHosts, host) {
			a.mu.Unlock()
			return esc(host) + " is already watched."
		}
		a.cfg.Watch.SSLHosts = append(a.cfg.Watch.SSLHosts, host)
		cfg := a.cfg
		a.mu.Unlock()
		return "🔒 Watching " + esc(host) + a.persist(cfg) + "\nCheck it now: /ssl"
	case "remove":
		a.mu.Lock()
		kept := a.cfg.Watch.SSLHosts[:0]
		for _, h := range a.cfg.Watch.SSLHosts {
			if h != host {
				kept = append(kept, h)
			}
		}
		removed := len(kept) != len(a.cfg.Watch.SSLHosts)
		a.cfg.Watch.SSLHosts = kept
		cfg := a.cfg
		a.mu.Unlock()
		if !removed {
			return esc(host) + " was not watched."
		}
		return "Removed " + esc(host) + a.persist(cfg)
	}
	return sslUsage
}

// sslLoop re-checks certificates twice a day; the first check runs at
// startup so a cert already in the danger window alerts immediately.
func (a *Agent) sslLoop(ctx context.Context) {
	tick := time.NewTicker(a.sslInterval)
	defer tick.Stop()
	a.checkCerts(ctx)
	for {
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
			a.checkCerts(ctx)
		}
	}
}

// checkCerts alerts on failing handshakes and approaching expiry.
func (a *Agent) checkCerts(ctx context.Context) {
	hosts := a.watchCopy().SSLHosts
	if len(hosts) == 0 || a.src.CheckCerts == nil {
		return
	}
	now := time.Now()
	for _, st := range a.src.CheckCerts(ctx, hosts) {
		var al *alert.Alert
		switch {
		case st.Err != "":
			al = a.engine.Event("ssl:"+st.Host, "SSL check failed",
				st.Host+": "+st.Err, alert.Warning, now, sslAlertCooldown)
		case st.DaysLeft < 0:
			// DaysLeft rounds down, so -1 is anything inside the first day.
			ago := "less than a day ago"
			if st.DaysLeft < -1 {
				ago = fmt.Sprintf("%d days ago", -st.DaysLeft)
			}
			al = a.engine.Event("ssl:"+st.Host, "Certificate expired",
				st.Host+" expired "+ago, alert.Critical, now, sslAlertCooldown)
		case st.DaysLeft <= 3:
			al = a.engine.Event("ssl:"+st.Host, "Certificate expiring",
				fmt.Sprintf("%s expires in %d days", st.Host, st.DaysLeft), alert.Critical, now, sslAlertCooldown)
		case st.DaysLeft <= 21:
			al = a.engine.Event("ssl:"+st.Host, "Certificate expiring",
				fmt.Sprintf("%s expires in %d days", st.Host, st.DaysLeft), alert.Warning, now, sslAlertCooldown)
		}
		if al != nil {
			a.pushAlert(ctx, *al)
		}
	}
}
