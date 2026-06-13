package agent

import (
	"context"
	"strconv"
	"strings"

	"github.com/eliau2005/statixagent/internal/bot"
	"github.com/eliau2005/statixagent/internal/config"
	"github.com/eliau2005/statixagent/internal/services"
)

// httpView runs the watched HTTP checks on demand; with args it manages
// the list ("/http add <url> [status]", "/http remove <url|number>").
func (a *Agent) httpView(ctx context.Context, args []string) string {
	if len(args) > 0 {
		return a.httpManage(args)
	}
	checks := a.watchCopy().HTTPChecks
	if len(checks) == 0 {
		return "🌐 No HTTP checks yet.\nAdd one: <code>/http add https://example.com/healthz</code>"
	}
	specs := make([]services.HTTPSpec, len(checks))
	for i, h := range checks {
		specs[i] = services.HTTPSpec{URL: h.URL, ExpectStatus: h.ExpectStatus, Timeout: h.Timeout.Duration}
	}
	return bot.ServiceResults(services.CheckHTTP(ctx, httpClient, specs))
}

// httpManage handles "/http add" and "/http remove".
func (a *Agent) httpManage(args []string) string {
	const usage = "Usage: /http add &lt;url&gt; [expected status] · /http remove &lt;url or number&gt;"
	if len(args) < 2 {
		return usage
	}
	verb, arg := strings.ToLower(args[0]), args[1]
	switch verb {
	case "add":
		if !strings.HasPrefix(arg, "http://") && !strings.HasPrefix(arg, "https://") {
			return "The URL must start with http:// or https://"
		}
		expect := 0 // 0 = expect 200, the CheckHTTP default
		if len(args) >= 3 {
			n, err := strconv.Atoi(args[2])
			if err != nil || n < 100 || n > 599 {
				return "Expected status must be 100-599."
			}
			expect = n
		}
		for _, h := range a.watchCopy().HTTPChecks {
			if h.URL == arg {
				return esc(arg) + " is already checked."
			}
		}
		note := a.mutateWatch(func(w *config.Watch) {
			w.HTTPChecks = append(w.HTTPChecks, config.HTTPCheck{URL: arg, ExpectStatus: expect})
		})
		return "🌐 checking " + esc(arg) + note + "\nRun it now: /http"

	case "remove":
		checks := a.watchCopy().HTTPChecks
		target := arg
		if n, err := strconv.Atoi(arg); err == nil && n >= 1 && n <= len(checks) {
			target = checks[n-1].URL
		}
		names := make([]string, len(checks))
		found := false
		for i, h := range checks {
			names[i] = h.URL
			if h.URL == target {
				found = true
			}
		}
		if !found {
			return esc(target) + " is not checked.\n" + numberedList("HTTP checks", names)
		}
		note := a.mutateWatch(func(w *config.Watch) {
			kept := w.HTTPChecks[:0]
			for _, h := range w.HTTPChecks {
				if h.URL != target {
					kept = append(kept, h)
				}
			}
			w.HTTPChecks = kept
		})
		return "🗑 stopped checking " + esc(target) + note
	}
	return usage
}
