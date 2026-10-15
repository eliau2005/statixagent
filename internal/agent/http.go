package agent

import (
	"strconv"
	"strings"

	"github.com/eliau2005/statixagent/internal/config"
)

// httpManage handles "/http add <url> [status]" and "/http remove
// <url|number>"; a bare /http opens the HTTP checks list (svhub.go).
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
