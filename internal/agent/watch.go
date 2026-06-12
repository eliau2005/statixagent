package agent

import (
	"context"
	"fmt"
	"log"
	"sort"
	"strconv"
	"strings"

	"github.com/eliau2005/statixagent/internal/bot"
	"github.com/eliau2005/statixagent/internal/config"
)

// watchCopy returns a snapshot of the watch lists under the lock.
func (a *Agent) watchCopy() config.Watch {
	a.mu.Lock()
	defer a.mu.Unlock()
	w := a.cfg.Watch
	w.Services = append([]string(nil), w.Services...)
	w.Processes = append([]string(nil), w.Processes...)
	w.Ports = append([]config.PortCheck(nil), w.Ports...)
	return w
}

// mutateWatch applies a change to the watch lists and persists the config.
// It returns a note to append to the reply ("", " (not persisted)", or an
// error description) — the in-memory change always sticks.
func (a *Agent) mutateWatch(apply func(*config.Watch)) string {
	a.mu.Lock()
	apply(&a.cfg.Watch)
	cfg := a.cfg
	a.mu.Unlock()

	if a.src.ConfigPath == "" {
		return " (not persisted: no config path)"
	}
	if err := config.Save(a.src.ConfigPath, cfg); err != nil {
		log.Printf("agent: persisting watch change: %v", err)
		return " (⚠️ not persisted: " + err.Error() + ")"
	}
	return ""
}

// registerWatchHandlers adds the scan/add/remove command family.
func (a *Agent) registerWatchHandlers(r *bot.Router) {
	r.Handle("services_scan", a.servicesScan)
	r.Handle("services_add", a.servicesAdd)
	r.Handle("services_remove", a.servicesRemove)
	r.Handle("ports_scan", a.portsScan)
	r.Handle("ports_add", a.portsAdd)
	r.Handle("ports_remove", a.portsRemove)
	r.Handle("procs_add", a.procsAdd)
	r.Handle("procs_remove", a.procsRemove)
}

// ---- services ----

func (a *Agent) servicesScan(ctx context.Context, _ []string) string {
	if a.src.Runner == nil {
		return "Service scanning unavailable in this build."
	}
	out, err := a.src.Runner.Run(ctx, "systemctl", "list-units",
		"--type=service", "--state=running", "--no-legend", "--plain")
	if err != nil {
		return "Scan failed: " + err.Error()
	}
	watched := map[string]bool{}
	for _, s := range a.watchCopy().Services {
		watched[s] = true
	}
	type unit struct{ name, desc string }
	var found []unit
	for _, line := range strings.Split(out, "\n") {
		f := strings.Fields(line)
		if len(f) < 4 || !strings.HasSuffix(f[0], ".service") {
			continue
		}
		if watched[f[0]] || f[0] == "statix-agent.service" {
			continue
		}
		found = append(found, unit{f[0], strings.Join(f[4:], " ")})
	}
	a.mu.Lock()
	a.lastServiceScan = a.lastServiceScan[:0]
	for _, u := range found {
		a.lastServiceScan = append(a.lastServiceScan, u.name)
	}
	a.mu.Unlock()

	if len(found) == 0 {
		return "👁 Every running service is already watched."
	}
	var b strings.Builder
	fmt.Fprintf(&b, "👁 <b>Running, not watched</b> — %d\n<pre>", len(found))
	for i, u := range found {
		fmt.Fprintf(&b, " %2d  %s\n", i+1, esc(u.name))
		if u.desc != "" {
			fmt.Fprintf(&b, "     %s\n", esc(truncate(u.desc, 30)))
		}
	}
	b.WriteString("</pre>\nAdd one: /services_add &lt;number or name&gt;")
	return b.String()
}

func (a *Agent) servicesAdd(ctx context.Context, args []string) string {
	if len(args) == 0 {
		return "Usage: /services_add &lt;number from /services_scan, or unit name&gt;"
	}
	a.mu.Lock()
	scan := append([]string(nil), a.lastServiceScan...)
	a.mu.Unlock()
	name := resolveByIndex(args[0], scan)
	if name == "" {
		name = args[0]
		if !strings.HasSuffix(name, ".service") {
			name += ".service"
		}
	}
	for _, s := range a.watchCopy().Services {
		if s == name {
			return esc(name) + " is already watched."
		}
	}
	note := a.mutateWatch(func(w *config.Watch) {
		w.Services = append(w.Services, name)
		sort.Strings(w.Services)
	})
	return "✅ watching " + esc(name) + note + "\n" + a.watchedSummary()
}

func (a *Agent) servicesRemove(ctx context.Context, args []string) string {
	watched := a.watchCopy().Services
	if len(args) == 0 {
		return "Usage: /services_remove &lt;number or name&gt;\n" + numberedList("Watched services", watched)
	}
	name := resolveByIndex(args[0], watched)
	if name == "" {
		name = args[0]
		if !strings.HasSuffix(name, ".service") {
			name += ".service"
		}
	}
	if !contains(watched, name) {
		return esc(name) + " is not watched.\n" + numberedList("Watched services", watched)
	}
	note := a.mutateWatch(func(w *config.Watch) {
		w.Services = remove(w.Services, name)
	})
	return "🗑 stopped watching " + esc(name) + note + "\n" + a.watchedSummary()
}

// ---- ports ----

func (a *Agent) portsScan(ctx context.Context, _ []string) string {
	if a.src.ListListeners == nil {
		return "Port scanning unavailable in this build."
	}
	ports, err := a.src.ListListeners()
	if err != nil {
		return "Scan failed: " + err.Error()
	}
	watched := map[int]bool{}
	for _, p := range a.watchCopy().Ports {
		watched[p.Port] = true
	}
	seen := map[int]bool{}
	var found []int
	for _, p := range ports {
		if !watched[p] && !seen[p] {
			seen[p] = true
			found = append(found, p)
		}
	}
	sort.Ints(found)
	a.mu.Lock()
	a.lastPortScan = found
	a.mu.Unlock()

	if len(found) == 0 {
		return "👁 Every listening port is already watched."
	}
	var b strings.Builder
	fmt.Fprintf(&b, "👁 <b>Listening, not watched</b> — %d\n<pre>", len(found))
	for i, p := range found {
		fmt.Fprintf(&b, " %2d  port %d\n", i+1, p)
	}
	b.WriteString("</pre>\nAdd one: /ports_add &lt;number or port&gt; [label]")
	return b.String()
}

func (a *Agent) portsAdd(ctx context.Context, args []string) string {
	if len(args) == 0 {
		return "Usage: /ports_add &lt;number from /ports_scan, or port&gt; [label]"
	}
	a.mu.Lock()
	scan := append([]int(nil), a.lastPortScan...)
	a.mu.Unlock()

	port, err := resolvePort(args[0], scan)
	if err != nil {
		return err.Error()
	}
	label := strings.Join(args[1:], " ")
	for _, p := range a.watchCopy().Ports {
		if p.Port == port {
			return fmt.Sprintf("Port %d is already watched.", port)
		}
	}
	note := a.mutateWatch(func(w *config.Watch) {
		w.Ports = append(w.Ports, config.PortCheck{Port: port, Label: label})
		sort.Slice(w.Ports, func(i, j int) bool { return w.Ports[i].Port < w.Ports[j].Port })
	})
	return fmt.Sprintf("✅ watching port %d%s\n%s", port, note, a.watchedSummary())
}

func (a *Agent) portsRemove(ctx context.Context, args []string) string {
	watched := a.watchCopy().Ports
	names := make([]string, len(watched))
	for i, p := range watched {
		names[i] = strconv.Itoa(p.Port)
		if p.Label != "" {
			names[i] += " (" + p.Label + ")"
		}
	}
	if len(args) == 0 {
		return "Usage: /ports_remove &lt;number or port&gt;\n" + numberedList("Watched ports", names)
	}
	n, err := strconv.Atoi(args[0])
	if err != nil {
		return "Give the port number or its index from the list."
	}
	port := n
	// Small numbers that match a list index (and no watched port) mean index.
	if n >= 1 && n <= len(watched) && !portWatched(watched, n) {
		port = watched[n-1].Port
	}
	if !portWatched(watched, port) {
		return fmt.Sprintf("Port %d is not watched.\n%s", port, numberedList("Watched ports", names))
	}
	note := a.mutateWatch(func(w *config.Watch) {
		kept := w.Ports[:0]
		for _, p := range w.Ports {
			if p.Port != port {
				kept = append(kept, p)
			}
		}
		w.Ports = kept
	})
	return fmt.Sprintf("🗑 stopped watching port %d%s\n%s", port, note, a.watchedSummary())
}

// ---- processes ----

func (a *Agent) procsAdd(ctx context.Context, args []string) string {
	if len(args) == 0 {
		return "Usage: /procs_add &lt;executable name&gt; (e.g. nginx)"
	}
	name := args[0]
	if contains(a.watchCopy().Processes, name) {
		return esc(name) + " is already watched."
	}
	note := a.mutateWatch(func(w *config.Watch) {
		w.Processes = append(w.Processes, name)
		sort.Strings(w.Processes)
	})
	return "✅ watching process " + esc(name) + note + "\n" + a.watchedSummary()
}

func (a *Agent) procsRemove(ctx context.Context, args []string) string {
	watched := a.watchCopy().Processes
	if len(args) == 0 {
		return "Usage: /procs_remove &lt;name&gt;\n" + numberedList("Watched processes", watched)
	}
	name := resolveByIndex(args[0], watched)
	if name == "" {
		name = args[0]
	}
	if !contains(watched, name) {
		return esc(name) + " is not watched.\n" + numberedList("Watched processes", watched)
	}
	note := a.mutateWatch(func(w *config.Watch) {
		w.Processes = remove(w.Processes, name)
	})
	return "🗑 stopped watching " + esc(name) + note + "\n" + a.watchedSummary()
}

// ---- helpers ----

// watchedSummary is the one-line state appended to every mutation reply.
func (a *Agent) watchedSummary() string {
	w := a.watchCopy()
	return fmt.Sprintf("Now watching: %d services · %d processes · %d ports",
		len(w.Services), len(w.Processes), len(w.Ports))
}

// resolveByIndex returns list[n-1] when arg is a valid 1-based index.
func resolveByIndex(arg string, list []string) string {
	n, err := strconv.Atoi(arg)
	if err != nil || n < 1 || n > len(list) {
		return ""
	}
	return list[n-1]
}

// resolvePort maps an argument to a port: a value present in the last scan
// wins (so "/ports_add 22" adds port 22 even if the scan has 22+ entries),
// then a scan index, then any valid port number.
func resolvePort(arg string, scan []int) (int, error) {
	n, err := strconv.Atoi(arg)
	if err != nil {
		return 0, fmt.Errorf("%q is not a port or list number", arg)
	}
	for _, p := range scan {
		if p == n {
			return n, nil
		}
	}
	if n >= 1 && n <= len(scan) {
		return scan[n-1], nil
	}
	if n < 1 || n > 65535 {
		return 0, fmt.Errorf("port %d out of range", n)
	}
	return n, nil
}

func portWatched(ports []config.PortCheck, port int) bool {
	for _, p := range ports {
		if p.Port == port {
			return true
		}
	}
	return false
}

func numberedList(title string, items []string) string {
	if len(items) == 0 {
		return "Nothing is watched yet."
	}
	var b strings.Builder
	fmt.Fprintf(&b, "<b>%s</b>\n<pre>", esc(title))
	for i, it := range items {
		fmt.Fprintf(&b, " %2d  %s\n", i+1, esc(it))
	}
	b.WriteString("</pre>")
	return b.String()
}

func contains(list []string, s string) bool {
	for _, v := range list {
		if v == s {
			return true
		}
	}
	return false
}

func remove(list []string, s string) []string {
	kept := list[:0]
	for _, v := range list {
		if v != s {
			kept = append(kept, v)
		}
	}
	return kept
}

func truncate(s string, n int) string {
	r := []rune(s)
	if len(r) <= n {
		return s
	}
	return string(r[:n-1]) + "…"
}

// esc is shared with agent.go replies built outside the bot package.
func esc(s string) string {
	r := strings.NewReplacer("&", "&amp;", "<", "&lt;", ">", "&gt;")
	return r.Replace(s)
}
