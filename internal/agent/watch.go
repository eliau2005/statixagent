package agent

import (
	"context"
	"fmt"
	"log"
	"slices"
	"sort"
	"strconv"
	"strings"

	"github.com/eliau2005/statixagent/internal/bot"
	"github.com/eliau2005/statixagent/internal/config"
	"github.com/eliau2005/statixagent/internal/telegram"
)

// watchCopy returns a snapshot of the watch lists under the lock.
func (a *Agent) watchCopy() config.Watch {
	a.mu.Lock()
	defer a.mu.Unlock()
	w := a.cfg.Watch
	w.Services = append([]string(nil), w.Services...)
	w.Processes = append([]string(nil), w.Processes...)
	w.Ports = append([]config.PortCheck(nil), w.Ports...)
	w.SSLHosts = append([]string(nil), w.SSLHosts...)
	w.HTTPChecks = append([]config.HTTPCheck(nil), w.HTTPChecks...)
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
	return a.persist(cfg)
}

// persist writes the config snapshot to disk, returning the reply note.
func (a *Agent) persist(cfg config.Config) string {
	if a.src.ConfigPath == "" {
		return " (not persisted: no config path)"
	}
	if err := config.Save(a.src.ConfigPath, cfg); err != nil {
		log.Printf("agent: persisting config change: %v", err)
		return " (⚠️ not persisted: " + err.Error() + ")"
	}
	return ""
}

// registerWatchHandlers adds the scan/add/remove command family.
func (a *Agent) registerWatchHandlers(r *bot.Router) {
	r.Handle("watching", func(ctx context.Context, _ []string) string {
		text, kb := a.watchingView()
		a.stashKB(kb)
		return text
	})
	r.Handle("settings", func(ctx context.Context, _ []string) string {
		text, kb := a.settingsView()
		a.stashKB(kb)
		return text
	})
	r.Handle("firewall", func(ctx context.Context, _ []string) string {
		text, kb := a.firewallView(ctx)
		a.stashKB(kb)
		return text
	})
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

type unitInfo struct{ name, desc string }

// scanServices lists running, unwatched units and stores them for index
// resolution by /services_add and ➕ buttons.
func (a *Agent) scanServices(ctx context.Context) ([]unitInfo, error) {
	if a.src.Runner == nil {
		return nil, fmt.Errorf("service scanning unavailable in this build")
	}
	out, err := a.src.Runner.Run(ctx, "systemctl", "list-units",
		"--type=service", "--state=running", "--no-legend", "--plain")
	if err != nil {
		return nil, err
	}
	watched := map[string]bool{}
	for _, s := range a.watchCopy().Services {
		watched[s] = true
	}
	var found []unitInfo
	for line := range strings.SplitSeq(out, "\n") {
		f := strings.Fields(line)
		if len(f) < 4 || !strings.HasSuffix(f[0], ".service") {
			continue
		}
		if watched[f[0]] || f[0] == "statix-agent.service" {
			continue
		}
		found = append(found, unitInfo{f[0], strings.Join(f[4:], " ")})
	}
	a.mu.Lock()
	a.lastServiceScan = a.lastServiceScan[:0]
	for _, u := range found {
		a.lastServiceScan = append(a.lastServiceScan, u.name)
	}
	a.mu.Unlock()
	return found, nil
}

// servicesScanView renders the scan with one ➕ button per candidate.
func (a *Agent) servicesScanView(ctx context.Context) (string, telegram.Keyboard) {
	found, err := a.scanServices(ctx)
	if err != nil {
		return "Scan failed: " + esc(err.Error()), backKeyboard()
	}
	if len(found) == 0 {
		return "👁 Every running service is already watched.", backKeyboard()
	}
	var b strings.Builder
	fmt.Fprintf(&b, "👁 <b>Running, not watched</b> — %d\nTap ➕ to watch:\n<pre>", len(found))
	const maxButtons = 12
	for i, u := range found {
		if i >= maxButtons {
			fmt.Fprintf(&b, " … %d more — /services_add &lt;name&gt;\n", len(found)-maxButtons)
			break
		}
		fmt.Fprintf(&b, " %2d  %s\n", i+1, esc(u.name))
		if u.desc != "" {
			fmt.Fprintf(&b, "     %s\n", esc(truncate(u.desc, 30)))
		}
	}
	b.WriteString("</pre>")
	var kb telegram.Keyboard
	var row []telegram.Button
	for i, u := range found {
		if i >= maxButtons {
			break
		}
		row = append(row, telegram.Button{
			Text: "➕ " + truncate(strings.TrimSuffix(u.name, ".service"), 18),
			Data: fmt.Sprintf("sa:%d", i+1),
		})
		if len(row) == 2 {
			kb = append(kb, row)
			row = nil
		}
	}
	if len(row) > 0 {
		kb = append(kb, row)
	}
	kb = append(kb, watchFooterRow())
	return b.String(), kb
}

func (a *Agent) servicesScan(ctx context.Context, _ []string) string {
	text, kb := a.servicesScanView(ctx)
	a.stashKB(kb)
	return text
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
	if slices.Contains(a.watchCopy().Services, name) {
		return esc(name) + " is already watched."
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

// scanPorts lists listening, unwatched ports and stores them for index
// resolution.
func (a *Agent) scanPorts() ([]int, error) {
	if a.src.ListListeners == nil {
		return nil, fmt.Errorf("port scanning unavailable in this build")
	}
	ports, err := a.src.ListListeners()
	if err != nil {
		return nil, err
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
	return found, nil
}

// portsScanView renders the scan with one ➕ button per port.
func (a *Agent) portsScanView() (string, telegram.Keyboard) {
	found, err := a.scanPorts()
	if err != nil {
		return "Scan failed: " + esc(err.Error()), backKeyboard()
	}
	if len(found) == 0 {
		return "👁 Every listening port is already watched.", backKeyboard()
	}
	var b strings.Builder
	fmt.Fprintf(&b, "👁 <b>Listening, not watched</b> — %d\nTap ➕ to watch:\n<pre>", len(found))
	const maxButtons = 12
	for i, p := range found {
		if i >= maxButtons {
			fmt.Fprintf(&b, " … %d more — /ports_add &lt;port&gt;\n", len(found)-maxButtons)
			break
		}
		fmt.Fprintf(&b, " %2d  port %d\n", i+1, p)
	}
	b.WriteString("</pre>")
	var kb telegram.Keyboard
	var row []telegram.Button
	for i, p := range found {
		if i >= maxButtons {
			break
		}
		row = append(row, telegram.Button{Text: fmt.Sprintf("➕ %d", p), Data: fmt.Sprintf("pa:%d", p)})
		if len(row) == 3 {
			kb = append(kb, row)
			row = nil
		}
	}
	if len(row) > 0 {
		kb = append(kb, row)
	}
	kb = append(kb, watchFooterRow())
	return b.String(), kb
}

func (a *Agent) portsScan(ctx context.Context, _ []string) string {
	text, kb := a.portsScanView()
	a.stashKB(kb)
	return text
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
	s := fmt.Sprintf("Now watching: %d services · %d processes · %d ports",
		len(w.Services), len(w.Processes), len(w.Ports))
	if n := len(w.SSLHosts); n > 0 {
		s += fmt.Sprintf(" · %d ssl", n)
	}
	if n := len(w.HTTPChecks); n > 0 {
		s += fmt.Sprintf(" · %d http", n)
	}
	return s
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
	if slices.Contains(scan, n) {
		return n, nil
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
	return slices.Contains(list, s)
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

// ---- button-driven management ----

// watchingView is the management hub: everything watched, one 🗑 button
// per item, plus scan entry points.
func (a *Agent) watchingView() (string, telegram.Keyboard) {
	w := a.watchCopy()
	var kb telegram.Keyboard
	var b strings.Builder
	b.WriteString("👁 <b>Watching</b>\n")
	total := len(w.Services) + len(w.Processes) + len(w.Ports) + len(w.SSLHosts) + len(w.HTTPChecks)
	if total == 0 {
		b.WriteString("Nothing yet — scan to add:")
	} else {
		b.WriteString("Tap 🗑 to stop watching:\n<pre>")
		for _, s := range w.Services {
			fmt.Fprintf(&b, " 🧩 %s\n", esc(s))
			kb = append(kb, []telegram.Button{{Text: "🗑 " + truncate(strings.TrimSuffix(s, ".service"), 20), Data: "sr:" + s}})
		}
		for _, p := range w.Processes {
			fmt.Fprintf(&b, " ⚙ %s\n", esc(p))
			kb = append(kb, []telegram.Button{{Text: "🗑 " + truncate(p, 20), Data: "xr:" + p}})
		}
		for _, p := range w.Ports {
			label := ""
			if p.Label != "" {
				label = " (" + esc(p.Label) + ")"
			}
			fmt.Fprintf(&b, " 🔌 port %d%s\n", p.Port, label)
			kb = append(kb, []telegram.Button{{Text: fmt.Sprintf("🗑 port %d", p.Port), Data: fmt.Sprintf("pr:%d", p.Port)}})
		}
		for _, h := range w.SSLHosts {
			fmt.Fprintf(&b, " 🔒 %s\n", esc(h))
			kb = append(kb, []telegram.Button{{Text: "🗑 " + truncate(h, 20), Data: "cr:" + h}})
		}
		// HTTP checks are removed by index: URLs overflow Telegram's
		// 64-byte callback-data limit.
		for i, h := range w.HTTPChecks {
			fmt.Fprintf(&b, " 🌐 %s\n", esc(truncate(h.URL, 34)))
			kb = append(kb, []telegram.Button{{Text: "🗑 " + truncate(h.URL, 20), Data: fmt.Sprintf("hr:%d", i)}})
		}
		b.WriteString("</pre>")
	}
	kb = append(kb, watchFooterRow())
	return b.String(), kb
}

// watchFooterRow links the management views together.
func watchFooterRow() []telegram.Button {
	return []telegram.Button{
		{Text: "👁 Watching", Data: "watching"},
		{Text: "🔎 Services", Data: "scan_svc"},
		{Text: "🔎 Ports", Data: "scan_port"},
	}
}

func backKeyboard() telegram.Keyboard {
	return telegram.Keyboard{watchFooterRow()}
}

// handleWatchCallback executes management button presses. It returns the
// new message content, keyboard, a toast, and whether the data was ours.
func (a *Agent) handleWatchCallback(ctx context.Context, data string) (string, telegram.Keyboard, string, bool) {
	switch {
	case data == "watching":
		text, kb := a.watchingView()
		return text, kb, "", true

	case data == "scan_svc":
		text, kb := a.servicesScanView(ctx)
		return text, kb, "", true

	case data == "scan_port":
		text, kb := a.portsScanView()
		return text, kb, "", true

	case strings.HasPrefix(data, "sa:"):
		a.mu.Lock()
		scan := append([]string(nil), a.lastServiceScan...)
		a.mu.Unlock()
		name := resolveByIndex(strings.TrimPrefix(data, "sa:"), scan)
		if name == "" {
			text, kb := a.servicesScanView(ctx)
			return text, kb, "stale list — rescanned", true
		}
		a.mutateWatch(func(w *config.Watch) {
			if !contains(w.Services, name) {
				w.Services = append(w.Services, name)
				sort.Strings(w.Services)
			}
		})
		text, kb := a.servicesScanView(ctx)
		return text, kb, "✅ watching " + name, true

	case strings.HasPrefix(data, "pa:"):
		port, err := strconv.Atoi(strings.TrimPrefix(data, "pa:"))
		if err != nil || port < 1 || port > 65535 {
			return "", nil, "bad port", true
		}
		a.mutateWatch(func(w *config.Watch) {
			if !portWatched(w.Ports, port) {
				w.Ports = append(w.Ports, config.PortCheck{Port: port})
				sort.Slice(w.Ports, func(i, j int) bool { return w.Ports[i].Port < w.Ports[j].Port })
			}
		})
		text, kb := a.portsScanView()
		return text, kb, fmt.Sprintf("✅ watching port %d", port), true

	case strings.HasPrefix(data, "sr:"):
		name := strings.TrimPrefix(data, "sr:")
		a.mutateWatch(func(w *config.Watch) { w.Services = remove(w.Services, name) })
		text, kb := a.watchingView()
		return text, kb, "🗑 " + name, true

	case strings.HasPrefix(data, "xr:"):
		name := strings.TrimPrefix(data, "xr:")
		a.mutateWatch(func(w *config.Watch) { w.Processes = remove(w.Processes, name) })
		text, kb := a.watchingView()
		return text, kb, "🗑 " + name, true

	case strings.HasPrefix(data, "cr:"):
		host := strings.TrimPrefix(data, "cr:")
		a.mutateWatch(func(w *config.Watch) { w.SSLHosts = remove(w.SSLHosts, host) })
		text, kb := a.watchingView()
		return text, kb, "🗑 " + host, true

	case strings.HasPrefix(data, "hr:"):
		i, err := strconv.Atoi(strings.TrimPrefix(data, "hr:"))
		checks := a.watchCopy().HTTPChecks
		if err != nil || i < 0 || i >= len(checks) {
			text, kb := a.watchingView()
			return text, kb, "stale list", true
		}
		url := checks[i].URL
		a.mutateWatch(func(w *config.Watch) {
			kept := w.HTTPChecks[:0]
			for _, h := range w.HTTPChecks {
				if h.URL != url {
					kept = append(kept, h)
				}
			}
			w.HTTPChecks = kept
		})
		text, kb := a.watchingView()
		return text, kb, "🗑 " + truncate(url, 30), true

	case strings.HasPrefix(data, "pr:"):
		port, err := strconv.Atoi(strings.TrimPrefix(data, "pr:"))
		if err != nil {
			return "", nil, "bad port", true
		}
		a.mutateWatch(func(w *config.Watch) {
			kept := w.Ports[:0]
			for _, p := range w.Ports {
				if p.Port != port {
					kept = append(kept, p)
				}
			}
			w.Ports = kept
		})
		text, kb := a.watchingView()
		return text, kb, fmt.Sprintf("🗑 port %d", port), true
	}
	return "", nil, "", false
}
