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
	"github.com/eliau2005/statixagent/internal/services"
	"github.com/eliau2005/statixagent/internal/telegram"
	"github.com/eliau2005/statixagent/internal/tgui"
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

// registerWatchHandlers adds the add/remove command family; /watching and
// the scans are screens (commandScreens).
func (a *Agent) registerWatchHandlers(r *bot.Router) {
	r.Handle("services_add", bot.Text(a.servicesAdd))
	r.Handle("services_remove", bot.Text(a.servicesRemove))
	r.Handle("ports_add", bot.Text(a.portsAdd))
	r.Handle("ports_remove", bot.Text(a.portsRemove))
	r.Handle("procs_add", bot.Text(a.procsAdd))
	r.Handle("procs_remove", bot.Text(a.procsRemove))
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
		if watched[f[0]] || f[0] == "statix-agent.service" || !services.ValidUnitName(f[0]) {
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

// servicesScanView renders the Scan services screen as a message.
func (a *Agent) servicesScanView(ctx context.Context) (string, telegram.Keyboard) {
	return a.screen(ctx, tgui.Open(scrScanServices))
}

// scanServicesScreen pages the running units nobody watches, one ➕
// button each. A button names its unit by digest and is resolved
// against a fresh scan when pressed. The numbers are the ones
// /services_add takes.
func (a *Agent) scanServicesScreen(ctx context.Context, c tgui.Call) tgui.View {
	found, err := a.scanServices(ctx)
	if err != nil {
		return tgui.View{Text: "🔎 Scan failed: " + esc(err.Error())}
	}
	if len(found) == 0 {
		return tgui.View{Text: "🔎 Every running service is already watched."}
	}
	page, pages := pageOf(c, len(found))
	var lines []string
	var btns []tgui.Button
	for i, u := range pageSlice(found, page) {
		lines = append(lines, fmt.Sprintf("%2d %s", (page-1)*pageSize+i+1, u.name))
		if u.desc != "" {
			lines = append(lines, "   "+bot.Clip(u.desc, bot.PreCols-3))
		}
		btns = append(btns, tgui.Button{
			Label: "➕ " + truncate(strings.TrimSuffix(u.name, ".service"), 18),
			Call:  tgui.Call{Act: cfgWatch, Args: []string{watchUnit, callbackDigest(u.name), strconv.Itoa(page)}, From: c.From},
		})
	}
	title := listTitle("🔎 <b>Running, not watched</b>", plural(len(found), "service"), page, pages)
	return tgui.View{
		Text: title + "\nTap ➕ to watch, or /services_add &lt;number&gt;:\n" + pre(lines),
		Rows: append(buttonRows(btns, 2), pageRow(scrScanServices, c, page, pages)),
	}
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
	if !services.ValidUnitName(name) {
		return "Invalid unit name: " + esc(name) + "\nUse a name like nginx.service (letters, digits, :_.@-)."
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

// portsScanView renders the Scan ports screen as a message.
func (a *Agent) portsScanView() (string, telegram.Keyboard) {
	return a.screen(context.Background(), tgui.Open(scrScanPorts))
}

// scanPortsScreen pages the listening ports nobody watches, one ➕
// button each, carrying the port itself.
func (a *Agent) scanPortsScreen(_ context.Context, c tgui.Call) tgui.View {
	found, err := a.scanPorts()
	if err != nil {
		return tgui.View{Text: "🔎 Scan failed: " + esc(err.Error())}
	}
	if len(found) == 0 {
		return tgui.View{Text: "🔎 Every listening port is already watched."}
	}
	page, pages := pageOf(c, len(found))
	var lines []string
	var btns []tgui.Button
	for i, p := range pageSlice(found, page) {
		lines = append(lines, fmt.Sprintf("%2d port %d", (page-1)*pageSize+i+1, p))
		btns = append(btns, tgui.Button{
			Label: fmt.Sprintf("➕ %d", p),
			Call:  tgui.Call{Act: cfgWatch, Args: []string{watchPort, strconv.Itoa(p), strconv.Itoa(page)}, From: c.From},
		})
	}
	title := listTitle("🔎 <b>Listening, not watched</b>", plural(len(found), "port"), page, pages)
	return tgui.View{
		Text: title + "\nTap ➕ to watch, or /ports_add &lt;number&gt;:\n" + pre(lines),
		Rows: append(buttonRows(btns, 4), pageRow(scrScanPorts, c, page, pages)),
	}
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
		return esc(err.Error())
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

// Watch item kinds, as the Watching and scan buttons name them.
const (
	watchUnit = "u" // systemd unit
	watchProc = "x" // process
	watchPort = "p" // TCP port
	watchCert = "c" // certificate host
	watchHTTP = "h" // HTTP check URL
)

// watchItem is one watched thing as the Watching screen lists it.
type watchItem struct {
	kind string
	// id names the item in callback data: the port itself, else the
	// digest of the name, resolved by hashing the current list again.
	id   string
	name string // as the config holds it
	note string // a port's label
}

// watchIcons are the glossary emoji of each kind (§2).
var watchIcons = map[string]string{watchUnit: "🧩", watchProc: "🧵", watchPort: "🔌", watchCert: "📜", watchHTTP: "🌐"}

// watchItems flattens the watch lists in the order Watching shows them.
func watchItems(w config.Watch) []watchItem {
	var items []watchItem
	named := func(kind string, names []string) {
		for _, n := range names {
			items = append(items, watchItem{kind: kind, id: callbackDigest(n), name: n})
		}
	}
	named(watchUnit, w.Services)
	named(watchProc, w.Processes)
	for _, p := range w.Ports {
		items = append(items, watchItem{kind: watchPort, id: strconv.Itoa(p.Port), name: strconv.Itoa(p.Port), note: p.Label})
	}
	named(watchCert, w.SSLHosts)
	for _, h := range w.HTTPChecks {
		items = append(items, watchItem{kind: watchHTTP, id: callbackDigest(h.URL), name: h.URL})
	}
	return items
}

// short is the item's name for a button.
func (it watchItem) short() string {
	s := strings.TrimSuffix(it.name, ".service")
	if it.kind == watchHTTP {
		s = strings.TrimPrefix(strings.TrimPrefix(s, "https://"), "http://")
	}
	return truncate(s, 12)
}

// line is the item as the Watching screen lists it.
func (it watchItem) line() string {
	s := watchIcons[it.kind] + " " + it.name
	if it.note != "" {
		s += " (" + it.note + ")"
	}
	return s
}

// unwatch removes the item from w.
func (it watchItem) unwatch(w *config.Watch) {
	switch it.kind {
	case watchUnit:
		w.Services = remove(w.Services, it.name)
	case watchProc:
		w.Processes = remove(w.Processes, it.name)
	case watchCert:
		w.SSLHosts = remove(w.SSLHosts, it.name)
	case watchPort:
		w.Ports = slices.DeleteFunc(w.Ports, func(p config.PortCheck) bool { return strconv.Itoa(p.Port) == it.name })
	case watchHTTP:
		w.HTTPChecks = slices.DeleteFunc(w.HTTPChecks, func(h config.HTTPCheck) bool { return h.URL == it.name })
	}
}

// validWatchID reports whether id can name an item of kind: a port in
// canonical form, or a digest.
func validWatchID(kind, id string) bool {
	switch kind {
	case watchPort:
		_, ok := parsePort(id)
		return ok
	case watchUnit, watchProc, watchCert, watchHTTP:
		return len(id) == 16 && isHex(id)
	}
	return false
}

// parsePort parses a port in canonical form, 1-65535.
func parsePort(s string) (int, bool) {
	n, err := strconv.Atoi(s)
	return n, err == nil && strconv.Itoa(n) == s && n >= 1 && n <= 65535
}

// parsePage parses a page argument in canonical form. Pages past the
// end are clamped when rendered.
func parsePage(s string) (int, bool) {
	n, err := strconv.Atoi(s)
	return n, err == nil && strconv.Itoa(n) == s && n >= 1
}

// watchingView renders the Watching screen as a message.
func (a *Agent) watchingView() (string, telegram.Keyboard) {
	return a.screen(context.Background(), tgui.Open(scrWatching))
}

// watchingScreen is the bulk editor (§3.11): everything watched, paged,
// with a 🗑 button per item carrying its stable ID, and the scans.
func (a *Agent) watchingScreen(_ context.Context, c tgui.Call) tgui.View {
	scans := []tgui.Button{
		{Label: "🔎 Scan services", Call: tgui.Open(scrScanServices)},
		{Label: "🔎 Scan ports", Call: tgui.Open(scrScanPorts)},
	}
	items := watchItems(a.watchCopy())
	if len(items) == 0 {
		return tgui.View{Text: "👁 <b>Watching</b>\nNothing yet — scan to add:", Rows: [][]tgui.Button{scans}}
	}
	page, pages := pageOf(c, len(items))
	var lines []string
	var btns []tgui.Button
	for _, it := range pageSlice(items, page) {
		lines = append(lines, it.line())
		btns = append(btns, tgui.Button{
			Label: "🗑 " + it.short(),
			Call:  tgui.Call{Act: cfgUnwatch, Args: []string{it.kind, it.id, strconv.Itoa(page)}, From: c.From},
		})
	}
	title := listTitle("👁 <b>Watching</b>", plural(len(items), "item"), page, pages)
	return tgui.View{
		Text: title + "\nTap 🗑 to stop watching:\n" + pre(lines),
		Rows: append(buttonRows(btns, 3), scans, pageRow(scrWatching, c, page, pages)),
	}
}

// listTitle is a paged list's title: "👁 Watching · 14 items · 1/2".
func listTitle(title, count string, page, pages int) string {
	title += " · " + count
	if pages > 1 {
		title += fmt.Sprintf(" · %d/%d", page, pages)
	}
	return title
}

// buttonRows lays btns out n to a row.
func buttonRows(btns []tgui.Button, n int) [][]tgui.Button {
	var rows [][]tgui.Button
	for len(btns) > n {
		rows, btns = append(rows, btns[:n]), btns[n:]
	}
	return append(rows, btns)
}

// itemGoneToast answers a press whose item is no longer listed.
const itemGoneToast = "Item gone, refreshed"

// unwatchPress handles "~1wr|<kind>|<id>|<page>": it stops watching the
// item id names, if it is still watched, and shows Watching again at
// that page. A replay finds the item gone and changes nothing.
func (a *Agent) unwatchPress(ctx context.Context, cb *telegram.Callback, c tgui.Call) {
	if len(c.Args) != 3 || !validWatchID(c.Args[0], c.Args[1]) {
		a.refuseCallback(ctx, cb, false)
		return
	}
	page, ok := parsePage(c.Args[2])
	if !ok {
		a.refuseCallback(ctx, cb, false)
		return
	}
	toast := itemGoneToast
	items := watchItems(a.watchCopy())
	if i := slices.IndexFunc(items, func(it watchItem) bool { return it.kind == c.Args[0] && it.id == c.Args[1] }); i >= 0 {
		it := items[i]
		toast = "🗑 Stopped watching " + truncate(it.name, 60) + a.mutateWatch(it.unwatch)
	}
	text, kb := a.screen(ctx, tgui.Call{Act: tgui.ActView, Args: []string{scrWatching, strconv.Itoa(page)}, From: c.From})
	a.finishCallback(ctx, cb, false, text, kb, toast)
}

// watchPress handles "~1wa|<kind>|<id>|<page>" from a scan: a unit named
// by digest, resolved against a fresh scan, or a port. It shows the scan
// again at that page. A replay finds the item watched and changes nothing.
func (a *Agent) watchPress(ctx context.Context, cb *telegram.Callback, c tgui.Call) {
	if len(c.Args) != 3 || (c.Args[0] != watchUnit && c.Args[0] != watchPort) || !validWatchID(c.Args[0], c.Args[1]) {
		a.refuseCallback(ctx, cb, false)
		return
	}
	page, ok := parsePage(c.Args[2])
	if !ok {
		a.refuseCallback(ctx, cb, false)
		return
	}
	var toast, screen string
	if c.Args[0] == watchPort {
		screen = scrScanPorts
		port, _ := parsePort(c.Args[1])
		toast = fmt.Sprintf("Port %d is already watched", port)
		if !portWatched(a.watchCopy().Ports, port) {
			toast = fmt.Sprintf("✅ Watching port %d", port) + a.mutateWatch(func(w *config.Watch) {
				if !portWatched(w.Ports, port) {
					w.Ports = append(w.Ports, config.PortCheck{Port: port})
					sort.Slice(w.Ports, func(i, j int) bool { return w.Ports[i].Port < w.Ports[j].Port })
				}
			})
		}
	} else {
		screen = scrScanServices
		toast = a.watchScannedUnit(ctx, c.Args[1])
	}
	text, kb := a.screen(ctx, tgui.Call{Act: tgui.ActView, Args: []string{screen, strconv.Itoa(page)}, From: c.From})
	a.finishCallback(ctx, cb, false, text, kb, toast)
}

// watchScannedUnit watches the running unit whose name hashes to id and
// returns the toast saying what happened.
func (a *Agent) watchScannedUnit(ctx context.Context, id string) string {
	for _, s := range a.watchCopy().Services {
		if callbackDigest(s) == id {
			return truncate(s, 60) + " is already watched"
		}
	}
	found, err := a.scanServices(ctx)
	if err != nil {
		return "Scan failed"
	}
	i := slices.IndexFunc(found, func(u unitInfo) bool { return callbackDigest(u.name) == id })
	if i < 0 {
		return itemGoneToast
	}
	name := found[i].name
	return "✅ Watching " + truncate(name, 60) + a.mutateWatch(func(w *config.Watch) {
		if !contains(w.Services, name) {
			w.Services = append(w.Services, name)
			sort.Strings(w.Services)
		}
	})
}

// handleWatchCallback executes the management buttons of older versions,
// which name items by list index and fingerprint. It returns the new
// message content, keyboard, a toast, and whether the data was ours.
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
		// sa:<i>:<fp16> binds the button to the unit name. Legacy sa:<n>
		// carries only a position, so it just rescans.
		i, fp, ok := parseWatchIndexData(data, "sa:")
		if !ok {
			text, kb := a.servicesScanView(ctx)
			return text, kb, "List refreshed", true
		}
		a.mu.Lock()
		scan := append([]string(nil), a.lastServiceScan...)
		a.mu.Unlock()
		name, ok := matchWatchItem(scan, i, fp, len(fp) == 16)
		if !ok {
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
		i, fp, ok := parseWatchIndexData(data, "sr:")
		services := a.watchCopy().Services
		name, ok := matchWatchItem(services, i, fp, ok)
		if !ok {
			text, kb := a.watchingView()
			return text, kb, "stale list", true
		}
		a.mutateWatch(func(w *config.Watch) { w.Services = remove(w.Services, name) })
		text, kb := a.watchingView()
		return text, kb, "🗑 " + name, true

	case strings.HasPrefix(data, "xr:"):
		i, fp, ok := parseWatchIndexData(data, "xr:")
		procs := a.watchCopy().Processes
		name, ok := matchWatchItem(procs, i, fp, ok)
		if !ok {
			text, kb := a.watchingView()
			return text, kb, "stale list", true
		}
		a.mutateWatch(func(w *config.Watch) { w.Processes = remove(w.Processes, name) })
		text, kb := a.watchingView()
		return text, kb, "🗑 " + name, true

	case strings.HasPrefix(data, "cr:"):
		i, fp, ok := parseWatchIndexData(data, "cr:")
		hosts := a.watchCopy().SSLHosts
		host, ok := matchWatchItem(hosts, i, fp, ok)
		if !ok {
			text, kb := a.watchingView()
			return text, kb, "stale list", true
		}
		a.mutateWatch(func(w *config.Watch) { w.SSLHosts = remove(w.SSLHosts, host) })
		text, kb := a.watchingView()
		return text, kb, "🗑 " + host, true

	case strings.HasPrefix(data, "hr:"):
		i, fp, ok := parseWatchIndexData(data, "hr:")
		checks := a.watchCopy().HTTPChecks
		if !ok || i < 0 || i >= len(checks) || !watchFingerprintMatches(checks[i].URL, fp) {
			text, kb := a.watchingView()
			return text, kb, "stale list", true
		}
		url := checks[i].URL
		a.mutateWatch(watchItem{kind: watchHTTP, name: url}.unwatch)
		text, kb := a.watchingView()
		return text, kb, "🗑 " + truncate(url, 30), true

	case strings.HasPrefix(data, "pr:"):
		port, err := strconv.Atoi(strings.TrimPrefix(data, "pr:"))
		if err != nil {
			return "", nil, "bad port", true
		}
		a.mutateWatch(watchItem{kind: watchPort, name: strconv.Itoa(port)}.unwatch)
		text, kb := a.watchingView()
		return text, kb, fmt.Sprintf("🗑 port %d", port), true
	}
	return "", nil, "", false
}

func parseWatchIndexData(data, prefix string) (int, string, bool) {
	rest, ok := strings.CutPrefix(data, prefix)
	if !ok {
		return 0, "", false
	}
	idxStr, fpStr, ok := strings.Cut(rest, ":")
	if !ok {
		return 0, "", false
	}
	i, err := strconv.Atoi(idxStr)
	if err != nil {
		return 0, "", false
	}
	// Accept new 16-char SHA-256 fingerprints and legacy 8-char CRC32 ones.
	if len(fpStr) != 16 && len(fpStr) != 8 {
		return 0, "", false
	}
	for _, c := range fpStr {
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return 0, "", false
		}
	}
	return i, fpStr, true
}

func matchWatchItem(list []string, i int, fp string, parsed bool) (string, bool) {
	if !parsed || i < 0 || i >= len(list) {
		return "", false
	}
	if !watchFingerprintMatches(list[i], fp) {
		return "", false
	}
	return list[i], true
}

// watchFingerprintMatches compares fp against the item using the new truncated
// SHA-256 form (16 hex) or the legacy CRC32 form (8 hex) from #64.
func watchFingerprintMatches(item, fp string) bool {
	switch len(fp) {
	case 16:
		return callbackDigest(item) == fp
	case 8:
		return legacyCRC32Hex(item) == fp
	default:
		return false
	}
}
