package agent

import (
	"cmp"
	"context"
	"errors"
	"fmt"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/eliau2005/statixagent/internal/bot"
	"github.com/eliau2005/statixagent/internal/dockermon"
	"github.com/eliau2005/statixagent/internal/netcheck"
	"github.com/eliau2005/statixagent/internal/services"
	"github.com/eliau2005/statixagent/internal/tgui"
)

// The services hub (docs/telegram-ux-redesign.md §3.3-§3.7): a count per
// kind, one filtered list per kind with failing items first, and detail
// screens for units and containers. It only reads: nothing here starts,
// stops or restarts anything.
//
// An item button names its item by a stable ID, never a list index and
// never a name (unit names run to 256 characters): a unit by the digest
// of its name, a container by its short ID. A detail screen resolves the
// ID against a fresh listing, so an item that has gone shows its list
// again instead of something else.

// svDocker is the kind of a container; the other kinds are the watch
// kinds (watch.go).
const svDocker = "d"

// svItem is one row of a hub list.
type svItem struct {
	kind string
	// id names the item in callback data: a unit's name digest or a
	// container's short ID; "" for kinds without a detail screen.
	id      string
	name    string // as systemd, Docker or the config has it
	label   string // as the list shows it
	state   services.State
	status  string // short state: "failed", "running", "got 503, want 200"
	watched bool
}

// icon is the item's state emoji; a healthy watched unit is starred.
func (it svItem) icon() string {
	switch it.state {
	case services.StateDown:
		return "❌"
	case services.StateDegraded:
		return "⚠️"
	case services.StateUnknown:
		return "❔"
	}
	if it.watched && it.kind == watchUnit {
		return "⭐"
	}
	return "✅"
}

// rank orders a list failing first: down, unknown, degraded, then the
// healthy ones, watched before the rest.
func (it svItem) rank() int {
	switch it.state {
	case services.StateDown:
		return 0
	case services.StateUnknown:
		return 1
	case services.StateDegraded:
		return 2
	}
	if it.watched {
		return 3
	}
	return 4
}

// detail is the screen showing the item, or "" when its kind has none.
func (it svItem) detail() string {
	switch {
	case it.id == "":
		return ""
	case it.kind == watchUnit:
		return scrUnit
	case it.kind == svDocker:
		return scrContainer
	}
	return ""
}

// rows is the item in a list; withKind prefixes the kind's emoji, for
// the Failing list that mixes kinds.
func (it svItem) rows(withKind bool) []string {
	switch {
	case withKind:
		return []string{bot.ItemRow(it.icon(), kindIcon(it.kind)+" "+it.label, it.status)}
	case it.kind == watchHTTP || it.kind == watchCert:
		return bot.ItemRows(it.icon(), it.label, it.status)
	}
	return []string{bot.ItemRow(it.icon(), it.label, it.status)}
}

// kindIcon is the glossary emoji of an item kind (§2).
func kindIcon(kind string) string {
	if kind == svDocker {
		return "🐳"
	}
	return watchIcons[kind]
}

// failing counts the items that are not OK.
func failing(items []svItem) int {
	n := 0
	for _, it := range items {
		if it.state != services.StateOK {
			n++
		}
	}
	return n
}

// sortItems puts failing items first, keeping the listing's order within
// each group.
func sortItems(items []svItem) []svItem {
	slices.SortStableFunc(items, func(x, y svItem) int { return cmp.Compare(x.rank(), y.rank()) })
	return items
}

// svKind is one kind of item: its list screen, its row on the hub and
// how its items are read.
type svKind struct {
	id    string // list screen
	label string // on the hub and its button
	emoji string
	// title heads the list; nouns counts its items ("unit", "units");
	// bad is what a not-OK item is called, "" to leave it out.
	title        string
	noun, nouns  string
	bad          string
	empty, notes string // HTML: the list when empty, and under it
	load         func(a *Agent, ctx context.Context) ([]svItem, error)
}

// count is "3 units" / "1 unit".
func (k svKind) count(n int) string {
	if n == 1 {
		return "1 " + k.noun
	}
	return fmt.Sprintf("%d %s", n, k.nouns)
}

// The kinds, in hub order.
var (
	kindUnits = svKind{id: scrUnits, label: "Units", emoji: "🧩", title: "Units", noun: "unit", nouns: "units", bad: "failing",
		empty: "No units listed.", notes: "⭐ = watched · tap a unit for details", load: (*Agent).unitItems}
	kindDocker = svKind{id: scrDocker, label: "Docker", emoji: "🐳", title: "Docker", noun: "container", nouns: "containers", bad: "down",
		empty: "No containers.", notes: "Tap a container for details", load: (*Agent).containerItems}
	kindHTTP = svKind{id: scrHTTP, label: "HTTP", emoji: "🌐", title: "HTTP checks", noun: "check", nouns: "checks", bad: "failing",
		empty: "No HTTP checks yet.\nAdd one: <code>/http add https://example.com/healthz</code>",
		notes: "Add: <code>/http add url</code> · remove: <code>/http remove url</code>", load: (*Agent).httpItems}
	kindCerts = svKind{id: scrSSL, label: "Certificates", emoji: "📜", title: "Certificates", noun: "certificate", nouns: "certificates", bad: "expiring",
		empty: "No certificates watched yet.\nAdd one: <code>/ssl add example.com</code>",
		notes: "Add: <code>/ssl add host[:port]</code> · remove: <code>/ssl remove host</code>", load: (*Agent).certItems}
	kindPorts = svKind{id: scrPorts, label: "Ports", emoji: "🔌", title: "Ports", noun: "port", nouns: "ports", bad: "closed",
		empty: "No ports watched yet.", load: (*Agent).portItems}
	kindProcs = svKind{id: scrProcs, label: "Processes", emoji: "🧵", title: "Processes", noun: "process", nouns: "processes", bad: "not running",
		empty: "No processes watched yet.\nAdd one: <code>/procs_add nginx</code>", load: (*Agent).procItems}
	svKinds = []svKind{kindUnits, kindDocker, kindHTTP, kindCerts, kindPorts, kindProcs}
)

// hubScreen is the services hub (§3.3): every kind with its count and
// state, and the way into each list.
func (a *Agent) hubScreen(ctx context.Context, _ tgui.Call) tgui.View {
	var rows []string
	ok, bad := 0, 0
	for _, k := range svKinds {
		items, err := k.load(a, ctx)
		if err != nil {
			rows = append(rows, bot.HubRow(k.label, "—", "n/a"))
			continue
		}
		n := failing(items)
		ok, bad = ok+len(items)-n, bad+n
		rows = append(rows, bot.HubRow(k.label, strconv.Itoa(len(items)), hubMark(items)))
	}
	open := func(k svKind) tgui.Button { return tgui.Button{Label: k.emoji + " " + k.label, Call: tgui.Open(k.id)} }
	var kb [][]tgui.Button
	if bad > 0 {
		kb = append(kb, []tgui.Button{{Label: fmt.Sprintf("❌ Failing (%d)", bad), Call: tgui.Open(scrFailing)}})
	}
	kb = append(kb,
		[]tgui.Button{open(kindUnits), open(kindDocker)},
		[]tgui.Button{open(kindHTTP), open(kindCerts)},
		[]tgui.Button{open(kindPorts), open(kindProcs)},
		[]tgui.Button{{Label: "👁 Watching", Call: tgui.Call{Act: tgui.ActView, Args: []string{scrWatching}, From: scrServices}}},
	)
	title := fmt.Sprintf("🧩 <b>Services</b> · %d OK · %d failing", ok, bad)
	return tgui.View{Text: title + "\n" + pre(rows), Rows: kb}
}

// hubMark is a kind's state on the hub: its worst item's emoji and how
// many are not OK, or ✅.
func hubMark(items []svItem) string {
	switch n := failing(items); {
	case len(items) == 0:
		return ""
	case n == 0:
		return "✅"
	default:
		return sortItems(slices.Clone(items))[0].icon() + " " + strconv.Itoa(n)
	}
}

// listView renders one page of a list: its rows, a button per item with
// a detail screen, and the page row. c is the list's own call.
func listView(k svKind, title string, items []svItem, c tgui.Call, withKind bool) tgui.View {
	head := fmt.Sprintf("%s <b>%s</b>", k.emoji, title)
	if len(items) == 0 {
		return tgui.View{Text: head + "\n" + k.empty}
	}
	head += " · " + k.count(len(items))
	if n := failing(items); n > 0 && k.bad != "" {
		head += fmt.Sprintf(" · %d %s", n, k.bad)
	}
	page, pages := pageOf(c, len(items))
	if pages > 1 {
		head += fmt.Sprintf(" · %d/%d", page, pages)
	}
	var lines []string
	var btns []tgui.Button
	for _, it := range pageSlice(items, page) {
		lines = append(lines, it.rows(withKind)...)
		if d := it.detail(); d != "" {
			btns = append(btns, tgui.Button{
				Label: it.icon() + " " + truncate(it.label, 14),
				Call:  tgui.Call{Act: tgui.ActView, Args: []string{d, it.id}, From: k.id},
			})
		}
	}
	text := head + "\n" + pre(lines)
	if k.notes != "" {
		text += "\n" + k.notes
	}
	return tgui.View{Text: text, Rows: append(buttonRows(btns, 2), pageRow(k.id, c, page, pages))}
}

// kindScreen is the list screen of k.
func (a *Agent) kindScreen(k svKind) func(context.Context, tgui.Call) tgui.View {
	return func(ctx context.Context, c tgui.Call) tgui.View {
		items, err := k.load(a, ctx)
		if err != nil {
			return tgui.View{Text: k.emoji + " " + esc(err.Error())}
		}
		v := listView(k, k.title, sortItems(items), c, false)
		switch k.id {
		case scrUnits:
			v.Rows = abovePages(v.Rows, unitFilterRow())
		case scrPorts:
			v.Rows = abovePages(v.Rows, []tgui.Button{
				{Label: "🔎 Scan ports", Call: tgui.Call{Act: tgui.ActView, Args: []string{scrScanPorts}, From: scrPorts}},
				{Label: "🛡 Firewall", Call: tgui.Call{Act: tgui.ActView, Args: []string{scrFirewall}, From: scrPorts}},
			})
		}
		return v
	}
}

// abovePages adds row to a list's rows, above its page row (the last of
// a list that has items).
func abovePages(rows [][]tgui.Button, row []tgui.Button) [][]tgui.Button {
	if len(rows) == 0 {
		return [][]tgui.Button{row}
	}
	return slices.Insert(rows, len(rows)-1, row)
}

// unitFilterRow switches the Units list between every unit and the
// watched ones.
func unitFilterRow() []tgui.Button {
	return []tgui.Button{{Label: "⭐ Watched only", Call: tgui.Open(scrUnitsWatched)}, {Label: "🔤 All units", Call: tgui.Open(scrUnits)}}
}

// watchedUnitsScreen is the Units list cut to the watched units.
func (a *Agent) watchedUnitsScreen(ctx context.Context, c tgui.Call) tgui.View {
	items, err := a.unitItems(ctx)
	if err != nil {
		return tgui.View{Text: "🧩 " + esc(err.Error())}
	}
	k := kindUnits
	k.id, k.empty = scrUnitsWatched, "No units watched yet. Find some: /services_scan"
	v := listView(k, "Watched units", sortItems(watchedOnly(items)), c, false)
	v.Rows = abovePages(v.Rows, unitFilterRow())
	return v
}

func watchedOnly(items []svItem) []svItem {
	return slices.DeleteFunc(items, func(it svItem) bool { return !it.watched })
}

// failingScreen lists every item of every kind that is not OK.
func (a *Agent) failingScreen(ctx context.Context, c tgui.Call) tgui.View {
	var bad []svItem
	for _, k := range svKinds {
		if items, err := k.load(a, ctx); err == nil {
			bad = append(bad, slices.DeleteFunc(items, func(it svItem) bool { return it.state == services.StateOK })...)
		}
	}
	k := svKind{id: scrFailing, emoji: "❌", noun: "item", nouns: "items", empty: "✅ Nothing is failing.",
		notes: "Tap a unit or container for details"}
	return listView(k, "Failing", sortItems(bad), c, true)
}

// itemGoneBanner heads a list shown in place of an item that has gone.
const itemGoneBanner = "⚠️ " + itemGoneToast

// find returns the index of the item c names (its second argument), or
// -1 when none has that ID.
func find(items []svItem, c tgui.Call) int {
	if len(c.Args) != 2 {
		return -1
	}
	return slices.IndexFunc(items, func(it svItem) bool { return it.id != "" && it.id == c.Args[1] })
}

// gone is the list k, from the items just read, in place of an item that
// is no longer listed.
func gone(k svKind, title string, items []svItem) tgui.View {
	v := listView(k, title, sortItems(items), tgui.Open(k.id), false)
	v.Text = itemGoneBanner + "\n" + v.Text
	return v
}

// ---- units ----

// unitName is the name systemd knows a watched unit by: a hand-written
// "nginx" is nginx.service, as for CheckSystemdUnits.
func unitName(s string) string {
	if !strings.Contains(s, ".") {
		return s + ".service"
	}
	return s
}

// unitItems lists the units in one systemctl call: every service that is
// not inactive, every failed unit and every watched one. A watched unit
// systemd does not list is "not found".
func (a *Agent) unitItems(ctx context.Context) ([]svItem, error) {
	if a.src.Runner == nil {
		return nil, errors.New("Unit listing is not available in this build.")
	}
	units, err := services.ListUnits(ctx, a.src.Runner)
	if err != nil {
		return nil, fmt.Errorf("Could not list units: %w", err)
	}
	watched := map[string]bool{}
	for _, s := range a.watchCopy().Services {
		watched[unitName(s)] = true
	}
	seen := map[string]bool{}
	var items []svItem
	for _, u := range units {
		w := watched[u.Name]
		shown := w || u.Active == "failed" || u.Active != "inactive" && strings.HasSuffix(u.Name, ".service")
		if seen[u.Name] || !shown {
			continue
		}
		seen[u.Name] = true
		it := svItem{kind: watchUnit, id: callbackDigest(u.Name), name: u.Name, label: strings.TrimSuffix(u.Name, ".service"), watched: w, status: u.Active}
		switch u.Active {
		case "active":
			it.state, it.status = services.StateOK, u.Sub
		case "activating", "deactivating", "reloading", "refreshing":
			it.state = services.StateDegraded
		case "failed", "inactive":
			it.state = services.StateDown
		default:
			it.state = services.StateUnknown
		}
		if u.Load == "not-found" {
			it.state, it.status = services.StateUnknown, "not found"
		}
		items = append(items, it)
	}
	var missing []string
	for name := range watched {
		if !seen[name] {
			missing = append(missing, name)
		}
	}
	slices.Sort(missing)
	for _, name := range missing {
		items = append(items, svItem{kind: watchUnit, id: callbackDigest(name), name: name,
			label: strings.TrimSuffix(name, ".service"), state: services.StateUnknown, status: "not found", watched: true})
	}
	return items, nil
}

// unitScreen is one unit's detail (§3.3): the unit is listed again and
// found by its digest, then read with systemctl show.
func (a *Agent) unitScreen(ctx context.Context, c tgui.Call) tgui.View {
	items, err := a.unitItems(ctx)
	if err != nil {
		return tgui.View{Text: "🧩 " + esc(err.Error())}
	}
	i := find(items, c)
	if i < 0 {
		if c.From == scrUnitsWatched {
			k := kindUnits
			k.id = scrUnitsWatched
			return gone(k, "Watched units", watchedOnly(items))
		}
		return gone(kindUnits, kindUnits.title, items)
	}
	it := items[i]
	text := "🧩 <b>" + esc(it.name) + "</b>\n"
	note := "Not watched"
	if it.watched {
		note = "⭐ Watched"
	}
	switch {
	case it.status == "not found":
		return tgui.View{Text: text + pre(bot.KV("State", it.status)) + "\n" + note + " · systemd has no such unit"}
	case !services.ValidUnitName(it.name):
		// An escaped name (\x2d) never goes back to systemctl.
		return tgui.View{Text: text + pre(bot.KV("State", it.status)) + "\n" + note + " · no details for this name"}
	}
	d, err := services.ShowUnit(ctx, a.src.Runner, it.name)
	if err != nil {
		return tgui.View{Text: text + pre(bot.KV("State", it.status)) + "\n" + note + "\nCould not read details: " + esc(clipErr(err))}
	}
	state := d.Active
	if why := d.Sub; why != "" {
		if d.Active == "failed" && d.Result != "" {
			why = d.Result
		}
		state += " (" + why + ")"
	}
	var rows []string
	if d.Load != "" && d.Load != "loaded" {
		rows = append(rows, bot.KV("Load", d.Load)...)
	}
	rows = append(rows, bot.KV("State", state)...)
	rows = append(rows, bot.KV("Since", a.since(d.Since))...)
	rows = append(rows, bot.KV("Boot", d.UnitFile)...)
	rows = append(rows, bot.KV("Restarts", d.Restarts)...)
	mem := ""
	if d.MemoryOK {
		mem = bot.BytesShort(d.Memory)
	}
	rows = append(rows, bot.KV("Memory", mem)...)
	return tgui.View{Text: text + pre(rows) + "\n" + note}
}

// since is when something changed and how long ago: "12:41 · 2m ago", or
// with the date when it was not today; "" for a zero time.
func (a *Agent) since(t time.Time) string {
	if t.IsZero() {
		return ""
	}
	now := a.now().In(t.Location())
	at := t.Format("15:04")
	if y, m, d := now.Date(); t.Day() != d || t.Month() != m || t.Year() != y {
		at = t.Format("Jan 02 15:04")
	}
	return at + " · " + bot.Age(now.Sub(t)) + " ago"
}

// clipErr is an error's text, short enough for a screen.
func clipErr(err error) string {
	return truncate(err.Error(), 200)
}

// ---- containers ----

// shortIDLen is the length of a container's short ID, as docker ps shows.
const shortIDLen = 12

// exitedRE reads the exit code from a container's status text.
var exitedRE = regexp.MustCompile(`^Exited \((-?\d+)\)`)

// containers lists the containers with one request, no inspect.
func (a *Agent) containers(ctx context.Context) ([]dockermon.Container, error) {
	if a.src.Docker == nil || !a.cfg.Monitors.Docker {
		return nil, errors.New("Docker monitoring is not enabled.")
	}
	cts, err := a.src.Docker.List(ctx)
	if err != nil {
		return nil, fmt.Errorf("Docker unreachable: %w", err)
	}
	return cts, nil
}

// containerItems lists the containers as hub items.
func (a *Agent) containerItems(ctx context.Context) ([]svItem, error) {
	cts, err := a.containers(ctx)
	if err != nil {
		return nil, err
	}
	return containerItemsOf(cts), nil
}

// containerItemsOf is cts as hub items, in the same order.
func containerItemsOf(cts []dockermon.Container) []svItem {
	items := make([]svItem, 0, len(cts))
	for _, ct := range cts {
		it := svItem{kind: svDocker, name: ct.Name, label: ct.Name, status: ct.State}
		if len(ct.ID) >= shortIDLen && isHex(ct.ID) {
			it.id = ct.ID[:shortIDLen]
		}
		switch ct.State {
		case "running":
			it.state, it.status = services.StateOK, "up"
		case "restarting", "paused":
			it.state = services.StateDegraded
		default:
			it.state = services.StateDown
			if m := exitedRE.FindStringSubmatch(ct.Status); m != nil {
				it.status = "exited(" + m[1] + ")"
			}
		}
		items = append(items, it)
	}
	return items
}

// containerScreen is one container's detail (§3.4): the containers are
// listed again and this one found by its short ID; only then is it
// inspected, and its usage read while it runs.
func (a *Agent) containerScreen(ctx context.Context, c tgui.Call) tgui.View {
	cts, err := a.containers(ctx)
	if err != nil {
		return tgui.View{Text: "🐳 " + esc(err.Error())}
	}
	items := containerItemsOf(cts)
	i := find(items, c)
	if i < 0 {
		return gone(kindDocker, kindDocker.title, items)
	}
	ct := cts[i]
	text := fmt.Sprintf("🐳 <b>%s</b> · %s\n", esc(ct.Name), items[i].id)
	copyID := [][]tgui.Button{{{Label: "📋 Copy ID", Copy: ct.ID}}}
	in, err := a.src.Docker.Inspect(ctx, ct.ID)
	if err != nil {
		rows := append(bot.KV("Image", ct.Image), bot.KV("State", ct.Status)...)
		return tgui.View{Text: text + pre(rows) + "\nCould not inspect: " + esc(clipErr(err)), Rows: copyID}
	}
	state := in.State
	switch {
	case in.State == "running" && !in.StartedAt.IsZero():
		state += " · " + bot.Age(a.now().Sub(in.StartedAt))
	case in.State == "exited":
		state += fmt.Sprintf(" (%d)", in.ExitCode)
		if !in.FinishedAt.IsZero() {
			state += " · " + bot.Age(a.now().Sub(in.FinishedAt))
		}
	}
	rows := append(bot.KV("Image", cmp.Or(in.Image, ct.Image)), bot.KV("State", state)...)
	if in.Health != "" {
		rows = append(rows, bot.KV("Health", in.Health)...)
	}
	rows = append(rows, bot.KV("Restarts", strconv.Itoa(in.RestartCount))...)
	cpu, mem := "", ""
	if in.State == "running" {
		usage := dockermon.Container{ID: ct.ID}
		if err := a.src.Docker.Stats(ctx, &usage); err == nil {
			cpu = fmt.Sprintf("%.1f%%", usage.CPUPercent)
			if usage.MemLimit > 0 {
				mem = bot.BytesShort(usage.MemUsage) + " / " + bot.BytesShort(usage.MemLimit)
			}
		}
	}
	rows = append(rows, bot.KV("CPU", cpu)...)
	rows = append(rows, bot.KV("Memory", mem)...)
	return tgui.View{Text: text + pre(rows), Rows: copyID}
}

// ---- checks ----

// httpItems runs the watched HTTP checks.
func (a *Agent) httpItems(ctx context.Context) ([]svItem, error) {
	checks := a.watchCopy().HTTPChecks
	specs := make([]services.HTTPSpec, len(checks))
	for i, h := range checks {
		specs[i] = services.HTTPSpec{URL: h.URL, ExpectStatus: h.ExpectStatus, Timeout: h.Timeout.Duration}
	}
	var items []svItem
	for _, r := range services.CheckHTTP(ctx, httpClient, specs) {
		label := strings.TrimPrefix(strings.TrimPrefix(r.Name, "https://"), "http://")
		items = append(items, svItem{kind: watchHTTP, name: r.Name, label: label, state: r.State, status: r.Detail, watched: true})
	}
	return items, nil
}

// certItems checks the watched certificates, failed checks first, then
// soonest expiry.
func (a *Agent) certItems(ctx context.Context) ([]svItem, error) {
	hosts := a.watchCopy().SSLHosts
	if len(hosts) == 0 {
		return nil, nil // the list says how to add one
	}
	if a.src.CheckCerts == nil {
		return nil, errors.New("Certificate checks are not available in this build.")
	}
	sts := a.src.CheckCerts(ctx, hosts)
	slices.SortStableFunc(sts, func(x, y netcheck.CertStatus) int {
		if (x.Err != "") != (y.Err != "") {
			if x.Err != "" {
				return -1
			}
			return 1
		}
		return cmp.Compare(x.DaysLeft, y.DaysLeft)
	})
	var items []svItem
	for _, st := range sts {
		it := svItem{kind: watchCert, name: st.Host, label: st.Host, status: bot.CertLeft(st), watched: true}
		switch {
		case st.Err != "", st.DaysLeft <= 3:
			it.state = services.StateDown
		case st.DaysLeft <= 21:
			it.state = services.StateDegraded
		}
		items = append(items, it)
	}
	return items, nil
}

// portItems checks that each watched port accepts a connection.
func (a *Agent) portItems(ctx context.Context) ([]svItem, error) {
	var items []svItem
	for _, p := range a.watchCopy().Ports {
		r := services.CheckPorts(ctx, defaultDialer(), []services.PortSpec{{Port: p.Port}})[0]
		it := svItem{kind: watchPort, name: strconv.Itoa(p.Port), label: fmt.Sprintf("%-5d %s", p.Port, p.Label),
			state: r.State, status: "listening", watched: true}
		if r.State != services.StateOK {
			it.status = "closed"
		}
		items = append(items, it)
	}
	return items, nil
}

// procItems checks that each watched process runs.
func (a *Agent) procItems(context.Context) ([]svItem, error) {
	names := a.watchCopy().Processes
	if len(names) == 0 {
		return nil, nil
	}
	if a.src.ProcFS == nil {
		return nil, errors.New("Process checks are not available in this build.")
	}
	results, err := a.src.ProcFS(names)
	if err != nil {
		return nil, fmt.Errorf("Could not read processes: %w", err)
	}
	var items []svItem
	for _, r := range results {
		items = append(items, svItem{kind: watchProc, name: r.Name, label: r.Name, state: r.State, status: r.Detail, watched: true})
	}
	return items, nil
}
