package agent

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"

	"github.com/eliau2005/statixagent/internal/bot"
	"github.com/eliau2005/statixagent/internal/telegram"
	"github.com/eliau2005/statixagent/internal/tgui"
)

// ufw management screens (docs/telegram-ux-redesign.md §3.8): the rule
// list and detail, Open port and the presets, Restore previous, and the
// typed /fw_open, /fw_allow and /fw_deny. They only read; every change
// they offer becomes a plan (fwplan.go) behind a confirm token, which
// runs under the dead-man switch.

// Screen IDs of the firewall screens under 🛡.
const (
	scrFwRules   = "fl"
	scrFwRule    = "fr"
	scrFwAdd     = "fa"
	scrFwPresets = "fp"
	scrFwDB      = "fd"
	scrFwRestore = "fh"
)

// Ask acts that plan a firewall change, and the confirm screen's Show
// commands toggle. None of them changes anything.
const (
	askFwDelete  = "frd" // frd|<rule ID>
	askFwPreset  = "fps" // fps|web, fps|ssh
	askFwRestore = "frs" // frs|<snapshot ID>
	askFwCmds    = "fx"  // fx|<plan ID>, fx|<plan ID>|h to hide
)

// actFwPlan is a planned rule change, as the audit log records it.
const actFwPlan = "fw_plan"

// fwNow is one fresh reading of ufw: the probe, the user rule specs, and
// whether ufw keeps IPv6 rules.
type fwNow struct {
	p     ufwProbe
	added [][]string
	v6    bool
}

// readFw reads ufw for a screen or a plan; the string is why it cannot
// (HTML), or "".
func (a *Agent) readFw(ctx context.Context) (fwNow, string) {
	if a.src.Runner == nil {
		return fwNow{}, "Firewall control unavailable in this build."
	}
	b := a.fwBackend("")
	p := b.Probe(ctx)
	if f := probeRefusal(p); f != nil {
		return fwNow{}, esc(f.display())
	}
	added, t := b.added(ctx)
	if t != nil {
		return fwNow{}, "Could not list the rules:\n" + preBlock(detail(t.out, t.err))
	}
	return fwNow{p: p, added: added, v6: a.ufwIPv6()}, ""
}

// ufwIPv6 reports whether ufw keeps IPv6 rules: IPV6= in
// /etc/default/ufw, which sits beside the rules directory /etc/ufw.
// Unknown counts as yes, ufw's own default.
func (a *Agent) ufwIPv6() bool {
	if a.src.UFWDir == "" {
		return true
	}
	data, err := os.ReadFile(filepath.Join(filepath.Dir(a.src.UFWDir), "default", "ufw"))
	if err != nil {
		return true
	}
	return parseUFWIPv6(string(data))
}

// parseUFWIPv6 reads the IPV6= setting of /etc/default/ufw.
func parseUFWIPv6(text string) bool {
	on := true
	for _, line := range strings.Split(text, "\n") {
		if v, ok := strings.CutPrefix(strings.TrimSpace(line), "IPV6="); ok {
			on = !strings.EqualFold(strings.Trim(strings.TrimSpace(v), `"'`), "no")
		}
	}
	return on
}

// adminPeers are the hosts of current SSH logins: established
// connections to an SSH port, and the sessions' hosts. The guard keeps
// SSH open for every one of them. Loopback peers (a tunnel) never pass
// ufw's rules.
func (a *Agent) adminPeers(ctx context.Context, ports []int) []netip.Addr {
	var peers []netip.Addr
	if a.src.Runner != nil {
		for _, c := range a.sshConns(ctx, ports) {
			peers = append(peers, c.peer.Addr())
		}
	}
	if a.src.Sessions != nil {
		if ss, err := a.src.Sessions(); err == nil {
			for _, s := range ss {
				if p, err := netip.ParseAddr(s.Host); err == nil && p.Zone() == "" {
					peers = append(peers, p.Unmap())
				}
			}
		}
	}
	peers = slices.DeleteFunc(peers, func(p netip.Addr) bool { return p.IsLoopback() || !p.IsValid() })
	slices.SortFunc(peers, func(x, y netip.Addr) int { return x.Compare(y) })
	return slices.Compact(peers)
}

// trustedHosts are the single-address trusted sources: the guard warns,
// but does not refuse, when a change would block one of them.
func (a *Agent) trustedHosts(peers []netip.Addr) []netip.Addr {
	var hosts []netip.Addr
	for _, p := range append(slices.Clone(a.configTrusted), a.trustStore.Entries()...) {
		if p.IsSingleIP() && !slices.Contains(peers, p.Addr()) && !slices.Contains(hosts, p.Addr()) {
			hosts = append(hosts, p.Addr())
		}
	}
	return hosts
}

// fwNavRow is the row of a firewall screen that is not a registered
// screen (a refusal, a typed reply): Back to 🛡 and Home.
func fwNavRow() []tgui.Button {
	return []tgui.Button{{Label: "⬅️ Back", Call: tgui.Open(scrFirewall)}, {Label: "🏠 Home", Call: tgui.Open(scrHome)}}
}

// refusalView is the ⛔ screen of a change the guard refuses (§3.8).
func refusalView(reason string) tgui.View {
	return tgui.View{Text: "⛔ <b>Refused</b>\n" + esc(reason) + "\nMake this change from a shell.",
		Rows: [][]tgui.Button{fwNavRow()}}
}

// ---- screens ----

// ruleLine is one rule in the list, 32 columns:
// "4 5432/tcp   ALLOW 10.0.0.0/8".
func ruleLine(r fwRule) string {
	from := prefixArg(r.From)
	if !r.From.IsValid() {
		from = "Anywhere"
		if r.V6 {
			from = "Anywhere v6"
		}
	}
	if r.Dir != "in" {
		from = r.Dir + " " + from
	}
	return bot.Clip(fmt.Sprintf("%2d %s %s %s", r.Num, bot.Pad(portLabel(r), 10), bot.Pad(strings.ToUpper(r.Action), 5), from), bot.PreCols)
}

// fwRulesScreen is 📋 Rules: every ufw rule in order, paged, each with a
// button naming it by its spec digest and the list's generation.
func (a *Agent) fwRulesScreen(ctx context.Context, c tgui.Call) tgui.View {
	n, why := a.readFw(ctx)
	if why != "" {
		return tgui.View{Text: "📋 <b>Rules</b>\n" + why}
	}
	return rulesList(n, c, "")
}

func rulesList(n fwNow, c tgui.Call, banner string) tgui.View {
	rules := n.p.fw.rules
	page, pages := pageOf(c, len(rules))
	head := fmt.Sprintf("📋 <b>Rules</b> · page %d/%d", page, pages)
	if banner != "" {
		head = banner + "\n" + head
	}
	if len(rules) == 0 {
		return tgui.View{Text: head + "\nNo rules: the default policy decides everything.\nOpen a port: <code>/fw_open 8080/tcp</code>"}
	}
	specs := rowSpecs(n.p.fw, n.added)
	gen := fwGen(n.p.fw)[:6]
	var lines []string
	var btns []tgui.Button
	for i, r := range pageSlice(rules, page) {
		lines = append(lines, ruleLine(r))
		btns = append(btns, tgui.Button{Label: "#" + strconv.Itoa(r.Num),
			Call: tgui.Call{Act: tgui.ActView, Args: []string{scrFwRule, gen, ruleID(r, specs[(page-1)*pageSize+i])}, From: scrFwRules}})
	}
	return tgui.View{Text: head + "\n" + pre(lines) + "\nTap a rule for details.",
		Rows: append(buttonRows(btns, 4), pageRow(scrFwRules, c, page, pages))}
}

// peersMatching counts the peers whose SSH connections row matches.
func peersMatching(row fwRule, ports []int, peers []netip.Addr) int {
	n := 0
	for _, p := range peers {
		if row.Dir != "in" || row.V6 != p.Is6() || (row.Proto != "" && row.Proto != "tcp") ||
			(row.From.IsValid() && !row.From.Contains(p)) {
			continue
		}
		if slices.ContainsFunc(ports, row.coversPort) || row.unresolved {
			n++
		}
	}
	return n
}

// fwRuleScreen is one rule (§3.8): what it matches, its canonical spec,
// how many current SSH peers it matches, and Delete. Its call names the
// rule by ID; a rule no longer listed shows the list instead.
func (a *Agent) fwRuleScreen(ctx context.Context, c tgui.Call) tgui.View {
	n, why := a.readFw(ctx)
	if why != "" {
		return tgui.View{Text: "📋 <b>Rule</b>\n" + why}
	}
	specs := rowSpecs(n.p.fw, n.added)
	i := -1
	if len(c.Args) == 3 {
		i = slices.IndexFunc(n.p.fw.rules, func(r fwRule) bool { return ruleID(r, specs[r.Num-1]) == c.Args[2] })
	}
	if i < 0 {
		return rulesList(n, tgui.Open(scrFwRules), itemGoneBanner)
	}
	row, spec := n.p.fw.rules[i], specs[i]
	fam := "v4"
	if row.V6 {
		fam = "v6"
	}
	rows := bot.KV("Action", strings.ToUpper(row.Action)+" "+row.Dir)
	rows = append(rows, bot.KV("Port", portLabel(row))...)
	rows = append(rows, bot.KV("From", fromLabel(row))...)
	if row.Dst.IsValid() {
		rows = append(rows, bot.KV("To", prefixArg(row.Dst))...)
	}
	if row.Iface != "" {
		rows = append(rows, bot.KV("On", row.Iface)...)
	}
	rows = append(rows, bot.KV("Family", fam)...)
	text := fmt.Sprintf("📋 <b>Rule #%d</b>\n", row.Num) + pre(rows)
	if c.Args[1] != fwGen(n.p.fw)[:6] {
		text = "ℹ️ The rules changed since that list.\n" + text
	}
	if spec != nil {
		text += "\nSpec: <code>ufw " + esc(specText(spec)) + "</code>"
	}
	ports := a.sshPorts(ctx)
	text += "\n" + fmt.Sprintf("Matches %s.", plural(peersMatching(row, ports, a.adminPeers(ctx, ports)), "current SSH peer"))
	switch {
	case row.Dir != "in":
		return tgui.View{Text: text + "\nOutgoing rules are changed from a shell only."}
	case spec == nil:
		return tgui.View{Text: text + "\n<code>ufw show added</code> does not list this rule, so it is deleted from a shell only."}
	}
	return tgui.View{Text: text, Rows: [][]tgui.Button{{{Label: "🗑 Delete rule", Call: tgui.Call{Act: askFwDelete, Args: []string{c.Args[2]}}, Style: "danger"}}}}
}

// presetRows are the preset buttons; from is the screen showing them.
func presetRows(from string) [][]tgui.Button {
	db := func(label, arg string) tgui.Button {
		return tgui.Button{Label: label, Call: tgui.Call{Act: tgui.ActView, Args: []string{scrFwDB, arg}, From: from}}
	}
	return [][]tgui.Button{
		{{Label: "🌍 Web 80+443", Call: tgui.Call{Act: askFwPreset, Args: []string{"web"}}},
			{Label: "🔐 SSH (limit)", Call: tgui.Call{Act: askFwPreset, Args: []string{"ssh"}}}},
		{db("🗄 Postgres from…", "pg"), db("🗄 Redis from…", "rd")},
	}
}

// fwAddScreen is ➕ Open a port: the typed commands, and the presets.
func (a *Agent) fwAddScreen(context.Context, tgui.Call) tgui.View {
	return tgui.View{Text: "➕ <b>Open a port</b>\nPick a preset, or send:\n" +
		"<code>/fw_open 8080/tcp</code>\n<code>/fw_allow 10.0.0.0/8 5432/tcp</code>\n<code>/fw_deny 198.51.100.7</code>\n" +
		"Every change runs as a trial: the old rules return unless you tap Keep.",
		Rows: presetRows(scrFwAdd)}
}

// fwPresetsScreen is 🧱 Presets.
func (a *Agent) fwPresetsScreen(context.Context, tgui.Call) tgui.View {
	return tgui.View{Text: "🧱 <b>Presets</b>\n" +
		"🌍 Web: allow 80/tcp and 443/tcp from Anywhere\n" +
		"🔐 SSH (limit): rate-limit new connections to the SSH port\n" +
		"🗄 Postgres and Redis: only from a source you name, never from Anywhere",
		Rows: presetRows(scrFwPresets)}
}

// fwDBScreen explains a database preset: it needs a source, so it is a
// typed command.
func (a *Agent) fwDBScreen(_ context.Context, c tgui.Call) tgui.View {
	dbs := []struct{ arg, name, port string }{{"pg", "Postgres", "5432"}, {"rd", "Redis", "6379"}}
	var parts []string
	for _, d := range dbs {
		if len(c.Args) > 1 && c.Args[1] != d.arg {
			continue
		}
		parts = append(parts, "🗄 <b>"+d.name+"</b> ("+d.port+"/tcp) is never opened to Anywhere. Send the network to allow, for example:\n"+
			"<code>/fw_allow 10.0.0.0/8 "+d.port+"/tcp</code>")
	}
	if len(parts) == 0 {
		return a.fwDBScreen(context.Background(), tgui.Open(scrFwDB))
	}
	return tgui.View{Text: strings.Join(parts, "\n\n")}
}

// restoreChoices are the snapshots Restore previous offers: the newest
// fwKeepSnaps, not the pending trial's own.
func (a *Agent) restoreChoices() []fwSnapInfo {
	if !a.fwReady() {
		return nil
	}
	pending, _, _ := loadTrial(a.src.FwDir)
	snaps := slices.DeleteFunc(a.listSnapshots(), func(s fwSnapInfo) bool { return s.id == pending.ID })
	return snaps[:min(len(snaps), fwKeepSnaps)]
}

// fwRestoreScreen is ↩️ Restore previous: the rules as they were before
// each recent change.
func (a *Agent) fwRestoreScreen(context.Context, tgui.Call) tgui.View {
	head := "↩️ <b>Restore previous</b>\n"
	if !a.fwReady() {
		return tgui.View{Text: head + "Snapshots are not set up in this build."}
	}
	snaps := a.restoreChoices()
	if len(snaps) == 0 {
		return tgui.View{Text: head + "No snapshots yet. One is taken before every firewall change."}
	}
	var lines []string
	var btns []tgui.Button
	for i, s := range snaps {
		count := "?"
		if snap, err := loadSnap(filepath.Join(a.src.FwDir, s.id)); err == nil {
			count = strconv.Itoa(len(parseUFWOutput(snap.Status).rules))
		}
		at := s.at.UTC().Format("15:04")
		lines = append(lines, fmt.Sprintf("%d %s UTC %4s ago %s rules", i+1, at, bot.Age(a.now().Sub(s.at)), count))
		btns = append(btns, tgui.Button{Label: fmt.Sprintf("↩️ %d · %s", i+1, at), Call: tgui.Call{Act: askFwRestore, Args: []string{s.id}}})
	}
	return tgui.View{Text: head + "The rules as they were before each recent change, newest first:\n" + pre(lines) +
		"\nRestoring one runs as a trial, with the SSH check.", Rows: buttonRows(btns, 3)}
}

// ---- plans ----

// fwBuilt is a plan built from a fresh reading.
type fwBuilt struct {
	title   string
	plan    fwPlan
	restore string
	after   ufwStatus
}

// errRefuse is a change refused outright: the ⛔ screen, no confirm.
type errRefuse string

func (e errRefuse) Error() string { return string(e) }

// planFor builds a plan from a fresh reading, guards it and, if it may
// run, keeps it under a confirm token bound to actor, chat and message
// (0 for a typed command's reply, which binds it once sent). The view is
// the confirm screen, a refusal, or why nothing was planned.
func (a *Agent) planFor(ctx context.Context, actor, chat, msg int64, build func(fwNow) (fwBuilt, error)) tgui.View {
	note := func(text string) tgui.View { return tgui.View{Text: text, Rows: [][]tgui.Button{fwNavRow()}} }
	n, why := a.readFw(ctx)
	switch {
	case why != "":
		return note("🛡 " + why)
	case !a.fwReady():
		return note("🛡 The firewall rollback switch is not set up in this build, so the agent will not change rules.")
	case a.FwTrialPending():
		return note("⏳ Another firewall change is on trial. Keep it or roll it back first.")
	}
	built, err := build(n)
	var refuse errRefuse
	switch {
	case errors.As(err, &refuse):
		a.writeAudit(auditRecord{Phase: phaseDenied, Action: actFwPlan, Target: built.title, ActorID: actor, ChatID: chat, MessageID: msg})
		return refusalView(string(refuse))
	case err != nil:
		return note("⚠️ " + esc(upperFirst(err.Error())))
	}
	ports := a.sshPorts(ctx)
	peers := a.adminPeers(ctx, ports)
	if reason := sshGuard(n.p.fw, built.after, ports, peers); reason != "" {
		a.writeAudit(auditRecord{Phase: phaseDenied, Action: actFwPlan, Target: built.title, ActorID: actor, ChatID: chat, MessageID: msg})
		return refusalView(reason)
	}
	id, err := newFwID()
	if err != nil {
		log.Printf("agent: %v", err)
		return note(mintFailedToast)
	}
	req := &fwPlanReq{id: id, title: built.title, plan: built.plan, restore: built.restore, base: fwGen(n.p.fw),
		after: built.after, diff: diffRows(n.p.fw, built.after), actor: actor, expires: a.now().Add(fwPlanTTL)}
	req.check = sshCheck(n.p.fw, built.after, ports, peers, a.trustedHosts(peers))
	in := tgui.Intent{Action: actFwPlan, Target: id, ActorID: actor, ChatID: chat, MessageID: msg}
	if req.nonce, err = a.mintTokenTTL(in, fwPlanTTL); err != nil {
		log.Printf("agent: %v", err)
		return note(mintFailedToast)
	}
	a.fwPlans.put(req, a.now())
	return a.planView(req, false)
}

// sshCheck is the confirm screen's SSH line: the guard passed, and for
// whom; a trusted source the change would block is a warning.
func sshCheck(before, after ufwStatus, ports []int, peers, trusted []netip.Addr) string {
	var names []string
	for _, p := range ports {
		names = append(names, strconv.Itoa(p)+"/tcp")
	}
	open := strings.Join(names, ", ")
	var s string
	switch {
	case len(peers) > 2:
		s = fmt.Sprintf("SSH check: ✅ %s still open for %s, %s and %d more", open, peers[0], peers[1], len(peers)-2)
	case len(peers) > 0:
		var ps []string
		for _, p := range peers {
			ps = append(ps, p.String())
		}
		s = "SSH check: ✅ " + open + " still open for " + strings.Join(ps, " and ")
	default:
		s = "SSH check: ✅ no current SSH session is affected"
	}
	for _, t := range trusted {
		if sshGuard(before, after, ports, []netip.Addr{t}) != "" {
			s += "\n⚠️ Trusted source " + t.String() + " would lose SSH."
		}
	}
	return esc(s)
}

// trialLabel is the trial window in a button: "2 min", "90 s".
func trialLabel(n int) string {
	if n%60 == 0 {
		return strconv.Itoa(n/60) + " min"
	}
	return strconv.Itoa(n) + " s"
}

// planView is a plan's confirm screen (§3.8): the exact diff, the trial
// window and the SSH check; cmds also reveals the exact commands.
func (a *Agent) planView(req *fwPlanReq, cmds bool) tgui.View {
	n := a.trialWindow()
	text := "⚠️ <b>Apply firewall change?</b>\n" + esc(req.title) + "\n" +
		"Trial: auto-rollback in " + mmss(n) + " unless you tap Keep.\n" + pre(req.diff) + "\n" + req.check
	toggle := tgui.Button{Label: "🔍 Show commands", Call: tgui.Call{Act: askFwCmds, Args: []string{req.id}}}
	if cmds {
		text += "\nCommands:\n" + pre(a.planCommands(req))
		toggle = tgui.Button{Label: "🔍 Hide commands", Call: tgui.Call{Act: askFwCmds, Args: []string{req.id, "h"}}}
	}
	yes := "✅ Apply (" + trialLabel(int(n.Seconds())) + " trial)"
	return tgui.View{Text: text, Rows: [][]tgui.Button{a.confirmRow(yes, req.nonce), {toggle}}}
}

// planCommands is what Apply runs, exactly.
func (a *Agent) planCommands(req *fwPlanReq) []string {
	var lines []string
	if req.restore != "" {
		lines = append(lines, "from snapshot "+req.restore+":")
		for _, f := range ufwRuleFiles {
			lines = append(lines, "write "+filepath.Join(a.src.UFWDir, f))
		}
	} else {
		for _, c := range req.plan {
			lines = append(lines, "ufw "+specText(c.argv()))
		}
	}
	return append(lines, "ufw reload")
}

// showPlan edits a plan's view into the pressed message; a token that
// ends up in a new message follows it there.
func (a *Agent) showPlan(ctx context.Context, cb *telegram.Callback, v tgui.View) {
	text, kb := encodeView(v)
	if id := a.finishCallback(ctx, cb, false, text, kb, ""); id != cb.MessageID && id != 0 {
		if nonce := confirmNonce(v); nonce != "" {
			a.tokens.Rebind(nonce, id)
		}
	}
}

// specsBuild plans adding specs.
func specsBuild(title string, specs ...fwSpec) func(fwNow) (fwBuilt, error) {
	return func(n fwNow) (fwBuilt, error) {
		plan, err := planSpecs(n.added, n.p.fw, specs, n.v6)
		if err != nil {
			return fwBuilt{title: title}, err
		}
		return fwBuilt{title: title, plan: plan, after: simulate(n.p.fw, plan, n.v6)}, nil
	}
}

// deleteBuild plans deleting the rule id names, by its spec.
func deleteBuild(id string) func(fwNow) (fwBuilt, error) {
	return func(n fwNow) (fwBuilt, error) {
		specs := rowSpecs(n.p.fw, n.added)
		i := slices.IndexFunc(n.p.fw.rules, func(r fwRule) bool { return ruleID(r, specs[r.Num-1]) == id })
		if i < 0 {
			return fwBuilt{}, errUsage("this rule is gone; the list changed. Open 📋 Rules again.")
		}
		row, spec := n.p.fw.rules[i], specs[i]
		title := "Delete rule " + strconv.Itoa(row.Num) + ": " + actionLabel(row) + " " + portLabel(row) + " from " + fromLabel(row)
		switch {
		case row.Dir != "in":
			return fwBuilt{title: title}, errRefuse("Outgoing rules are not changed from the bot.")
		case spec == nil:
			return fwBuilt{title: title}, errUsage("ufw show added does not list this rule, so it is deleted from a shell only.")
		}
		if _, _, ok := specRule(spec); !ok {
			return fwBuilt{title: title}, errUsage("the agent cannot read this rule's spec, so it is deleted from a shell only.")
		}
		plan := fwPlan{{Op: opDelete, Spec: spec}}
		return fwBuilt{title: title, plan: plan, after: simulate(n.p.fw, plan, n.v6)}, nil
	}
}

// restoreBuild plans restoring snapshot id.
func (a *Agent) restoreBuild(id string) func(fwNow) (fwBuilt, error) {
	return func(n fwNow) (fwBuilt, error) {
		i := slices.IndexFunc(a.restoreChoices(), func(s fwSnapInfo) bool { return s.id == id })
		if i < 0 {
			return fwBuilt{}, errUsage("this snapshot is gone. Open ↩️ Restore previous again.")
		}
		snap, err := loadSnap(filepath.Join(a.src.FwDir, id))
		title := "Restore the rules of snapshot " + id
		after := parseUFWOutput(snap.Status)
		switch {
		case err != nil:
			return fwBuilt{title: title}, errUsage("the snapshot could not be read: " + err.Error())
		case !after.active:
			return fwBuilt{title: title}, errUsage("the snapshot's rule listing could not be read.")
		case snap.Added == nil:
			return fwBuilt{title: title}, errUsage("this snapshot was taken by an older version; it serves only for rollback.")
		case fwGen(after) == fwGen(n.p.fw):
			return fwBuilt{title: title}, errUsage("the rules are already as in this snapshot.")
		}
		after.policy = n.p.fw.policy // only the rules are restored
		return fwBuilt{title: title, plan: restorePlan(n.added, snap.Added), restore: id, after: after}, nil
	}
}

// parseFwCommand reads /fw_open, /fw_allow or /fw_deny into the rule it
// adds and a title for it.
func parseFwCommand(cmd string, args []string, v6ok bool) (fwSpec, string, error) {
	usage := map[string]string{
		"fw_open":  "usage: /fw_open port[/tcp|udp], e.g. /fw_open 8080/tcp",
		"fw_allow": "usage: /fw_allow ip-or-cidr port[/tcp|udp], e.g. /fw_allow 10.0.0.0/8 5432/tcp",
		"fw_deny":  "usage: /fw_deny ip-or-cidr [port[/tcp|udp]], e.g. /fw_deny 198.51.100.7",
	}[cmd]
	var s fwSpec
	switch {
	case cmd == "fw_open" && len(args) == 1:
		r, proto, err := parsePortArg(args[0])
		if err != nil {
			return s, "", err
		}
		s = fwSpec{Action: "allow", Ports: r, Proto: proto}
		if port, db := dbPort(r); db != "" {
			return s, "", errUsage(fmt.Sprintf("%s is never opened to Anywhere. Name who may connect: /fw_allow <cidr> %d/tcp", db, port))
		}
		return s, "Open " + portLabel(fwRule{Ports: []portRange{r}, Proto: proto}), nil
	case cmd == "fw_allow" && len(args) == 2, cmd == "fw_deny" && (len(args) == 1 || len(args) == 2):
		from, err := parseSourceArg(args[0], v6ok)
		if err != nil {
			return s, "", err
		}
		s = fwSpec{Action: "allow", From: from}
		if cmd == "fw_deny" {
			s.Action = "deny"
		}
		if len(args) == 2 {
			if s.Ports, s.Proto, err = parsePortArg(args[1]); err != nil {
				return s, "", err
			}
		}
		what := "all ports"
		if s.Ports.Lo != 0 {
			what = portLabel(fwRule{Ports: []portRange{s.Ports}, Proto: s.Proto})
		}
		return s, upperFirst(s.Action) + " " + what + " from " + prefixArg(from), nil
	}
	return s, "", errUsage(usage)
}

// fwCommand is the handler of /fw_open, /fw_allow and /fw_deny: it
// replies with the plan's confirm screen, bound to the sender.
func (a *Agent) fwCommand(cmd string) func(ctx context.Context, args []string) tgui.View {
	return func(ctx context.Context, args []string) tgui.View {
		spec, title, err := parseFwCommand(cmd, args, a.ufwIPv6())
		if err != nil {
			return tgui.View{Text: "⚠️ " + esc(upperFirst(err.Error()))}
		}
		return a.planFor(ctx, actorFrom(ctx), a.cfg.Telegram.ChatID, 0, specsBuild(title, spec))
	}
}

// fwPlanAsks are the ask acts that plan a change from a button.
func (a *Agent) fwPlanAsks() map[string]askAction {
	plan := func(build func(c tgui.Call) (func(fwNow) (fwBuilt, error), bool)) func(context.Context, *telegram.Callback, tgui.Call) {
		return func(ctx context.Context, cb *telegram.Callback, c tgui.Call) {
			b, ok := build(c)
			if !ok {
				a.refuseCallback(ctx, cb, false)
				return
			}
			a.showPlan(ctx, cb, a.planFor(ctx, cb.FromID, cb.ChatID, cb.MessageID, b))
		}
	}
	return map[string]askAction{
		askFwDelete: {class: tgui.ClassMutate, press: plan(func(c tgui.Call) (func(fwNow) (fwBuilt, error), bool) {
			if len(c.Args) != 1 || len(c.Args[0]) != fingerprint || !isHex(c.Args[0]) {
				return nil, false
			}
			return deleteBuild(c.Args[0]), true
		})},
		askFwPreset: {class: tgui.ClassMutate, press: func(ctx context.Context, cb *telegram.Callback, c tgui.Call) {
			if len(c.Args) != 1 || (c.Args[0] != "web" && c.Args[0] != "ssh") {
				a.refuseCallback(ctx, cb, false)
				return
			}
			b := specsBuild("Web: allow 80/tcp and 443/tcp", fwSpec{Action: "allow", Ports: portRange{80, 80}, Proto: "tcp"},
				fwSpec{Action: "allow", Ports: portRange{443, 443}, Proto: "tcp"})
			if c.Args[0] == "ssh" {
				var specs []fwSpec
				var names []string
				for _, p := range a.sshPorts(ctx) {
					specs = append(specs, fwSpec{Action: "limit", Ports: portRange{p, p}, Proto: "tcp"})
					names = append(names, strconv.Itoa(p)+"/tcp")
				}
				b = specsBuild("SSH: limit "+strings.Join(names, ", "), specs...)
			}
			a.showPlan(ctx, cb, a.planFor(ctx, cb.FromID, cb.ChatID, cb.MessageID, b))
		}},
		askFwRestore: {class: tgui.ClassMutate, press: plan(func(c tgui.Call) (func(fwNow) (fwBuilt, error), bool) {
			if len(c.Args) != 1 || !fwIDPattern.MatchString(c.Args[0]) {
				return nil, false
			}
			return a.restoreBuild(c.Args[0]), true
		})},
		askFwCmds: {class: tgui.ClassMutate, press: a.planCmdsPress},
	}
}

// planCmdsPress shows or hides a plan's exact commands, keeping its Yes.
func (a *Agent) planCmdsPress(ctx context.Context, cb *telegram.Callback, c tgui.Call) {
	if len(c.Args) < 1 || len(c.Args) > 2 || !fwIDPattern.MatchString(c.Args[0]) || (len(c.Args) == 2 && c.Args[1] != "h") {
		a.refuseCallback(ctx, cb, false)
		return
	}
	req, ok := a.fwPlans.get(c.Args[0], a.now())
	switch {
	case !ok:
		text, kb := encodeView(tgui.View{Text: staleText, Rows: [][]tgui.Button{fwNavRow()}})
		a.finishCallback(ctx, cb, false, text, kb, staleToast)
		return
	case req.actor != cb.FromID:
		a.answer(ctx, cb, wrongActorToast)
		return
	}
	a.showPlan(ctx, cb, a.planView(req, len(c.Args) == 1))
}

// planAction runs a plan its confirm token names, under the dead-man
// switch: the rules must be the ones it was made against, and the guard
// runs again on a fresh reading and fresh SSH peers.
func (a *Agent) planAction() confirmAction {
	return confirmAction{
		back: scrFirewall, backLabel: "🛡 Firewall",
		prompt: func(ctx context.Context, _ string, _ bool) confirmPrompt {
			text, kb := a.firewallView(ctx)
			return confirmPrompt{text: text, kb: kb}
		},
		run:    a.runPlan,
		cancel: a.firewallView,
	}
}

// runPlan runs plan id under a trial.
func (a *Agent) runPlan(ctx context.Context, id string) actionResult {
	req, ok := a.fwPlans.take(id, a.now())
	if !ok {
		return actionResult{drift: true, driftToast: "This change has expired",
			text: "⌛ This planned change has expired. Plan it again.", kb: fwBackKB()}
	}
	job := fwJob{action: actFwPlan, target: req.title, what: req.title,
		prepare: func(ctx context.Context, b *ufwBackend, p ufwProbe) fwPrep {
			if fwGen(p.fw) != req.base {
				return fwPrep{refused: &actionResult{drift: true, driftToast: "The rules changed",
					text: "⚠️ The rules changed since this change was planned, so nothing was changed. Plan it again.", kb: fwBackKB()}}
			}
			after := req.after
			if req.restore == "" {
				after = simulate(p.fw, req.plan, a.ufwIPv6())
			} else if _, err := loadSnap(filepath.Join(a.src.FwDir, req.restore)); err != nil {
				return fwPrep{fail: &fwFailure{reason: "the snapshot could not be read, so nothing was changed: " + err.Error()}}
			}
			ports := a.sshPorts(ctx)
			if why := sshGuard(p.fw, after, ports, a.adminPeers(ctx, ports)); why != "" {
				text, kb := encodeView(refusalView(why))
				return fwPrep{refused: &actionResult{refused: true, driftToast: "Refused", text: text, kb: kb}}
			}
			return fwPrep{plan: req.plan}
		},
		verify: func(ctx context.Context, before, after ufwProbe) *fwFailure {
			if !after.manageable() {
				return &fwFailure{reason: "ufw accepted the change, but the agent could not read the rules back"}
			}
			ports := a.sshPorts(ctx)
			if why := sshGuard(before.fw, after.fw, ports, a.adminPeers(ctx, ports)); why != "" {
				return &fwFailure{reason: "ufw applied the change, but the rules read back fail the SSH check: " + why}
			}
			return nil
		},
	}
	if req.restore != "" {
		job.apply = func(ctx context.Context, b *ufwBackend) (*cmdTrace, error) {
			snap, err := loadSnap(filepath.Join(a.src.FwDir, req.restore))
			if err != nil {
				return nil, err
			}
			return nil, b.Restore(ctx, snap)
		}
	}
	return a.runTrial(ctx, job)
}
