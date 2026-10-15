package agent

import (
	"context"
	"fmt"
	"strings"

	"github.com/eliau2005/statixagent/internal/bot"
	"github.com/eliau2005/statixagent/internal/services"
	"github.com/eliau2005/statixagent/internal/tgui"
)

// Which firewall this host runs (docs/telegram-ux-redesign.md §5.2,
// Decision 14b), and so what the agent may do with it. In order: an
// active ufw is managed; else a running firewalld is; else nftables or
// iptables rules are shown read-only, since they have no rule model a
// change could be simulated on; else there is no firewall manager. With
// ufw and firewalld both active, two managers write the same tables, so
// nothing is changed until one of them is stopped.

const (
	fwKindUFW      = "ufw"
	fwKindNft      = "nftables"
	fwKindIptables = "iptables"
)

var (
	nftPaths      = []string{"nft", "/usr/sbin/nft", "/sbin/nft"}
	iptablesPaths = []string{"iptables", "/usr/sbin/iptables", "/sbin/iptables"}
)

// fwReadOnlyRows is how many lines of a read-only ruleset are shown.
const fwReadOnlyRows = 20

// fwFound is what detection found.
type fwFound struct {
	kind string   // fwKindUFW, fwKindFirewalld, fwKindNft, fwKindIptables; "" for none
	ufw  ufwProbe // ufw's own probe, always taken
	// b is the backend the agent manages, and p its probe; nil for a
	// read-only firewall or none.
	b FwBackend
	p ufwProbe
	// conflict: ufw is active and firewalld runs too.
	conflict bool
	// listing is the read-only ruleset as nft or iptables printed it.
	listing string
}

// detectFw finds this host's firewall, in the order above.
func (a *Agent) detectFw(ctx context.Context) fwFound {
	run := a.src.Runner
	f := fwFound{ufw: a.probeUFW(ctx)}
	fwdBin, fwd := firewalldRunning(ctx, run)
	switch {
	case f.ufw.manageable():
		f.kind, f.b, f.p, f.conflict = fwKindUFW, a.fwBackend(f.ufw.bin), f.ufw, fwd
	case fwd:
		b := &firewalldBackend{run: run, bin: fwdBin}
		f.kind, f.b, f.p = fwKindFirewalld, b, b.Probe(ctx)
	default:
		if out, ok := runFirst(ctx, run, nftPaths, "list", "ruleset"); ok && nftCounts(out) != "" {
			f.kind, f.listing = fwKindNft, out
		} else if out, ok := runFirst(ctx, run, iptablesPaths, "-S"); ok && iptablesCounts(out) != "" {
			f.kind, f.listing = fwKindIptables, out
		}
	}
	return f
}

// runFirst runs the first of paths that exists; ok when it exited 0.
func runFirst(ctx context.Context, run services.Runner, paths []string, args ...string) (string, bool) {
	for _, bin := range paths {
		out, err := run.Run(ctx, bin, args...)
		if notFound(err) {
			continue
		}
		return out, err == nil
	}
	return "", false
}

// fwConflictText is why nothing changes while ufw and firewalld both run.
const fwConflictText = "ufw and firewalld are both active: two managers write the same tables, " +
	"so the agent changes nothing until one of them is stopped"

// refusal is why no rule change can run on what was found, nil when one
// can. A Telegram keyboard stays live on old messages, so the action
// path refuses on its own in every state the view offers no button in.
func (f fwFound) refusal() *fwFailure {
	switch {
	case f.conflict:
		return &fwFailure{reason: fwConflictText}
	case f.kind == fwKindNft || f.kind == fwKindIptables:
		return &fwFailure{reason: "this host's firewall is plain " + f.kind + " rules; the agent manages ufw or firewalld only, so it changes nothing here"}
	case f.b == nil:
		return probeRefusal(f.ufw)
	case f.b.Name() == fwKindFirewalld:
		return firewalldRefusal(f.p)
	}
	return probeRefusal(f.p)
}

// firewalldRefusal is probeRefusal for firewalld.
func firewalldRefusal(p ufwProbe) *fwFailure {
	switch p.state {
	case fwMissing, fwInactive:
		return &fwFailure{reason: "firewalld stopped running, so the agent will not change rules"}
	case fwUnusable:
		return &fwFailure{cmd: "firewall-cmd --list-all", out: p.out, err: p.err}
	case fwUnparsed:
		return &fwFailure{reason: "the agent could not read firewalld's zone, so it will not change rules blindly"}
	}
	return nil
}

// readOnlyFwView is the 🛡 screen of nftables or iptables rules: what
// enforces, clipped, and why there is nothing to press.
func readOnlyFwView(f fwFound) tgui.View {
	count := nftCounts(f.listing)
	if f.kind == fwKindIptables {
		count = iptablesCounts(f.listing)
	}
	text := "🛡 <b>Firewall</b> · " + f.kind + " (read-only)\n" +
		"The agent manages ufw or firewalld only, so it cannot change these rules. This is what enforces (" + count + "):\n" +
		pre(readOnlyRows(f.listing))
	if f.ufw.state == fwInactive {
		text += "\nufw is installed but inactive."
	}
	return tgui.View{Text: text}
}

// readOnlyRows is a ruleset clipped to fit: one space of indent per tab
// nft indents with, each line cut to a phone's width, at most
// fwReadOnlyRows lines.
func readOnlyRows(listing string) []string {
	var rows []string
	n := 0
	for _, line := range strings.Split(listing, "\n") {
		t := strings.TrimSpace(line)
		if t == "" {
			continue
		}
		n++
		if len(rows) < fwReadOnlyRows {
			depth := len(line) - len(strings.TrimLeft(line, "\t"))
			rows = append(rows, bot.Clip(strings.Repeat(" ", min(depth, 4))+t, bot.PreCols))
		}
	}
	if n > len(rows) {
		rows = append(rows, fmt.Sprintf("… %d more lines", n-len(rows)))
	}
	return rows
}

// nftCounts is "2 tables, 5 chains" for `nft list ruleset`, "" for an
// empty ruleset (or anything that is not one).
func nftCounts(out string) string {
	tables, chains := 0, 0
	for _, line := range strings.Split(out, "\n") {
		switch t := strings.TrimSpace(line); {
		case strings.HasPrefix(line, "table ") && strings.HasSuffix(t, "{"):
			tables++
		case strings.HasPrefix(t, "chain ") && strings.HasSuffix(t, "{"):
			chains++
		}
	}
	if tables == 0 {
		return ""
	}
	return plural(tables, "table") + ", " + plural(chains, "chain")
}

// iptablesCounts is "7 rules" for `iptables -S`, "" when it holds no
// rule (the default ACCEPT policies alone filter nothing).
func iptablesCounts(out string) string {
	rules, policy := 0, false
	for _, line := range strings.Split(out, "\n") {
		f := strings.Fields(line)
		switch {
		case len(f) >= 2 && f[0] == "-A":
			rules++
		case len(f) == 3 && f[0] == "-P" && f[2] != "ACCEPT":
			policy = true
		}
	}
	if rules == 0 && !policy {
		return ""
	}
	return plural(rules, "rule")
}
