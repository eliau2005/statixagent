package agent

import (
	"errors"
	"fmt"
	"maps"
	"net/netip"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/eliau2005/statixagent/internal/bot"
)

// Firewall plans (docs/telegram-ux-redesign.md §5.3). Every rule change
// the bot offers, a typed /fw_open, a preset, a rule deletion or a
// restored snapshot, becomes a plan: ordered ufw changes built only from
// parsed values, or from specs ufw itself printed. A plan is simulated
// on the parsed rules, guarded, shown as an exact diff and kept here,
// server-side, under a confirm token: callback data never carries a
// rule. On Yes it runs under the dead-man switch (fwdeadman.go), after
// the guard has run again on a fresh reading. Everything in the first
// half of this file is pure, so it is pinned by table tests.

const (
	// fwMaxUserRules is the most user rules the bot will add up to.
	fwMaxUserRules = 64
	// fwMaxSpan is the widest port range a rule may cover.
	fwMaxSpan = 1000
	// fwPlanTTL is how long a planned change waits for its Yes.
	fwPlanTTL = 10 * time.Minute
	// fwMaxPlans bounds the pending plans; the oldest go first.
	fwMaxPlans = 32
	// fwDiffMax is how many changed rows a confirm screen lists.
	fwDiffMax = 24
)

// fwDBPorts are the database presets: never opened to Anywhere.
var fwDBPorts = map[int]string{5432: "Postgres", 6379: "Redis"}

// fwSpec is a rule the bot adds, made of parsed values only.
type fwSpec struct {
	Action string       // allow|deny|limit
	Ports  portRange    // zero: every port
	Proto  string       // tcp|udp|"" (both)
	From   netip.Prefix // zero: Anywhere
}

func (s fwSpec) portArg() string {
	p := strconv.Itoa(s.Ports.Lo)
	if s.Ports.Hi != s.Ports.Lo {
		p += ":" + strconv.Itoa(s.Ports.Hi)
	}
	return p
}

// args is the rule spec as `ufw show added` prints it, so a rule the
// bot added can be found and deleted by the same words.
func (s fwSpec) args() []string {
	if !s.From.IsValid() {
		p := s.portArg()
		if s.Proto != "" {
			p += "/" + s.Proto
		}
		return []string{s.Action, p}
	}
	args := []string{s.Action, "from", prefixArg(s.From)}
	if s.Ports.Lo != 0 {
		args = append(args, "to", "any", "port", s.portArg())
	}
	if s.Proto != "" {
		args = append(args, "proto", s.Proto)
	}
	return args
}

// prefixArg writes a single host as its bare address, as ufw does.
func prefixArg(p netip.Prefix) string {
	if p.IsSingleIP() {
		return p.Addr().String()
	}
	return p.String()
}

// errUsage is a typed command's argument that did not validate; its
// text is shown to the user (escaped).
type errUsage string

func (e errUsage) Error() string { return string(e) }

// parsePortArg parses "port", "port/proto" or "lo:hi/proto". Ranges
// need a protocol, as ufw requires, and cover at most fwMaxSpan ports.
func parsePortArg(s string) (portRange, string, error) {
	list, proto, hasProto := strings.Cut(s, "/")
	if hasProto && proto != "tcp" && proto != "udp" {
		return portRange{}, "", errUsage(fmt.Sprintf("protocol %q is not tcp or udp", proto))
	}
	port := func(s string) (int, error) {
		n, err := strconv.Atoi(s)
		if err != nil || n < 1 || n > 65535 || strconv.Itoa(n) != s {
			return 0, errUsage(fmt.Sprintf("%q is not a port (1-65535)", s))
		}
		return n, nil
	}
	lo, hi, isRange := strings.Cut(list, ":")
	a, err := port(lo)
	if err != nil {
		return portRange{}, "", err
	}
	if !isRange {
		return portRange{a, a}, proto, nil
	}
	b, err := port(hi)
	switch {
	case err != nil:
		return portRange{}, "", err
	case proto == "":
		return portRange{}, "", errUsage("a port range needs a protocol, e.g. " + lo + ":" + hi + "/tcp")
	case a >= b:
		return portRange{}, "", errUsage("a port range runs from low to high, e.g. 6000:6007/tcp")
	case b-a+1 > fwMaxSpan:
		return portRange{}, "", errUsage(fmt.Sprintf("a range may cover at most %d ports", fwMaxSpan))
	}
	return portRange{a, b}, proto, nil
}

// parseSourceArg parses the source of an allow or deny: an address or a
// CIDR, in canonical form only; anything else is refused with the form
// it probably meant. Sources that never reach ufw's INPUT rules
// (loopback, link-local, multicast), IPv6 while ufw has it turned off,
// and the whole Internet are refused: /fw_open is the explicit way to
// allow from Anywhere, and a deny from everywhere is a lockout.
func parseSourceArg(s string, v6ok bool) (netip.Prefix, error) {
	var p netip.Prefix
	var canon string
	if strings.Contains(s, "/") {
		q, err := netip.ParsePrefix(s)
		if err != nil {
			return p, errUsage(fmt.Sprintf("%q is not an IP address or CIDR", s))
		}
		if q.Addr().Is4In6() {
			if q.Bits() < 96 {
				return p, errUsage(fmt.Sprintf("%q is not an IPv4 range; write IPv4 sources as a.b.c.d/n", s))
			}
			q = netip.PrefixFrom(q.Addr().Unmap(), q.Bits()-96)
		}
		p, canon = q.Masked(), q.Masked().String()
		if p.IsSingleIP() {
			canon = p.Addr().String()
		}
	} else {
		a, err := netip.ParseAddr(s)
		if err != nil || a.Zone() != "" {
			return p, errUsage(fmt.Sprintf("%q is not an IP address or CIDR", s))
		}
		a = a.Unmap()
		p, canon = netip.PrefixFrom(a, a.BitLen()), a.String()
	}
	a := p.Addr()
	switch {
	case canon != s:
		return p, errUsage(fmt.Sprintf("%q is not in canonical form; did you mean %s?", s, canon))
	case p.Bits() == 0:
		return p, errUsage("a source of /0 is every address; use /fw_open to allow from Anywhere, and deny from a shell")
	case a.IsLoopback() || a.IsLinkLocalUnicast() || a.IsLinkLocalMulticast() || a.IsMulticast() || a.IsUnspecified():
		return p, errUsage(canon + " is a loopback, link-local or multicast address; ufw rules do not apply to it")
	case a.Is6() && !v6ok:
		return p, errUsage("IPv6 is turned off in ufw (IPV6=no in /etc/default/ufw)")
	}
	return p, nil
}

// dbPort is the database preset port r covers, and its name; 0 and ""
// when it covers none.
func dbPort(r portRange) (int, string) {
	for _, port := range slices.Sorted(maps.Keys(fwDBPorts)) {
		if r.Lo <= port && port <= r.Hi {
			return port, fwDBPorts[port]
		}
	}
	return 0, ""
}

// specRule reads a ufw rule spec, simple ("allow 22/tcp", "limit
// OpenSSH") or extended ("allow from 10.0.0.0/8 to any port 5432 proto
// tcp"), as the row ufw would list for it. fam is "v4" or "v6" for a
// rule tied to one family by an address, "" for one that is in both.
func specRule(spec []string) (r fwRule, fam string, ok bool) {
	var words []string
	for i := 0; i < len(spec); i++ {
		switch w := spec[i]; w {
		case "log", "log-all":
		case "comment":
			i++ // and its text
		default:
			words = append(words, w)
		}
	}
	if len(words) < 2 {
		return r, "", false
	}
	r = fwRule{Action: words[0], Dir: "in"}
	switch r.Action {
	case "allow", "deny", "reject", "limit":
	default:
		return r, "", false
	}
	words = words[1:]
	if words[0] == "in" || words[0] == "out" {
		r.Dir, words = words[0], words[1:]
	}
	if len(words) >= 2 && words[0] == "on" {
		r.Iface, words = words[1], words[2:]
	}
	switch {
	case len(words) == 1 && parsePortSpec(&r, words[0]):
	case len(words) == 1 && words[0] != "from" && words[0] != "to":
		r.App = words[0]
	case len(words)%2 != 0 || len(words) == 0:
		return r, "", false
	default:
		side, port, proto := "", "", ""
		for i := 0; i < len(words); i += 2 {
			k, v := words[i], words[i+1]
			switch k {
			case "from", "to":
				side = k
				if v == "any" {
					continue
				}
				p, ok := parseFwAddr(v)
				if !ok {
					return r, "", false
				}
				if k == "from" {
					r.From = p
				} else {
					r.Dst = p
				}
			case "port", "app":
				switch {
				case side == "from":
					r.partial = true // a source port or app
				case k == "port":
					port = v
				default:
					r.App = v
				}
			case "proto":
				proto = v
			default:
				return r, "", false
			}
		}
		switch {
		case port != "" && proto != "":
			ok = parsePortSpec(&r, port+"/"+proto)
		case port != "":
			ok = parsePortSpec(&r, port)
		default:
			ok, r.Proto = true, proto
		}
		if !ok {
			return r, "", false
		}
	}
	for _, p := range []netip.Prefix{r.From, r.Dst} {
		if p.IsValid() {
			fam = "v4"
			if p.Addr().Is6() {
				fam = "v6"
			}
		}
	}
	r.V6 = fam == "v6"
	return r, fam, true
}

// sameMatch reports whether two rules match the same traffic, whatever
// their actions.
func sameMatch(a, b fwRule) bool {
	if a.Dir != b.Dir || a.From != b.From || a.Dst != b.Dst || a.Iface != b.Iface || a.partial != b.partial {
		return false
	}
	if a.App != "" || b.App != "" {
		return a.App == b.App
	}
	return a.Proto == b.Proto && slices.Equal(a.Ports, b.Ports)
}

// rowOf reports whether status row is one of the rows spec rule r (of
// family fam) is listed as.
func rowOf(row, r fwRule, fam string) bool {
	return row.Action == r.Action && sameMatch(row, r) && (fam == "" || row.V6 == (fam == "v6"))
}

// families is the families a rule of fam is listed in.
func families(fam string, v6 bool) []bool {
	switch {
	case fam == "v4":
		return []bool{false}
	case fam == "v6":
		return []bool{true}
	case v6:
		return []bool{false, true}
	}
	return []bool{false}
}

// simulate applies plan to the parsed rules in memory, the way ufw
// would: v4 rows are listed before v6 rows; insert and prepend put a
// rule first in its family, add puts it last, and add of a rule that
// matches the same traffic as an existing one changes that rule's
// action in place. v6 says whether ufw keeps IPv6 rules at all. A spec
// the model cannot read changes nothing; plans are built only from
// readable ones.
func simulate(st ufwStatus, plan fwPlan, v6 bool) ufwStatus {
	rules := slices.Clone(st.rules)
	for _, c := range plan {
		r, fam, ok := specRule(c.Spec)
		if !ok {
			continue
		}
		if c.Op == opDelete {
			rules = slices.DeleteFunc(rules, func(row fwRule) bool { return rowOf(row, r, fam) })
			continue
		}
		for _, six := range families(fam, v6) {
			row := r
			row.V6 = six
			row.Raw = rowRaw(row)
			i := slices.IndexFunc(rules, func(x fwRule) bool { return x.V6 == six && sameMatch(x, row) })
			switch {
			case i >= 0 && rules[i].Action == row.Action:
				continue // ufw skips an existing rule
			case i >= 0 && c.Op == opAdd:
				rules[i] = row
				continue
			case i >= 0:
				rules = slices.Delete(rules, i, i+1)
			}
			firstV6 := slices.IndexFunc(rules, func(x fwRule) bool { return x.V6 })
			if firstV6 < 0 {
				firstV6 = len(rules)
			}
			at := len(rules) // add: last of its family
			switch {
			case c.Op != opAdd && six:
				at = firstV6
			case c.Op != opAdd:
				at = 0
			case !six:
				at = firstV6
			}
			rules = slices.Insert(rules, at, row)
		}
	}
	for i := range rules {
		rules[i].Num = i + 1
	}
	st.rules = rules
	return st
}

// rowRaw is a simulated row as `ufw status verbose` would print it.
func rowRaw(r fwRule) string {
	to := portLabel(r)
	if to == "any" {
		to = "Anywhere"
	}
	if r.V6 && !r.Dst.IsValid() {
		to += " (v6)"
	}
	return to + " " + strings.ToUpper(r.Action) + " " + strings.ToUpper(r.Dir) + " " + fromLabel(r)
}

// portLabel is what a rule matches on: "22/tcp", "6000:6007/udp", an
// app profile, or "any".
func portLabel(r fwRule) string {
	if r.App != "" && len(r.Ports) == 0 {
		return r.App
	}
	var ports []string
	for _, p := range r.Ports {
		s := strconv.Itoa(p.Lo)
		if p.Hi != p.Lo {
			s += ":" + strconv.Itoa(p.Hi)
		}
		ports = append(ports, s)
	}
	s := strings.Join(ports, ",")
	switch {
	case s == "" && r.Proto == "":
		return "any"
	case s == "":
		s = "any"
	}
	if r.Proto != "" {
		s += "/" + r.Proto
	}
	return s
}

// fromLabel is a rule's source: an address, a CIDR or Anywhere.
func fromLabel(r fwRule) string {
	if r.From.IsValid() {
		return prefixArg(r.From)
	}
	if r.V6 {
		return "Anywhere (v6)"
	}
	return "Anywhere"
}

// actionLabel is "ALLOW", or "ALLOW OUT" for an outgoing rule.
func actionLabel(r fwRule) string {
	if r.Dir != "in" {
		return strings.ToUpper(r.Action + " " + r.Dir)
	}
	return strings.ToUpper(r.Action)
}

// verdictSig identifies what decided a verdict, to tell whether a
// change touched it.
func verdictSig(v portVerdict) string {
	var b strings.Builder
	fmt.Fprintf(&b, "%d|%s|", v.state, v.policy)
	if v.rule != nil {
		b.WriteString(v.rule.Action + " " + v.rule.Raw)
	}
	for _, list := range [][]fwRule{v.except, v.unsure} {
		b.WriteString("|")
		for _, r := range list {
			b.WriteString(r.Action + " " + r.Raw + ";")
		}
	}
	return b.String()
}

// sshGuard is the hard refusal of §5.3, with no bot override: the change
// from before to after must leave first-match for (SSH port, tcp, peer)
// allowing every current admin peer, and leave every SSH port that was
// open to Anywhere open. A peer the model cannot show as allowed (an
// interface-bound rule, say) only counts when the change touches what
// decides for it. It returns why the change is refused, or "".
func sshGuard(before, after ufwStatus, ports []int, peers []netip.Addr) string {
	for _, port := range ports {
		for _, peer := range peers {
			vb := before.verdict(port, peer.Is6(), peer)
			va := after.verdict(port, peer.Is6(), peer)
			if !reachable(va) && (reachable(vb) || verdictSig(vb) != verdictSig(va)) {
				return fmt.Sprintf("This would block SSH %d/tcp for your session from %s.", port, peer)
			}
		}
		for _, v6 := range []bool{false, true} {
			if v6 && !before.hasV6() && !after.hasV6() {
				continue
			}
			if reachable(before.verdict(port, v6, netip.Addr{})) && !reachable(after.verdict(port, v6, netip.Addr{})) {
				fam := ""
				if v6 {
					fam = " for IPv6"
				}
				return fmt.Sprintf("This would close SSH %d/tcp%s.", port, fam)
			}
		}
	}
	return ""
}

// sameRow reports whether two rows say the same, parsed or simulated.
func sameRow(a, b fwRule) bool {
	return a.Action == b.Action && a.V6 == b.V6 && sameMatch(a, b)
}

// diffRows renders the rows only in before as "−" and the rows only in
// after as "+", numbered as each side lists them, at most fwDiffMax.
func diffRows(before, after ufwStatus) []string {
	var lines []string
	n := 0
	add := func(sign string, r fwRule) {
		n++
		if n > fwDiffMax {
			return
		}
		lines = append(lines, fmt.Sprintf("%s %d %s %s", sign, r.Num, bot.Pad(actionLabel(r), 5), portLabel(r)),
			"    from "+fromLabel(r))
	}
	for _, r := range before.rules {
		if !slices.ContainsFunc(after.rules, func(x fwRule) bool { return sameRow(r, x) }) {
			add("−", r)
		}
	}
	for _, r := range after.rules {
		if !slices.ContainsFunc(before.rules, func(x fwRule) bool { return sameRow(r, x) }) {
			add("+", r)
		}
	}
	if n > fwDiffMax {
		lines = append(lines, fmt.Sprintf("… %d more changes", n-fwDiffMax))
	}
	return lines
}

// errNoChange: every rule the plan would add is already there.
var errNoChange = errors.New("nothing to change: the rules are already there")

// planSpecs is the plan that adds specs in order. A rule matching the
// same traffic with another action is deleted first, so the result is
// explicit in the diff; a rule already there is left alone. Deny rules
// go first in their family, so no earlier allow can let the traffic in;
// allow and limit rules are appended, as ufw does. ufw refuses `insert
// 1` into an empty IPv4 list, so a deny is then added; and inserting an
// IPv6-only rule at 1 names an IPv4 position, so it is prepended.
func planSpecs(added [][]string, st ufwStatus, specs []fwSpec, v6 bool) (fwPlan, error) {
	var plan fwPlan
	count := len(added)
	for _, s := range specs {
		want := s.args()
		wr, wfam, _ := specRule(want)
		present := false
		for _, spec := range added {
			r, fam, ok := specRule(spec)
			if !ok || fam != wfam || !sameMatch(r, wr) || slices.ContainsFunc(plan, func(c fwChange) bool {
				return c.Op == opDelete && slices.Equal(c.Spec, spec)
			}) {
				continue
			}
			if r.Action == wr.Action {
				present = true
				continue
			}
			plan = append(plan, fwChange{Op: opDelete, Spec: spec})
			count--
		}
		if present {
			continue
		}
		op := opAdd
		if s.Action == "deny" {
			v4 := slices.ContainsFunc(simulate(st, plan, v6).rules, func(r fwRule) bool { return !r.V6 })
			switch {
			case wfam == "v6":
				op = opPrepend
			case v4:
				op = opInsert
			}
		}
		plan = append(plan, fwChange{Op: op, Spec: want})
		count++
	}
	switch {
	case count > fwMaxUserRules:
		return nil, errUsage(fmt.Sprintf("ufw would hold %d user rules; the bot manages at most %d. Remove some first.", count, fwMaxUserRules))
	case len(plan) == 0:
		return nil, errNoChange
	}
	return plan, nil
}

// restorePlan is what undoes restoring a snapshot by spec, should the
// rules change during the trial: the rules only the current list has are
// deleted, the ones only the snapshot has are added.
func restorePlan(cur, snap [][]string) fwPlan {
	var plan fwPlan
	for _, s := range cur {
		if !slices.ContainsFunc(snap, func(x []string) bool { return slices.Equal(x, s) }) {
			plan = append(plan, fwChange{Op: opDelete, Spec: s})
		}
	}
	for _, s := range snap {
		if !slices.ContainsFunc(cur, func(x []string) bool { return slices.Equal(x, s) }) {
			plan = append(plan, fwChange{Op: opAdd, Spec: s})
		}
	}
	return plan
}

// fwGen fingerprints a rule list: a plan made against one generation
// runs only against the same, and list buttons carry its first 6 hex.
func fwGen(st ufwStatus) string {
	var b strings.Builder
	for _, r := range st.rules {
		fmt.Fprintf(&b, "%s %s|", r.Action, r.Raw)
	}
	return callbackDigest(b.String())
}

// rowSpecs pairs each status row with the user rule spec it is listed
// for, nil when none (a rule `show added` does not print).
func rowSpecs(st ufwStatus, added [][]string) [][]string {
	specs := make([][]string, len(st.rules))
	for i, row := range st.rules {
		for _, spec := range added {
			if r, fam, ok := specRule(spec); ok && rowOf(row, r, fam) {
				specs[i] = spec
				break
			}
		}
	}
	return specs
}

// ruleID names a row in callback data: the digest of its canonical spec
// and family, or of the row itself when no spec lists it.
func ruleID(row fwRule, spec []string) string {
	if spec == nil {
		return callbackDigest("row|" + row.Action + " " + row.Raw)
	}
	fam := "v4"
	if row.V6 {
		fam = "v6"
	}
	return callbackDigest(strings.Join(spec, " ") + "|" + fam)
}

// specText is a spec as a shell would take it, quoting arguments with
// spaces (an app profile like 'Nginx Full').
func specText(args []string) string {
	out := make([]string, len(args))
	for i, a := range args {
		if a == "" || strings.ContainsAny(a, " \t'\"") {
			a = "'" + strings.ReplaceAll(a, "'", `'\''`) + "'"
		}
		out[i] = a
	}
	return strings.Join(out, " ")
}

// ---- pending plans ----

// fwPlanReq is a planned change waiting for its Yes.
type fwPlanReq struct {
	id    string
	title string // "Open 8080/tcp", plain text
	plan  fwPlan
	// restore is the snapshot a restore writes back; plan then only
	// undoes it by spec.
	restore string
	// base is the generation of the rules the plan was made against.
	base string
	// after is the simulated rule list (a restore: the snapshot's).
	after ufwStatus
	// diff and check are the confirm screen's diff rows and SSH line.
	diff  []string
	check string
	actor int64
	nonce string
	// expires is when the plan, and its token, run out.
	expires time.Time
}

// fwPlans holds the pending plans of this process, in memory only: a
// restart forgets them, as it forgets their tokens.
type fwPlans struct {
	mu    sync.Mutex
	m     map[string]*fwPlanReq
	order []string // oldest first
}

// put stores r, evicting expired plans and then the oldest.
func (s *fwPlans) put(r *fwPlanReq, now time.Time) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.m == nil {
		s.m = map[string]*fwPlanReq{}
	}
	s.order = slices.DeleteFunc(s.order, func(id string) bool {
		if !now.Before(s.m[id].expires) {
			delete(s.m, id)
			return true
		}
		return false
	})
	for len(s.order) >= fwMaxPlans {
		delete(s.m, s.order[0])
		s.order = s.order[1:]
	}
	s.m[r.id] = r
	s.order = append(s.order, r.id)
}

// get returns the plan id names while it has not expired.
func (s *fwPlans) get(id string, now time.Time) (*fwPlanReq, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	r, ok := s.m[id]
	if !ok || !now.Before(r.expires) {
		return nil, false
	}
	return r, true
}

// take is get, removing the plan: it runs at most once.
func (s *fwPlans) take(id string, now time.Time) (*fwPlanReq, bool) {
	r, ok := s.get(id, now)
	if ok {
		s.mu.Lock()
		delete(s.m, id)
		s.order = slices.DeleteFunc(s.order, func(x string) bool { return x == id })
		s.mu.Unlock()
	}
	return r, ok
}
