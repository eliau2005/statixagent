package agent

import (
	"cmp"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/eliau2005/statixagent/internal/services"
	"github.com/eliau2005/statixagent/internal/sshwatch"
)

// firewalld backend (docs/telegram-ux-redesign.md §5.2, Decision 14b).
// The agent changes the runtime configuration of the default zone only,
// so a reload or a reboot also takes a change back. Keep re-runs the same
// changes with --permanent; never --runtime-to-permanent, which would
// also persist whatever other tools added at runtime. Rollback runs the
// inverse runtime operations. --reload is the last resort only: it brings
// back the permanent configuration, which a trial never touched, but it
// also drops every runtime-only rule, other tools' included (fail2ban's
// bans, Docker's rules on some versions).
//
// The zone maps onto the ufw rule model (fwufw.go) in the order firewalld
// evaluates it: rich rules with a negative priority, then deny and reject
// rich rules, then ports, services and accept rich rules, then rich rules
// with a positive priority, and the zone's target when nothing matched.
// Rules the agent writes are built from parsed values only (specRule),
// each rich rule a single argument.

// firewalldPaths are tried in order, like ufwPaths.
var firewalldPaths = []string{"firewall-cmd", "/usr/bin/firewall-cmd"}

// fwKindFirewalld is the firewalld backend's name.
const fwKindFirewalld = "firewalld"

const fwdZoneFile = "zone.json"

// fwdNoSpec is why a firewalld rule without a spec is not deleted here.
const fwdNoSpec = "The agent does not write this kind of firewalld rule (a priority, log, limit, " +
	"source port, or a family without an address), so it is deleted from a shell only."

var (
	// fwdNamePattern is a zone, service or protocol name as firewalld
	// prints it; anything else never reaches an argument.
	fwdNamePattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.+-]{0,63}$`)
	// fwdPortPattern is a port entry: "8080/tcp", "6000-6007/udp".
	fwdPortPattern = regexp.MustCompile(`^[0-9]{1,5}(-[0-9]{1,5})?/(tcp|udp|sctp|dccp)$`)
)

// fwdZone is one zone's runtime configuration, as --list-all prints it.
type fwdZone struct {
	Name        string   `json:"name"`
	Target      string   `json:"target"`
	Services    []string `json:"services,omitempty"`
	Ports       []string `json:"ports,omitempty"`
	Protocols   []string `json:"protocols,omitempty"`
	SourcePorts []string `json:"source_ports,omitempty"`
	Rich        []string `json:"rich,omitempty"`
	// Other is every other setting ("masquerade: no"), only so a change
	// to it changes the hash.
	Other []string `json:"other,omitempty"`
	// SvcPorts are each service's ports and protocols ("22/tcp", "gre"),
	// as --info-service prints them; a service missing here is unknown.
	SvcPorts map[string][]string `json:"svc_ports,omitempty"`
}

// parseFwdZone reads `firewall-cmd --zone=<zone> --list-all`. The
// zone's own line is located rather than assumed to be first, since the
// runner merges stderr (warnings) into the output.
func parseFwdZone(out, zone string) (fwdZone, bool) {
	z := fwdZone{Name: zone}
	head, rich, target := false, false, false
	for _, line := range strings.Split(out, "\n") {
		t := strings.TrimSpace(line)
		switch {
		case t == "":
			continue
		case !head:
			if f := strings.Fields(line); len(f) > 0 && f[0] == zone && line[0] != ' ' && line[0] != '\t' {
				head = true
			}
			continue
		case rich && strings.HasPrefix(t, "rule "):
			z.Rich = append(z.Rich, t)
			continue
		}
		k, v, ok := strings.Cut(t, ":")
		if !ok {
			continue
		}
		rich = false
		f := strings.Fields(v)
		switch k {
		case "target":
			z.Target, target = strings.TrimSpace(v), true
		case "services":
			z.Services = f
		case "ports":
			z.Ports = f
		case "protocols":
			z.Protocols = f
		case "source-ports":
			z.SourcePorts = f
		case "rich rules":
			rich = true
		case "interfaces", "sources":
			// Where the zone applies, not what it allows.
		default:
			slices.Sort(f)
			z.Other = append(z.Other, k+": "+strings.Join(f, " "))
		}
	}
	return z, head && target
}

// sha fingerprints what the zone allows, order aside.
func (z fwdZone) sha() string {
	h := sha256.New()
	fmt.Fprintf(h, "%s\x00%s\x00", z.Name, z.Target)
	for _, list := range [][]string{z.Services, z.Ports, z.Protocols, z.SourcePorts, z.Rich, z.Other} {
		for _, s := range slices.Sorted(slices.Values(list)) {
			fmt.Fprintf(h, "%s\x00", s)
		}
		h.Write([]byte{1})
	}
	return hex.EncodeToString(h.Sum(nil))
}

// fwdPolicy is the incoming policy a zone target stands for. "default"
// rejects what no rule accepted.
func fwdPolicy(target string) string {
	switch target {
	case "ACCEPT":
		return "allow"
	case "DROP":
		return "deny"
	case "default", "%%REJECT%%", "REJECT":
		return "reject"
	}
	return ""
}

// Evaluation groups, in firewalld's order.
const (
	fwdPre   = iota // rich rules with a negative priority
	fwdDeny         // deny and reject rich rules
	fwdAllow        // ports, services, accept rich rules
	fwdPost         // rich rules with a positive priority
)

// fwdEntry is one rule of the zone before it is listed per family.
type fwdEntry struct {
	r     fwRule
	fam   string // "v4", "v6", or "" for both
	group int
	prio  int
	what  string // "port", "service", "rich rule", …
}

// status is the zone as the rule model: IPv4 rows first, then IPv6, each
// in evaluation order.
func (z fwdZone) status() ufwStatus {
	st := ufwStatus{found: true, active: true, policy: fwdPolicy(z.Target)}
	var es []fwdEntry
	allow := func(r fwRule, what string) {
		r.Action, r.Dir = "allow", "in"
		es = append(es, fwdEntry{r: r, group: fwdAllow, what: what})
	}
	for _, p := range z.Ports {
		if r, ok := fwdPort(p); ok {
			allow(r, "port")
		}
	}
	for _, p := range z.Protocols {
		allow(fwRule{Proto: p}, "protocol")
	}
	for _, s := range z.Services {
		for _, r := range z.serviceRows(fwRule{App: s}, s) {
			allow(r, "service")
		}
	}
	for _, p := range z.SourcePorts {
		// Traffic from a source port: narrower than any port rule.
		if r, ok := fwdPort(p); ok {
			allow(fwRule{Proto: r.Proto, partial: true}, "source port")
		}
	}
	for _, text := range z.Rich {
		x, ok := parseRich(text)
		if !ok || !x.decides {
			continue
		}
		e := fwdEntry{fam: x.fam, prio: x.prio, group: fwdAllow, what: "rich rule"}
		switch {
		case x.prio < 0:
			e.group = fwdPre
		case x.prio > 0:
			e.group = fwdPost
		case x.r.Action == "deny" || x.r.Action == "reject":
			e.group = fwdDeny
		}
		rows := []fwRule{x.r}
		if x.service != "" {
			rows = z.serviceRows(x.r, x.service)
		}
		for _, r := range rows {
			e.r = r
			es = append(es, e)
		}
	}
	slices.SortStableFunc(es, func(a, b fwdEntry) int {
		return cmp.Or(cmp.Compare(a.group, b.group), cmp.Compare(a.prio, b.prio))
	})
	for _, six := range []bool{false, true} {
		for _, e := range es {
			if e.fam == "v4" && six || e.fam == "v6" && !six {
				continue
			}
			r := e.r
			r.V6, r.Num = six, len(st.rules)+1
			r.Raw = rowRaw(r) + " · " + e.what
			if r.App != "" && len(r.Ports) > 0 {
				r.Raw += " " + r.App
			}
			st.rules = append(st.rules, r)
		}
	}
	return st
}

// serviceRows are the rows of service svc: base with the service's
// ports, one row per protocol, or one unresolved row when its ports are
// unknown.
func (z fwdZone) serviceRows(base fwRule, svc string) []fwRule {
	base.App = svc
	entries, known := z.SvcPorts[svc]
	if !known {
		base.unresolved = true
		return []fwRule{base}
	}
	var rows []fwRule
	byProto := map[string]int{}
	for _, p := range entries {
		r, ok := fwdPort(p)
		if !ok {
			r = fwRule{Proto: p} // a whole protocol
		}
		if i, seen := byProto[r.Proto]; seen && ok && len(rows[i].Ports) > 0 {
			rows[i].Ports = append(rows[i].Ports, r.Ports...)
			continue
		}
		row := base
		row.Proto, row.Ports = r.Proto, r.Ports
		byProto[r.Proto] = len(rows)
		rows = append(rows, row)
	}
	return rows
}

// fwdPort parses a port entry, "8080/tcp" or "6000-6007/udp".
func fwdPort(s string) (fwRule, bool) {
	if !fwdPortPattern.MatchString(s) {
		return fwRule{}, false
	}
	ports, proto, _ := strings.Cut(s, "/")
	lo, hi, isRange := strings.Cut(ports, "-")
	if !isRange {
		hi = lo
	}
	a, err1 := strconv.Atoi(lo)
	b, err2 := strconv.Atoi(hi)
	if err1 != nil || err2 != nil || a < 1 || b > 65535 || a > b {
		return fwRule{}, false
	}
	return fwRule{Proto: proto, Ports: []portRange{{a, b}}}, true
}

// fwdPortArg writes a port range as firewalld does: "22", "6000-6007".
func fwdPortArg(p portRange) string {
	if p.Lo == p.Hi {
		return strconv.Itoa(p.Lo)
	}
	return strconv.Itoa(p.Lo) + "-" + strconv.Itoa(p.Hi)
}

// fwdRich is a rich rule as the model reads it.
type fwdRich struct {
	r       fwRule
	fam     string // "v4", "v6", or "" for both
	prio    int
	service string
	// decides: an accept, reject or drop; log-only and mark rules, and
	// ICMP, masquerade and forward-port rules, never decide a TCP port.
	decides bool
	// plain: a rule the agent itself could have written, so it has a
	// spec and can be deleted by it.
	plain bool
}

// richWords splits a rich rule into words, a quoted value staying one
// word with its quotes removed: `log prefix="a b"` is log, prefix=a b.
func richWords(s string) []string {
	var out []string
	var cur strings.Builder
	quoted, in := false, false
	for _, r := range s {
		switch {
		case r == '"':
			quoted, in = !quoted, true
		case (r == ' ' || r == '\t') && !quoted:
			if in {
				out = append(out, cur.String())
				cur.Reset()
				in = false
			}
		default:
			cur.WriteRune(r)
			in = true
		}
	}
	if in {
		out = append(out, cur.String())
	}
	return out
}

// parseRich reads a rich rule as firewalld lists it.
func parseRich(text string) (fwdRich, bool) {
	w := richWords(text)
	if len(w) == 0 || w[0] != "rule" {
		return fwdRich{}, false
	}
	x := fwdRich{r: fwRule{Dir: "in"}, plain: true}
	var elem, action, family, port, portProto string
	limited := false
	for _, word := range w[1:] {
		k, v, kv := strings.Cut(word, "=")
		if !kv {
			switch word {
			case "source", "destination", "port", "protocol", "service":
				elem = word
			case "log", "nflog", "audit":
				elem, x.plain = word, false
			case "source-port":
				elem, x.r.partial, x.plain = word, true, false
			case "icmp-block", "icmp-type", "masquerade", "forward-port", "tcp-mss-clamp":
				return x, true // never accepts a TCP port
			case "not":
				x.r.partial, x.plain = true, false
			case "accept", "reject", "drop", "mark":
				elem, action = "action", word
			case "limit":
				if elem == "action" {
					limited = true
				}
				x.plain = false
			default:
				x.plain = false
			}
			continue
		}
		switch {
		case elem == "" && k == "family":
			family = v
		case elem == "" && k == "priority":
			n, err := strconv.Atoi(v)
			if err != nil {
				return fwdRich{}, false
			}
			x.prio = n
		case elem == "source" && k == "address":
			p, ok := parseFwAddr(v)
			if !ok {
				x.r.partial, x.plain = true, false
				continue
			}
			x.r.From = p
		case elem == "source", elem == "destination":
			// A MAC, an ipset or a destination: narrower than the model.
			x.r.partial, x.plain = true, false
			if p, ok := parseFwAddr(v); ok && elem == "destination" && k == "address" {
				x.r.Dst, x.r.partial = p, false
			}
		case elem == "port" && k == "port":
			port = v
		case elem == "port" && k == "protocol":
			portProto = v
		case elem == "protocol" && k == "value":
			x.r.Proto, x.plain = v, false
		case elem == "service" && k == "name":
			x.service, x.plain = v, false
		case elem == "action":
			// A reject type or a mark: more than the agent writes.
			x.plain = false
		}
	}
	if port != "" {
		r, ok := fwdPort(port + "/" + portProto)
		if !ok {
			return fwdRich{}, false
		}
		x.r.Ports, x.r.Proto = r.Ports, r.Proto
		if r.Proto != "tcp" && r.Proto != "udp" {
			x.plain = false
		}
	}
	switch family {
	case "ipv4":
		x.fam = "v4"
	case "ipv6":
		x.fam = "v6"
	}
	if x.r.From.IsValid() {
		fam := "v4"
		if x.r.From.Addr().Is6() {
			fam = "v6"
		}
		if x.fam != "" && x.fam != fam {
			return fwdRich{}, false
		}
		x.fam = fam
	} else if x.fam != "" {
		x.plain = false // a family without an address: not a spec
	}
	switch action {
	case "accept":
		x.r.Action, x.decides = "allow", true
		if limited {
			x.r.Action = "limit"
		}
	case "reject":
		x.r.Action, x.decides = "reject", true
	case "drop":
		x.r.Action, x.decides = "deny", true
	default:
		x.plain = false
	}
	x.plain = x.plain && x.prio == 0 && !x.r.Dst.IsValid() && !x.r.partial
	return x, true
}

// spec is the rule as ufw words, in the extended form, so it reads back
// as a rich rule; nil when the rule is not one the agent could write.
func (x fwdRich) spec() []string {
	if !x.plain || !x.decides {
		return nil
	}
	from := "any"
	if x.r.From.IsValid() {
		from = prefixArg(x.r.From)
	}
	spec := []string{x.r.Action, "from", from}
	if len(x.r.Ports) > 0 {
		spec = append(spec, "to", "any", "port", portLabel(fwRule{Ports: x.r.Ports}), "proto", x.r.Proto)
	}
	return spec
}

// specs are the rules the agent can delete by spec: tcp and udp ports,
// services, and rich rules within what it writes.
func (z fwdZone) specs() [][]string {
	var specs [][]string
	for _, p := range z.Ports {
		if r, ok := fwdPort(p); ok && (r.Proto == "tcp" || r.Proto == "udp") {
			specs = append(specs, []string{"allow", portLabel(r)})
		}
	}
	for _, s := range z.Services {
		if fwdNamePattern.MatchString(s) {
			specs = append(specs, []string{"allow", s})
		}
	}
	for _, text := range z.Rich {
		if x, ok := parseRich(text); ok {
			if spec := x.spec(); spec != nil {
				specs = append(specs, spec)
			}
		}
	}
	return specs
}

// richRule writes rule r for one port range and protocol, from its
// parsed values only. A rule without an address has no family, so it
// holds for IPv4 and IPv6.
func richRule(r fwRule, p portRange, proto string) string {
	var b strings.Builder
	b.WriteString("rule")
	if r.From.IsValid() {
		family := "ipv4"
		if r.From.Addr().Is6() {
			family = "ipv6"
		}
		fmt.Fprintf(&b, ` family="%s" source address="%s"`, family, prefixArg(r.From))
	}
	if p.Lo != 0 {
		fmt.Fprintf(&b, ` port port="%s" protocol="%s"`, fwdPortArg(p), proto)
	}
	b.WriteString(" " + map[string]string{"allow": "accept", "deny": "drop", "reject": "reject"}[r.Action])
	return b.String()
}

// fwdArgs is the firewall-cmd arguments that make change c, one per
// command, zone aside. They are built from the values specRule parsed,
// never from the spec's own words. A spec in ufw's simple form that
// allows ports is a port entry, an app is a service, anything else a
// rich rule; ufw's "both protocols" is a tcp and a udp entry.
func fwdArgs(c fwChange) ([]string, error) {
	r, _, ok := specRule(c.Spec)
	if !ok {
		return nil, fmt.Errorf("firewalld cannot take the rule %q", specText(c.Spec))
	}
	verb := "--add-"
	if c.Op == opDelete {
		verb = "--remove-"
	}
	switch {
	case r.Dir != "in":
		return nil, errors.New("outgoing rules are not managed on firewalld")
	case r.Iface != "" || r.Dst.IsValid() || r.partial:
		return nil, errors.New("rules bound to an interface, a destination or a source port are not managed on firewalld")
	case r.Action == "limit":
		return nil, errors.New("rate limiting (limit) is not offered on firewalld")
	case r.App != "":
		if r.Action != "allow" || r.From.IsValid() || !fwdNamePattern.MatchString(r.App) {
			return nil, fmt.Errorf("firewalld cannot take the rule %q", specText(c.Spec))
		}
		return []string{verb + "service=" + r.App}, nil
	case r.Proto != "" && len(r.Ports) == 0:
		return nil, errors.New("a protocol without a port is not managed on firewalld")
	}
	simple := !slices.Contains(c.Spec, "from") && !slices.Contains(c.Spec, "to")
	if simple && r.Action == "allow" && len(r.Ports) == 0 {
		return nil, errors.New("firewalld opens ports one by one; name a port")
	}
	protos := []string{r.Proto}
	if r.Proto == "" && len(r.Ports) > 0 {
		protos = []string{"tcp", "udp"}
	}
	ports := r.Ports
	if len(ports) == 0 {
		ports = []portRange{{}}
	}
	var out []string
	for _, proto := range protos {
		for _, p := range ports {
			if simple && r.Action == "allow" {
				out = append(out, verb+"port="+fwdPortArg(p)+"/"+proto)
			} else {
				out = append(out, verb+"rich-rule="+richRule(r, p, proto))
			}
		}
	}
	return out, nil
}

// fwdInverse is the argument that undoes arg: add for remove and back.
func fwdInverse(arg string) string {
	if rest, ok := strings.CutPrefix(arg, "--add-"); ok {
		return "--remove-" + rest
	}
	return "--add-" + strings.TrimPrefix(arg, "--remove-")
}

// firewalldRunning reports whether firewalld runs, and the binary that
// said so.
func firewalldRunning(ctx context.Context, run services.Runner) (string, bool) {
	for _, bin := range firewalldPaths {
		out, err := run.Run(ctx, bin, "--state")
		if notFound(err) {
			continue
		}
		return bin, fwdRunning(out, err)
	}
	return "", false
}

// fwdRunning reads `firewall-cmd --state`: "running", or "not running"
// with a non-zero exit.
func fwdRunning(out string, err error) bool {
	if err != nil {
		return false
	}
	for _, line := range strings.Split(out, "\n") {
		if strings.TrimSpace(line) == "running" {
			return true
		}
	}
	return false
}

// firewalldBackend is firewalld, through firewall-cmd, on one zone.
type firewalldBackend struct {
	run  services.Runner
	bin  string // resolved on first use
	zone string // the default zone; resolved on first use
	note string // what the last Restore has to tell
}

func (b *firewalldBackend) Name() string            { return fwKindFirewalld }
func (b *firewalldBackend) ident() (string, string) { return b.bin, b.zone }
func (b *firewalldBackend) zoneArg() string         { return "--zone=" + b.zone }

func (b *firewalldBackend) takeNote() string {
	n := b.note
	b.note = ""
	return n
}

// cmd runs one firewall-cmd command with the resolved binary.
func (b *firewalldBackend) cmd(ctx context.Context, args ...string) *cmdTrace {
	if b.bin == "" {
		b.bin = firewalldPaths[0]
		for _, bin := range firewalldPaths {
			if _, err := b.run.Run(ctx, bin, "--version"); !notFound(err) {
				b.bin = bin
				break
			}
		}
	}
	t := &cmdTrace{argv: append([]string{b.bin}, args...)}
	start := time.Now()
	t.out, t.err = b.run.Run(ctx, b.bin, args...)
	t.dur = time.Since(start)
	return t
}

// ensureZone resolves the default zone, which every change names.
func (b *firewalldBackend) ensureZone(ctx context.Context) *cmdTrace {
	if b.zone != "" {
		if !fwdNamePattern.MatchString(b.zone) {
			return &cmdTrace{err: fmt.Errorf("invalid firewalld zone %q", b.zone)}
		}
		return nil
	}
	t := b.cmd(ctx, "--get-default-zone")
	if t.err != nil {
		return t
	}
	f := strings.Fields(t.out)
	if len(f) == 0 || !fwdNamePattern.MatchString(f[len(f)-1]) {
		t.err = errors.New("unreadable default zone")
		return t
	}
	b.zone = f[len(f)-1]
	return nil
}

// readZone lists the zone; services also reads each service's ports,
// which only the rule model needs.
func (b *firewalldBackend) readZone(ctx context.Context, services bool) (fwdZone, *cmdTrace) {
	if t := b.ensureZone(ctx); t != nil {
		return fwdZone{}, t
	}
	t := b.cmd(ctx, b.zoneArg(), "--list-all")
	if t.err != nil {
		return fwdZone{}, t
	}
	z, ok := parseFwdZone(t.out, b.zone)
	if !ok {
		return fwdZone{}, &cmdTrace{argv: t.argv, out: t.out, err: errFwdUnparsed}
	}
	if services {
		var names []string
		for _, text := range z.Rich {
			if x, ok := parseRich(text); ok && x.service != "" {
				names = append(names, x.service)
			}
		}
		z.SvcPorts = map[string][]string{}
		for _, s := range append(names, z.Services...) {
			if _, done := z.SvcPorts[s]; done || !fwdNamePattern.MatchString(s) {
				continue
			}
			if it := b.cmd(ctx, "--info-service="+s); it.err == nil {
				z.SvcPorts[s] = parseFwdService(it.out)
			}
		}
	}
	return z, t
}

// errFwdUnparsed: --list-all answered with something unreadable.
var errFwdUnparsed = errors.New("unreadable zone listing")

// parseFwdService reads the ports and protocols of `--info-service`.
func parseFwdService(out string) []string {
	var entries []string
	for _, line := range strings.Split(out, "\n") {
		k, v, ok := strings.Cut(strings.TrimSpace(line), ":")
		if ok && (k == "ports" || k == "protocols") {
			entries = append(entries, strings.Fields(v)...)
		}
	}
	return entries
}

func (b *firewalldBackend) Probe(ctx context.Context) ufwProbe {
	st := b.cmd(ctx, "--state")
	p := ufwProbe{bin: b.bin, out: st.out}
	switch {
	case notFound(st.err):
		p.state, p.err = fwMissing, st.err
		return p
	case !fwdRunning(st.out, st.err):
		p.state, p.err = fwInactive, st.err
		return p
	}
	z, t := b.readZone(ctx, true)
	p.out, p.err = t.out, t.err
	switch {
	case errors.Is(t.err, errFwdUnparsed):
		p.state, p.err = fwUnparsed, nil
	case t.err != nil:
		p.state = fwUnusable
	default:
		p.fw = z.status()
		p.state = p.fw.verdict(22, false, netip.Addr{}).state
	}
	return p
}

func (b *firewalldBackend) Added(ctx context.Context) ([][]string, *cmdTrace) {
	z, t := b.readZone(ctx, false)
	if t.err != nil {
		return nil, t
	}
	return z.specs(), nil
}

func (b *firewalldBackend) Snapshot(ctx context.Context, dir string) (fwSnap, error) {
	z, t := b.readZone(ctx, true)
	if t.err != nil {
		return fwSnap{}, fmt.Errorf("firewall-cmd --list-all: %s", detail(t.out, t.err))
	}
	data, err := json.Marshal(z)
	if err != nil {
		return fwSnap{}, err
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fwSnap{}, err
	}
	if err := sshwatch.WriteStateFile(filepath.Join(dir, fwdZoneFile), data); err != nil {
		return fwSnap{}, err
	}
	if err := sshwatch.WriteStateFile(filepath.Join(dir, snapStatusFile), []byte(t.out)); err != nil {
		return fwSnap{}, err
	}
	return fwSnap{Status: t.out, SHA: z.sha(), fw: z.status(), zone: &z}, nil
}

func (b *firewalldBackend) Load(dir string) (fwSnap, error) {
	data, err := os.ReadFile(filepath.Join(dir, fwdZoneFile))
	if err != nil {
		return fwSnap{}, err
	}
	var z fwdZone
	if err := json.Unmarshal(data, &z); err != nil {
		return fwSnap{}, fmt.Errorf("%s: %w", fwdZoneFile, err)
	}
	status, _ := os.ReadFile(filepath.Join(dir, snapStatusFile))
	return fwSnap{Status: string(status), SHA: z.sha(), fw: z.status(), zone: &z}, nil
}

func (b *firewalldBackend) Hash(ctx context.Context) (string, error) {
	z, t := b.readZone(ctx, false)
	if t.err != nil {
		return "", errFwCmd{t}
	}
	return z.sha(), nil
}

// Commands is the firewall-cmd command of each change. Keep runs the
// same with --permanent.
func (b *firewalldBackend) Commands(p fwPlan) ([]string, error) {
	args, err := fwdPlanArgs(p)
	if err != nil {
		return nil, err
	}
	zone := b.zone
	if zone == "" {
		zone = "<default zone>"
	}
	var lines []string
	for _, a := range args {
		lines = append(lines, "firewall-cmd "+specText([]string{"--zone=" + zone, a}))
	}
	return append(lines, "Keep: the same with --permanent"), nil
}

// fwdPlanArgs is the argument of every command p runs, in order; none
// when any change is one firewalld cannot take, so nothing half runs.
func fwdPlanArgs(p fwPlan) ([]string, error) {
	var all []string
	for _, c := range p {
		args, err := fwdArgs(c)
		if err != nil {
			return nil, err
		}
		all = append(all, args...)
	}
	return all, nil
}

// Apply changes the runtime configuration only.
func (b *firewalldBackend) Apply(ctx context.Context, p fwPlan) (*cmdTrace, error) {
	args, err := fwdPlanArgs(p)
	if err != nil {
		return nil, err
	}
	if t := b.ensureZone(ctx); t != nil {
		return t, errFwCmd{t}
	}
	var last *cmdTrace
	for _, a := range args {
		if last = b.cmd(ctx, b.zoneArg(), a); last.err != nil {
			return last, errFwCmd{last}
		}
	}
	return last, nil
}

// Revert runs the inverse runtime operations, best effort: removing a
// rule someone already removed is not worth stopping for.
func (b *firewalldBackend) Revert(ctx context.Context, p fwPlan) error {
	if t := b.ensureZone(ctx); t != nil {
		return errFwCmd{t}
	}
	for _, c := range p.inverse() {
		args, err := fwdArgs(c)
		if err != nil {
			continue
		}
		for _, a := range args {
			b.cmd(ctx, b.zoneArg(), a)
		}
	}
	return nil
}

// Commit re-runs p's changes with --permanent. A failure takes back the
// permanent changes already made, so a later reload or reboot cannot
// bring back half a plan.
func (b *firewalldBackend) Commit(ctx context.Context, p fwPlan) error {
	args, err := fwdPlanArgs(p)
	if err != nil {
		return err
	}
	if t := b.ensureZone(ctx); t != nil {
		return errFwCmd{t}
	}
	for i, a := range args {
		if t := b.cmd(ctx, "--permanent", b.zoneArg(), a); t.err != nil {
			for j := i - 1; j >= 0; j-- {
				b.cmd(ctx, "--permanent", b.zoneArg(), fwdInverse(args[j]))
			}
			return errFwCmd{t}
		}
	}
	return nil
}

// Restore undoes, one runtime operation each, every difference between
// the zone now and the snapshot. The values are firewalld's own listing,
// each checked against its form. When that does not bring the zone back
// (a changed target cannot be undone at runtime), it reloads the
// permanent configuration, which no trial changed, and says what that
// cost.
func (b *firewalldBackend) Restore(ctx context.Context, s fwSnap) error {
	if s.zone == nil {
		return errors.New("the snapshot holds no firewalld zone")
	}
	b.zone = s.zone.Name
	cur, t := b.readZone(ctx, false)
	if t.err == nil && cur.Target == s.zone.Target {
		for _, arg := range zoneDiff(cur, *s.zone) {
			b.cmd(ctx, b.zoneArg(), arg)
		}
		if h, err := b.Hash(ctx); err == nil && h == s.SHA {
			return nil
		}
	}
	if t := b.cmd(ctx, "--reload"); t.err != nil {
		return errFwCmd{t}
	}
	b.note = "⚠️ Undoing the changes one by one did not bring the rules back, so firewalld was reloaded " +
		"from its permanent configuration. A reload also drops runtime-only rules other tools added " +
		"(fail2ban bans, Docker's rules on some versions)."
	return nil
}

// zoneDiff is the arguments that turn zone cur into want: removals
// first, then additions. An entry not in its listed form is left out, so
// the hash check after it fails instead.
func zoneDiff(cur, want fwdZone) []string {
	kinds := []struct {
		name      string
		cur, want []string
		ok        func(string) bool
	}{
		{"port", cur.Ports, want.Ports, fwdPortPattern.MatchString},
		{"source-port", cur.SourcePorts, want.SourcePorts, fwdPortPattern.MatchString},
		{"service", cur.Services, want.Services, fwdNamePattern.MatchString},
		{"protocol", cur.Protocols, want.Protocols, fwdNamePattern.MatchString},
		{"rich-rule", cur.Rich, want.Rich, func(s string) bool {
			return strings.HasPrefix(s, "rule ") && !strings.ContainsFunc(s, func(r rune) bool { return r < ' ' })
		}},
	}
	var remove, add []string
	for _, k := range kinds {
		for _, s := range k.cur {
			if !slices.Contains(k.want, s) && k.ok(s) {
				remove = append(remove, "--remove-"+k.name+"="+s)
			}
		}
		for _, s := range k.want {
			if !slices.Contains(k.cur, s) && k.ok(s) {
				add = append(add, "--add-"+k.name+"="+s)
			}
		}
	}
	return append(remove, add...)
}
