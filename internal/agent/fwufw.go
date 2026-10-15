package agent

import (
	"context"
	"net/netip"
	"slices"
	"strconv"
	"strings"
)

// ufw rule model and first-match evaluation. The old summary scanned for
// "22" rows and let any DENY win, so a host with `OpenSSH ALLOW` first and
// `22/tcp DENY` appended after it was reported closed while SSH stayed
// reachable. ufw checks its user rules top to bottom and the first match
// decides; the default incoming policy applies only when none matches.
// Everything here is pure so it can be pinned with real ufw output.

// portRange is an inclusive port span; a single port has Lo == Hi.
type portRange struct{ Lo, Hi int }

// fwRule is one row of `ufw status [verbose]`.
type fwRule struct {
	Num    int          // position in the listing, as `ufw status numbered` counts
	Action string       // allow|deny|reject|limit
	Dir    string       // in|out|fwd
	Proto  string       // tcp|udp|"" (any)
	Ports  []portRange  // empty = any port
	From   netip.Prefix // zero = Anywhere
	Dst    netip.Prefix // zero = any local address
	Iface  string       // "on eth0"; empty = every interface
	App    string       // "OpenSSH"; ports are known only when Ports is set
	V6     bool
	Raw    string // the row as ufw printed it, for display

	// unresolved: an app profile without ports (plain `ufw status` does not
	// expand them), so whether it matches a port is unknown.
	unresolved bool
	// partial: a qualifier the model does not represent (a source port, an
	// unreadable address), so the rule matches only some traffic.
	partial bool
}

// ufwStatus is the parsed text of `ufw status` or `ufw status verbose`.
type ufwStatus struct {
	found  bool   // a "Status:" line was present
	active bool   // "Status: active"
	policy string // default incoming policy (verbose only); "" = unknown
	rules  []fwRule
}

// parseUFWOutput reads `ufw status`, `status numbered` or `status verbose`
// output. The status line is located rather than assumed to be first, for
// the reason given on parseUFWStatus.
func parseUFWOutput(out string) ufwStatus {
	var s ufwStatus
	lines := strings.Split(out, "\n")
	head := -1
	for i, line := range lines {
		if strings.Contains(strings.ToLower(line), "status:") {
			head = i
			break
		}
	}
	if head < 0 {
		return s
	}
	s.found = true
	s.active = strings.Contains(strings.ToLower(lines[head]), "status: active")
	if !s.active {
		return s
	}
	for _, line := range lines[head+1:] {
		if rest, ok := strings.CutPrefix(strings.TrimSpace(line), "Default:"); ok {
			s.policy = parseDefaultPolicy(rest)
			continue
		}
		if r, ok := parseUFWRow(line); ok {
			r.Num = len(s.rules) + 1
			s.rules = append(s.rules, r)
		}
	}
	return s
}

// parseDefaultPolicy extracts the incoming policy from the tail of
// "Default: deny (incoming), allow (outgoing), disabled (routed)".
func parseDefaultPolicy(s string) string {
	for _, part := range strings.Split(s, ",") {
		if f := strings.Fields(part); len(f) == 2 && f[1] == "(incoming)" {
			return strings.ToLower(f[0])
		}
	}
	return ""
}

// parseUFWRow parses one rule row. Actions are matched in upper case only,
// as ufw prints them, so "Default: deny (incoming)" and the column header
// can never be read as rules.
func parseUFWRow(line string) (fwRule, bool) {
	line = strings.TrimSpace(line)
	if i := strings.Index(line, " # "); i >= 0 {
		line = strings.TrimSpace(line[:i]) // ufw rule comment
	}
	if strings.HasPrefix(line, "[") { // `status numbered` index
		if i := strings.Index(line, "]"); i > 0 {
			line = strings.TrimSpace(line[i+1:])
		}
	}
	f := strings.Fields(line)
	act := -1
	for i, w := range f {
		if w == "ALLOW" || w == "DENY" || w == "REJECT" || w == "LIMIT" {
			act = i
			break
		}
	}
	if act < 1 {
		return fwRule{}, false
	}
	r := fwRule{Action: strings.ToLower(f[act]), Dir: "in", Raw: strings.Join(f, " ")}
	from := f[act+1:]
	if len(from) > 0 && (from[0] == "IN" || from[0] == "OUT" || from[0] == "FWD") {
		r.Dir = strings.ToLower(from[0])
		from = from[1:]
	}
	if len(from) == 0 {
		return fwRule{}, false
	}
	parseRuleTo(&r, strings.Join(f[:act], " "))
	parseRuleFrom(&r, from)
	return r, true
}

// parseRuleTo reads the "To" column: "22/tcp", "22", "80,443/tcp",
// "Anywhere", "10.0.0.5 22/tcp", "22/tcp on eth0", "OpenSSH" (plain), or
// "22/tcp (OpenSSH)" (verbose), any of them with a "(v6)" marker.
func parseRuleTo(r *fwRule, s string) {
	if strings.Contains(s, "(v6)") {
		r.V6 = true
		s = strings.ReplaceAll(s, "(v6)", "")
	}
	if i, j := strings.Index(s, "("), strings.LastIndex(s, ")"); i >= 0 && j > i {
		r.App = strings.TrimSpace(s[i+1 : j])
		s = s[:i] + " " + s[j+1:]
	}
	if i := strings.Index(s, " on "); i >= 0 {
		r.Iface = strings.TrimSpace(s[i+4:])
		s = s[:i]
	}
	f := strings.Fields(s)
	switch {
	case len(f) == 1 && f[0] == "Anywhere":
		return
	case len(f) == 1 && parsePortSpec(r, f[0]):
		return
	case len(f) == 1 && parseAnyProto(r, f[0]):
		return
	case len(f) == 1:
		if p, ok := parseFwAddr(f[0]); ok {
			r.Dst = p
			r.V6 = r.V6 || p.Addr().Is6()
			return
		}
	case len(f) == 2:
		if p, ok := parseFwAddr(f[0]); ok && parsePortSpec(r, f[1]) {
			r.Dst = p
			r.V6 = r.V6 || p.Addr().Is6()
			return
		}
	}
	// Anything else is an app profile name ("OpenSSH", "Nginx Full") whose
	// ports plain `ufw status` does not show.
	r.App = strings.TrimSpace(strings.Join(f, " "))
	r.unresolved = true
}

// parseRuleFrom reads the "From" column: "Anywhere", an address or CIDR,
// optionally followed by a source port, with an optional "(v6)" marker.
func parseRuleFrom(r *fwRule, f []string) {
	f = slices.DeleteFunc(slices.Clone(f), func(w string) bool {
		if w == "(v6)" {
			r.V6 = true
			return true
		}
		return false
	})
	if len(f) == 0 {
		return
	}
	if len(f) > 1 {
		r.partial = true // source port or app: narrower than the model says
	}
	if f[0] == "Anywhere" {
		return
	}
	p, ok := parseFwAddr(f[0])
	if !ok {
		r.partial = true
		return
	}
	r.From = p
	r.V6 = r.V6 || p.Addr().Is6()
}

// parseFwAddr parses an address or CIDR as ufw prints it.
func parseFwAddr(s string) (netip.Prefix, bool) {
	if p, err := netip.ParsePrefix(s); err == nil {
		return p.Masked(), true
	}
	if a, err := netip.ParseAddr(s); err == nil {
		a = a.Unmap()
		return netip.PrefixFrom(a, a.BitLen()), true
	}
	return netip.Prefix{}, false
}

// parsePortSpec parses "22", "22/tcp", "80,443/tcp" or "6000:6007/udp".
func parsePortSpec(r *fwRule, s string) bool {
	list, proto, _ := strings.Cut(s, "/")
	if proto != "" && proto != "tcp" && proto != "udp" {
		return false
	}
	var ports []portRange
	for _, item := range strings.Split(list, ",") {
		lo, hi, isRange := strings.Cut(item, ":")
		if !isRange {
			hi = lo
		}
		a, err1 := strconv.Atoi(lo)
		b, err2 := strconv.Atoi(hi)
		if err1 != nil || err2 != nil || a < 1 || b > 65535 || a > b {
			return false
		}
		ports = append(ports, portRange{a, b})
	}
	r.Ports, r.Proto = ports, proto
	return true
}

// parseAnyProto parses "Anywhere/udp": every port of one protocol.
func parseAnyProto(r *fwRule, s string) bool {
	proto, ok := strings.CutPrefix(s, "Anywhere/")
	if !ok {
		return false
	}
	r.Proto = proto
	return true
}

// portVerdict is the effective first-match state of one port.
type portVerdict struct {
	state  sshPortState // fwOpen, fwClosed, or fwUnmanaged (no rule matched)
	rule   *fwRule      // the deciding rule; nil when the default policy decides
	policy string       // default incoming policy when known
	// except are narrower ALLOW/LIMIT rules (source, interface or address
	// restricted) checked before the decision: the port is open to those.
	except []fwRule
	// unsure are app profiles checked before the decision whose ports are
	// unknown, so they might have decided first.
	unsure []fwRule
}

// verdict evaluates first-match for incoming TCP to port in one address
// family. peer narrows the evaluation to one client; the zero Addr stands
// for an arbitrary host, for which restricted rules never decide.
func (s ufwStatus) verdict(port int, v6 bool, peer netip.Addr) portVerdict {
	v := portVerdict{state: fwUnmanaged, policy: s.policy}
	peer = peer.Unmap()
	for i := range s.rules {
		r := &s.rules[i]
		if r.Dir != "in" || r.V6 != v6 || (r.Proto != "" && r.Proto != "tcp") {
			continue
		}
		if r.unresolved {
			v.unsure = append(v.unsure, *r)
			continue
		}
		if !r.coversPort(port) {
			continue
		}
		if r.From.IsValid() && peer.IsValid() && !r.From.Contains(peer) {
			continue // not this peer's rule at all
		}
		restricted := r.partial || r.Iface != "" || r.Dst.IsValid() || (r.From.IsValid() && !peer.IsValid())
		if restricted {
			if r.Action == "allow" || r.Action == "limit" {
				v.except = append(v.except, *r)
			}
			continue
		}
		v.rule = r
		if r.Action == "allow" || r.Action == "limit" {
			v.state = fwOpen
		} else {
			v.state = fwClosed
		}
		return v
	}
	return v
}

// coversPort reports whether the rule's port list includes port.
func (r *fwRule) coversPort(port int) bool {
	if len(r.Ports) == 0 {
		return true
	}
	for _, p := range r.Ports {
		if port >= p.Lo && port <= p.Hi {
			return true
		}
	}
	return false
}

// hasV6 reports whether any rule belongs to the IPv6 table. With none, an
// IPv6 verdict is only the default policy and says nothing new.
func (s ufwStatus) hasV6() bool {
	return slices.ContainsFunc(s.rules, func(r fwRule) bool { return r.V6 })
}

// sshPorts detects the TCP ports sshd accepts connections on: the union of
// `sshd -T`, an active ssh/sshd socket unit, sshd's own listeners in `ss`,
// and sshd_config. Every probe is optional; when none answers the result
// is the default port 22.
func (a *Agent) sshPorts(ctx context.Context) []int {
	var ports []int
	if a.src.Runner != nil {
		for _, bin := range []string{"sshd", "/usr/sbin/sshd"} {
			out, err := a.src.Runner.Run(ctx, bin, "-T")
			if err == nil {
				ports = append(ports, parseSSHDTPorts(out)...)
				break
			}
			if !notFound(err) {
				break
			}
		}
		if out, err := a.src.Runner.Run(ctx, "systemctl", "show",
			"--property=Listen,ActiveState", "ssh.socket", "sshd.socket"); err == nil {
			ports = append(ports, parseSocketListen(out)...)
		}
		if out, err := a.src.Runner.Run(ctx, "ss", "-Htlnp"); err == nil {
			ports = append(ports, parseSSListen(out)...)
		}
	}
	if a.src.SSHDConfig != nil {
		ports = append(ports, parseSSHDConfigPorts(a.src.SSHDConfig())...)
	}
	if len(ports) == 0 {
		return []int{22}
	}
	slices.Sort(ports)
	return slices.Compact(ports)
}

// parseSSHDTPorts reads the "port N" lines of `sshd -T`.
func parseSSHDTPorts(out string) []int {
	var ports []int
	for _, line := range strings.Split(out, "\n") {
		if f := strings.Fields(line); len(f) == 2 && f[0] == "port" {
			if p, ok := validPort(f[1]); ok {
				ports = append(ports, p)
			}
		}
	}
	return ports
}

// parseSocketListen reads `systemctl show --property=Listen,ActiveState`
// for several units. Only an active socket counts: a disabled ssh.socket
// still carries its Listen= setting.
func parseSocketListen(out string) []int {
	var ports, pending []int
	active := false
	flush := func() {
		if active {
			ports = append(ports, pending...)
		}
		pending, active = nil, false
	}
	for _, line := range strings.Split(out, "\n") {
		line = strings.TrimSpace(line)
		switch {
		case line == "":
			flush()
		case line == "ActiveState=active":
			active = true
		case strings.HasPrefix(line, "Listen="):
			addr, _, _ := strings.Cut(strings.TrimPrefix(line, "Listen="), " ")
			if p, ok := validPort(addr[strings.LastIndex(addr, ":")+1:]); ok {
				pending = append(pending, p)
			}
		}
	}
	flush()
	return ports
}

// parseSSListen reads `ss -Htlnp` rows owned by sshd.
func parseSSListen(out string) []int {
	var ports []int
	for _, line := range strings.Split(out, "\n") {
		f := strings.Fields(line)
		if len(f) < 6 || !strings.Contains(line, `"sshd",`) {
			continue
		}
		local := f[3]
		if p, ok := validPort(local[strings.LastIndex(local, ":")+1:]); ok {
			ports = append(ports, p)
		}
	}
	return ports
}

// parseSSHDConfigPorts reads Port directives from sshd_config text.
func parseSSHDConfigPorts(text string) []int {
	var ports []int
	for _, line := range strings.Split(text, "\n") {
		f := strings.Fields(line)
		if len(f) >= 2 && strings.EqualFold(f[0], "port") {
			if p, ok := validPort(f[1]); ok {
				ports = append(ports, p)
			}
		}
	}
	return ports
}

// validPort parses a TCP port number in 1–65535.
func validPort(s string) (int, bool) {
	p, err := strconv.Atoi(s)
	return p, err == nil && p >= 1 && p <= 65535
}
