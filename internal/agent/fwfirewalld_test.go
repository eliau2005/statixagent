package agent

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"os/exec"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/eliau2005/statixagent/internal/tgui"
)

// A `firewall-cmd --list-all` as firewalld 1.3 prints it, after a
// warning the runner merged in from stderr.
const fwdListAll = `Warning: ALREADY_ENABLED: ssh
public (active)
  target: default
  icmp-block-inversion: no
  interfaces: eth0
  sources:
  services: dhcpv6-client ssh
  ports: 8080/tcp 6000-6007/udp
  protocols:
  forward: yes
  masquerade: no
  forward-ports:
  source-ports:
  icmp-blocks:
  rich rules:
	rule family="ipv4" source address="198.51.100.0/24" drop
	rule family="ipv4" source address="10.0.0.0/8" port port="5432" protocol="tcp" accept
	rule priority="-5" family="ipv6" source address="2001:db8::/32" accept
	rule family="ipv4" source address="192.0.2.9" log prefix="ssh: <&>" level="info" limit value="1/m"
	rule service name="http" accept limit value="10/m"
`

const fwdInfoSSH = `ssh
  ports: 22/tcp
  protocols:
  source-ports:
  modules:
  destination:
  includes:
  helpers:
`

func TestParseFwdZone(t *testing.T) {
	z, ok := parseFwdZone(fwdListAll, "public")
	if !ok {
		t.Fatal("not parsed")
	}
	if z.Target != "default" || !slices.Equal(z.Services, []string{"dhcpv6-client", "ssh"}) ||
		!slices.Equal(z.Ports, []string{"8080/tcp", "6000-6007/udp"}) || len(z.Rich) != 5 ||
		z.Rich[1] != `rule family="ipv4" source address="10.0.0.0/8" port port="5432" protocol="tcp" accept` {
		t.Errorf("zone = %+v", z)
	}
	if _, ok := parseFwdZone(fwdListAll, "home"); ok {
		t.Error("another zone's name matched")
	}
	if _, ok := parseFwdZone("FirewallD is not running", "public"); ok {
		t.Error("an error parsed as a zone")
	}
	// The hash ignores the order firewalld happens to list things in,
	// and where the zone applies; it sees what the zone allows.
	moved := strings.NewReplacer("dhcpv6-client ssh", "ssh dhcpv6-client", "interfaces: eth0", "interfaces: eth1").Replace(fwdListAll)
	z2, _ := parseFwdZone(moved, "public")
	if z.sha() != z2.sha() {
		t.Error("hash depends on listing order or interfaces")
	}
	z2.Ports = append(z2.Ports, "9000/tcp")
	if z.sha() == z2.sha() {
		t.Error("hash misses a port")
	}
	if got := parseFwdService(fwdInfoSSH); !slices.Equal(got, []string{"22/tcp"}) {
		t.Errorf("service ports = %q", got)
	}
}

func TestParseRich(t *testing.T) {
	for _, tc := range []struct {
		rule    string
		action  string // "" when the rule decides nothing
		fam     string
		spec    string // "" when it has none
		partial bool
	}{
		{`rule family="ipv4" source address="10.0.0.0/8" port port="5432" protocol="tcp" accept`, "allow", "v4",
			"allow from 10.0.0.0/8 to any port 5432 proto tcp", false},
		{`rule family="ipv4" source address="198.51.100.7" drop`, "deny", "v4", "deny from 198.51.100.7", false},
		{`rule family="ipv6" source address="2001:db8::/32" reject type="icmp6-adm-prohibited"`, "reject", "v6",
			"", false}, // reject with a type: not something the agent writes
		{`rule port port="22" protocol="tcp" drop`, "deny", "", "deny from any to any port 22 proto tcp", false},
		{`rule port port="6000-6007" protocol="udp" accept`, "allow", "", "allow from any to any port 6000:6007 proto udp", false},
		{`rule family="ipv4" port port="22" protocol="tcp" accept`, "allow", "v4", "", false},
		{`rule priority="-1" family="ipv4" source address="10.0.0.1" accept`, "allow", "v4", "", false},
		{`rule family="ipv4" source not address="10.0.0.0/8" drop`, "deny", "v4", "", true},
		{`rule family="ipv4" source ipset="blocklist" drop`, "deny", "v4", "", true},
		{`rule family="ipv4" source address="192.0.2.9" log prefix="ssh: a b" level="info"`, "", "v4", "", false},
		{`rule service name="ssh" accept limit value="3/m"`, "limit", "", "", false},
		{`rule protocol value="gre" accept`, "allow", "", "", false},
		{`rule icmp-block name="echo-request"`, "", "", "", false},
		{`rule forward-port port="80" protocol="tcp" to-port="8080"`, "", "", "", false},
	} {
		x, ok := parseRich(tc.rule)
		if !ok {
			t.Errorf("%s: not parsed", tc.rule)
			continue
		}
		action := ""
		if x.decides {
			action = x.r.Action
		}
		if action != tc.action || x.fam != tc.fam || strings.Join(x.spec(), " ") != tc.spec || x.r.partial != tc.partial {
			t.Errorf("%s:\n got %q %q %q %v\nwant %q %q %q %v", tc.rule, action, x.fam, strings.Join(x.spec(), " "), x.r.partial,
				tc.action, tc.fam, tc.spec, tc.partial)
		}
	}
	for _, bad := range []string{"", "accept", `rule family="ipv6" source address="10.0.0.1" accept`, `rule priority="x" accept`} {
		if _, ok := parseRich(bad); ok {
			t.Errorf("%q parsed", bad)
		}
	}
}

// fwdTestZone is fwdListAll with the services' ports known.
func fwdTestZone(t *testing.T) fwdZone {
	t.Helper()
	z, ok := parseFwdZone(fwdListAll, "public")
	if !ok {
		t.Fatal("not parsed")
	}
	z.SvcPorts = map[string][]string{"ssh": {"22/tcp"}, "dhcpv6-client": {"546/udp"}, "http": {"80/tcp"}}
	return z
}

func TestFwdZoneStatus(t *testing.T) {
	z := fwdTestZone(t)
	st := z.status()
	var rows []string
	for _, r := range st.rules {
		rows = append(rows, fmt.Sprintf("%d %s", r.Num, r.Raw))
	}
	// firewalld's order: negative priority, deny, allow; IPv4, then IPv6.
	want := []string{
		"1 Anywhere DENY IN 198.51.100.0/24 · rich rule",
		"2 8080/tcp ALLOW IN Anywhere · port",
		"3 6000:6007/udp ALLOW IN Anywhere · port",
		"4 546/udp ALLOW IN Anywhere · service dhcpv6-client",
		"5 22/tcp ALLOW IN Anywhere · service ssh",
		"6 5432/tcp ALLOW IN 10.0.0.0/8 · rich rule",
		"7 80/tcp LIMIT IN Anywhere · rich rule http",
		"8 Anywhere (v6) ALLOW IN 2001:db8::/32 · rich rule",
		"9 8080/tcp (v6) ALLOW IN Anywhere (v6) · port",
		"10 6000:6007/udp (v6) ALLOW IN Anywhere (v6) · port",
		"11 546/udp (v6) ALLOW IN Anywhere (v6) · service dhcpv6-client",
		"12 22/tcp (v6) ALLOW IN Anywhere (v6) · service ssh",
		"13 80/tcp (v6) LIMIT IN Anywhere (v6) · rich rule http",
	}
	if !slices.Equal(rows, want) || st.policy != "reject" {
		t.Errorf("rows:\n%s\npolicy %q", strings.Join(rows, "\n"), st.policy)
	}
	for _, tc := range []struct {
		peer string
		want sshPortState
	}{
		{"203.0.113.4", fwOpen},
		{"198.51.100.7", fwClosed}, // the drop is checked before the ssh service
		{"2001:db8::1", fwOpen},
	} {
		peer := netip.MustParseAddr(tc.peer)
		if v := st.verdict(22, peer.Is6(), peer); v.state != tc.want {
			t.Errorf("%s: %v, want %v", tc.peer, v.state, tc.want)
		}
	}
	// A service whose ports are unknown may match first.
	z.SvcPorts = nil
	if v := z.status().verdict(22, false, netip.Addr{}); len(v.unsure) == 0 {
		t.Errorf("unknown service ports not flagged: %+v", v)
	}
	// What the agent can delete by spec.
	var specs []string
	for _, s := range fwdTestZone(t).specs() {
		specs = append(specs, strings.Join(s, " "))
	}
	if want := []string{"allow 8080/tcp", "allow 6000:6007/udp", "allow dhcpv6-client", "allow ssh",
		"deny from 198.51.100.0/24", "allow from 10.0.0.0/8 to any port 5432 proto tcp"}; !slices.Equal(specs, want) {
		t.Errorf("specs = %q", specs)
	}
}

func TestFwdArgs(t *testing.T) {
	for _, tc := range []struct {
		op, spec string
		want     []string
		err      string
	}{
		{opAdd, "allow 8080/tcp", []string{"--add-port=8080/tcp"}, ""},
		{opAdd, "allow 8080", []string{"--add-port=8080/tcp", "--add-port=8080/udp"}, ""},
		{opAdd, "allow 6000:6007/udp", []string{"--add-port=6000-6007/udp"}, ""},
		{opAdd, "allow 80,443/tcp", []string{"--add-port=80/tcp", "--add-port=443/tcp"}, ""},
		{opDelete, "allow ssh", []string{"--remove-service=ssh"}, ""},
		// Closing SSH: a rich rule without an address holds for both families.
		{opInsert, "deny 22/tcp", []string{`--add-rich-rule=rule port port="22" protocol="tcp" drop`}, ""},
		{opInsert, "deny from 198.51.100.7", []string{`--add-rich-rule=rule family="ipv4" source address="198.51.100.7" drop`}, ""},
		{opPrepend, "deny from 2001:db8::/32 to any port 22 proto tcp",
			[]string{`--add-rich-rule=rule family="ipv6" source address="2001:db8::/32" port port="22" protocol="tcp" drop`}, ""},
		{opAdd, "allow from 10.0.0.0/8 to any port 5432 proto tcp",
			[]string{`--add-rich-rule=rule family="ipv4" source address="10.0.0.0/8" port port="5432" protocol="tcp" accept`}, ""},
		{opAdd, "reject from 10.0.0.0/8 to any port 5432",
			[]string{`--add-rich-rule=rule family="ipv4" source address="10.0.0.0/8" port port="5432" protocol="tcp" reject`,
				`--add-rich-rule=rule family="ipv4" source address="10.0.0.0/8" port port="5432" protocol="udp" reject`}, ""},
		{opDelete, "allow from any to any port 22 proto tcp", []string{`--remove-rich-rule=rule port port="22" protocol="tcp" accept`}, ""},
		{opAdd, "limit 22/tcp", nil, "rate limiting"},
		{opAdd, "allow out 22/tcp", nil, "outgoing"},
		{opAdd, "allow in on eth0 to any port 22", nil, "interface"},
		{opAdd, "deny OpenSSH", nil, "cannot take"},
		{opAdd, "allow from 10.0.0.0/8 proto tcp", nil, "protocol without a port"},
		{opAdd, "allow --remove-port", nil, "cannot take"},
	} {
		got, err := fwdArgs(fwChange{Op: tc.op, Spec: strings.Fields(tc.spec)})
		switch {
		case tc.err != "" && (err == nil || !strings.Contains(err.Error(), tc.err)):
			t.Errorf("%s %s: err %v, want %q", tc.op, tc.spec, err, tc.err)
		case tc.err == "" && (err != nil || !slices.Equal(got, tc.want)):
			t.Errorf("%s %s:\n got %q %v\nwant %q", tc.op, tc.spec, got, err, tc.want)
		}
	}
	// A comment's words never reach the rule: only the parsed values do.
	got, err := fwdArgs(fwChange{Op: opAdd, Spec: []string{"allow", "from", "10.0.0.0/8", "to", "any", "port", "5432",
		"proto", "tcp", "comment", `x" accept; rule family="ipv4" accept`}})
	if err != nil || len(got) != 1 || strings.Contains(got[0], "x") || strings.Count(got[0], "accept") != 1 {
		t.Errorf("comment leaked: %q %v", got, err)
	}
	if fwdInverse("--add-port=22/tcp") != "--remove-port=22/tcp" || fwdInverse("--remove-rich-rule=rule drop") != "--add-rich-rule=rule drop" {
		t.Error("fwdInverse")
	}
}

// The typed commands reach firewall-cmd only as values parsed from the
// user's text, each rich rule one argument.
func TestFwdArgsFromTypedCommands(t *testing.T) {
	for _, tc := range []struct {
		cmd  string
		args []string
		want []string
	}{
		{"fw_open", []string{"8080/tcp"}, []string{"--add-port=8080/tcp"}},
		{"fw_allow", []string{"10.0.0.0/8", "5432/tcp"},
			[]string{`--add-rich-rule=rule family="ipv4" source address="10.0.0.0/8" port port="5432" protocol="tcp" accept`}},
		{"fw_deny", []string{"198.51.100.7"}, []string{`--add-rich-rule=rule family="ipv4" source address="198.51.100.7" drop`}},
		{"fw_deny", []string{"2001:db8::/32", "6000:6007/udp"},
			[]string{`--add-rich-rule=rule family="ipv6" source address="2001:db8::/32" port port="6000-6007" protocol="udp" drop`}},
	} {
		spec, _, err := parseFwCommand(tc.cmd, tc.args, true)
		if err != nil {
			t.Fatalf("%s %q: %v", tc.cmd, tc.args, err)
		}
		got, err := fwdArgs(fwChange{Op: opAdd, Spec: spec.args()})
		if err != nil || !slices.Equal(got, tc.want) {
			t.Errorf("%s %q:\n got %q %v\nwant %q", tc.cmd, tc.args, got, err, tc.want)
		}
	}
}

// ---- end to end, over fake firewalld ----

// fwdSets is one zone configuration of the fake: runtime or permanent.
type fwdSets struct {
	target                string
	services, ports, rich []string
}

func (s fwdSets) clone() fwdSets {
	return fwdSets{s.target, slices.Clone(s.services), slices.Clone(s.ports), slices.Clone(s.rich)}
}

func (s fwdSets) String() string {
	return fmt.Sprintf("%s|%q|%q|%q", s.target, s.services, s.ports, s.rich)
}

// fakeFwd is firewalld with a runtime and a permanent configuration of
// zone public, answering firewall-cmd the way firewalld does, plus
// systemd-run, systemctl and ss. ufw is not installed.
type fakeFwd struct {
	mu       sync.Mutex
	calls    [][]string
	rt, perm fwdSets
	ss       string
	failOn   string // a firewall-cmd argument starting with this fails
	ufw      string // `ufw status` output; "" when ufw is missing
	nft      string // `nft list ruleset` output; "" when nft is missing
}

func newFakeFwd(services ...string) *fakeFwd {
	s := fwdSets{target: "default", services: services}
	return &fakeFwd{rt: s, perm: s.clone(), ss: adminPeer}
}

func (f *fakeFwd) runtime() string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.rt.String()
}

// fwdCalls are the firewall-cmd invocations that change something.
func (f *fakeFwd) fwdCalls() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []string
	for _, c := range f.calls {
		if c[0] != "firewall-cmd" || strings.HasPrefix(c[len(c)-1], "--info-service=") {
			continue
		}
		switch c[len(c)-1] {
		case "--state", "--version", "--get-default-zone", "--list-all":
			continue
		}
		out = append(out, strings.Join(c[1:], " "))
	}
	return out
}

func (f *fakeFwd) Run(_ context.Context, name string, args ...string) (string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = append(f.calls, append([]string{name}, args...))
	switch name {
	case "firewall-cmd":
	case "ufw":
		if f.ufw == "" {
			break
		}
		return f.ufw, nil
	case "nft":
		if f.nft == "" {
			break
		}
		return f.nft, nil
	case "systemd-run":
		return "Running timer as unit: " + strings.TrimPrefix(args[0], "--unit=") + ".timer", nil
	case "systemctl":
		return "", nil
	case "ss":
		if slices.Contains(args, "established") {
			return f.ss, nil
		}
		return "", nil
	}
	if name != "firewall-cmd" {
		return "", &exec.Error{Name: name, Err: exec.ErrNotFound}
	}
	set := &f.rt
	if args[0] == "--permanent" {
		set, args = &f.perm, args[1:]
	}
	last := args[len(args)-1]
	if f.failOn != "" && strings.HasPrefix(last, f.failOn) {
		return "Error: COMMAND_FAILED", errors.New("exit status 254")
	}
	switch {
	case last == "--state":
		return "running", nil
	case last == "--version":
		return "1.3.4", nil
	case last == "--get-default-zone":
		return "public", nil
	case last == "--reload":
		f.rt = f.perm.clone()
		return "success", nil
	case strings.HasPrefix(last, "--info-service="):
		svc := strings.TrimPrefix(last, "--info-service=")
		port := map[string]string{"ssh": "22/tcp", "http": "80/tcp", "dhcpv6-client": "546/udp"}[svc]
		if port == "" {
			return "Error: INVALID_SERVICE: " + svc, errors.New("exit status 101")
		}
		return strings.Replace(fwdInfoSSH, "ssh\n  ports: 22/tcp", svc+"\n  ports: "+port, 1), nil
	case last == "--list-all":
		return fmt.Sprintf("public (active)\n  target: %s\n  icmp-block-inversion: no\n  interfaces: eth0\n  sources: \n"+
			"  services: %s\n  ports: %s\n  protocols: \n  forward: yes\n  masquerade: no\n  forward-ports: \n"+
			"  source-ports: \n  icmp-blocks: \n  rich rules: \n\t%s\n", set.target, strings.Join(set.services, " "),
			strings.Join(set.ports, " "), strings.Join(set.rich, "\n\t")), nil
	}
	if args[0] != "--zone=public" {
		return "Error: INVALID_ZONE", errors.New("exit status 112")
	}
	verb, value, _ := strings.Cut(strings.TrimPrefix(last, "--"), "=")
	op, kind, _ := strings.Cut(verb, "-")
	list := map[string]*[]string{"port": &set.ports, "service": &set.services, "rich-rule": &set.rich}[kind]
	if list == nil {
		return "Error: unknown option", errors.New("exit status 2")
	}
	switch {
	case op == "add" && slices.Contains(*list, value):
		return "Warning: ALREADY_ENABLED: " + value + "\nsuccess", nil
	case op == "add":
		*list = append(*list, value)
	case !slices.Contains(*list, value):
		return "Warning: NOT_ENABLED: " + value + "\nsuccess", nil
	default:
		*list = slices.DeleteFunc(*list, func(s string) bool { return s == value })
	}
	return "success", nil
}

// fwdAgent is an agent over fakeFwd with a fake clock, the owner
// connected over SSH from 203.0.113.4.
func fwdAgent(t *testing.T, f *fakeFwd) (*Agent, *fakeSender, *fakeClock) {
	t.Helper()
	send := &fakeSender{}
	a := testAgent(send)
	a.src.Runner = f
	allowFw(t, a)
	a.cfg.Firewall.AllowCloseSSH = false
	a.src.SelfPath, a.src.ConfigPath = testSelf, testCfg
	clk := newFakeClock()
	a.now, a.fwAfter = clk.Now, clk.After
	return a, send, clk
}

func TestFirewalldOpenRuntimeThenKeepPermanent(t *testing.T) {
	f := newFakeFwd("ssh")
	a, send, _ := fwdAgent(t, f)

	text, kb := typed(t, a, send, "/fw_open 8080/tcp")
	msg := lastSentID(send)
	for _, want := range []string{"Apply firewall change?", "+ 2 ALLOW 8080/tcp\n    from Anywhere",
		"SSH check: ✅ 22/tcp still open for 203.0.113.4"} {
		if !strings.Contains(text, want) {
			t.Errorf("confirm lacks %q:\n%s", want, text)
		}
	}
	pressOn(a, "cmds", msg, buttonDataPrefix(kb, "🔍 Show commands"))
	if html := send.lastEdit().html; !strings.Contains(html, "firewall-cmd --zone=public\n    --add-port=8080/tcp") ||
		!strings.Contains(html, "Keep: the same with --permanent") {
		t.Errorf("show commands = %q", html)
	}
	pressOn(a, "yes", msg, tokenData(kb, tgui.ActYes))
	if got, want := f.fwdCalls(), []string{"--zone=public --add-port=8080/tcp"}; !slices.Equal(got, want) {
		t.Fatalf("calls = %q, want %q", got, want)
	}
	rec, ok := pendingTrial(t, a)
	if !ok || rec.Backend != fwKindFirewalld || rec.Zone != "public" || rec.Bin != "firewall-cmd" {
		t.Fatalf("trial = %+v", rec)
	}
	if !slices.Contains(f.rt.ports, "8080/tcp") || slices.Contains(f.perm.ports, "8080/tcp") {
		t.Fatalf("apply is not runtime-only: %v / %v", f.rt, f.perm)
	}

	pressOn(a, "keep", msg, buttonDataPrefix(send.lastEdit().kb, "✅ Keep"))
	if got, want := f.fwdCalls()[1:], []string{"--permanent --zone=public --add-port=8080/tcp"}; !slices.Equal(got, want) {
		t.Fatalf("keep calls = %q, want %q", got, want)
	}
	if !slices.Contains(f.perm.ports, "8080/tcp") || !strings.Contains(send.lastEdit().html, "Kept") {
		t.Errorf("not kept: %v, %q", f.perm, send.lastEdit().html)
	}
	if _, ok := pendingTrial(t, a); ok {
		t.Error("trial left pending")
	}
	for _, c := range f.fwdCalls() {
		if strings.Contains(c, "runtime-to-permanent") || strings.Contains(c, "--reload") {
			t.Errorf("forbidden call %q", c)
		}
	}
}

func TestFirewalldRollbackIsInverseRuntimeOps(t *testing.T) {
	f := newFakeFwd("ssh")
	a, send, clk := fwdAgent(t, f)
	before := f.runtime()

	_, kb := typed(t, a, send, "/fw_allow 10.0.0.0/8 5432/tcp")
	pressOn(a, "yes", lastSentID(send), tokenData(kb, tgui.ActYes))
	rule := `rule family="ipv4" source address="10.0.0.0/8" port port="5432" protocol="tcp" accept`
	if got, want := f.fwdCalls(), []string{"--zone=public --add-rich-rule=" + rule}; !slices.Equal(got, want) {
		t.Fatalf("calls = %q, want %q", got, want)
	}

	clk.Advance(125 * time.Second)
	if got, want := f.fwdCalls()[1:], []string{"--zone=public --remove-rich-rule=" + rule}; !slices.Equal(got, want) {
		t.Fatalf("rollback calls = %q, want %q", got, want)
	}
	if f.runtime() != before || !strings.Contains(send.lastEdit().html, "Rolled back") {
		t.Errorf("not rolled back: %s, %q", f.runtime(), send.lastEdit().html)
	}
	if _, ok := pendingTrial(t, a); ok {
		t.Error("trial left pending")
	}
}

func TestFirewalldForeignEditKeptOnRollback(t *testing.T) {
	f := newFakeFwd("ssh")
	a, send, _ := fwdAgent(t, f)
	_, kb := typed(t, a, send, "/fw_open 8080/tcp")
	msg := lastSentID(send)
	pressOn(a, "yes", msg, tokenData(kb, tgui.ActYes))
	// fail2ban, say, bans a host at runtime during the trial.
	ban := `rule family="ipv4" source address="198.51.100.7" reject`
	f.mu.Lock()
	f.rt.rich = append(f.rt.rich, ban)
	f.mu.Unlock()

	pressOn(a, "back", msg, buttonDataPrefix(send.lastEdit().kb, "↩️ Roll back"))
	if got, want := f.fwdCalls()[1:], []string{"--zone=public --remove-port=8080/tcp"}; !slices.Equal(got, want) {
		t.Fatalf("rollback calls = %q, want %q", got, want)
	}
	if !slices.Contains(f.rt.rich, ban) || slices.Contains(f.rt.ports, "8080/tcp") {
		t.Errorf("runtime = %v", f.rt)
	}
	if html := send.lastEdit().html; !strings.Contains(html, "trial's own changes") || !strings.Contains(html, "198.51.100.7") {
		t.Errorf("notice = %q", html)
	}
}

func TestFirewalldReloadIsLastResort(t *testing.T) {
	f := newFakeFwd("ssh")
	a, send, clk := fwdAgent(t, f)
	_, kb := typed(t, a, send, "/fw_open 8080/tcp")
	pressOn(a, "yes", lastSentID(send), tokenData(kb, tgui.ActYes))
	// The inverse operation fails: only a reload brings the rules back.
	f.mu.Lock()
	f.failOn = "--remove-port"
	f.mu.Unlock()

	clk.Advance(125 * time.Second)
	calls := f.fwdCalls()
	if got := calls[len(calls)-2:]; !slices.Equal(got, []string{"--zone=public --remove-port=8080/tcp", "--reload"}) {
		t.Fatalf("calls = %q", calls)
	}
	if slices.Contains(f.rt.ports, "8080/tcp") {
		t.Errorf("not rolled back: %v", f.rt)
	}
	html := send.lastEdit().html
	if !strings.Contains(html, "Rolled back") || !strings.Contains(html, "reloaded") || !strings.Contains(html, "fail2ban") {
		t.Errorf("notice = %q", html)
	}
}

func TestFirewalldCloseSSHPlanAndGuard(t *testing.T) {
	f := newFakeFwd("ssh")
	a, send, _ := fwdAgent(t, f)
	a.cfg.Firewall.AllowCloseSSH = true
	before := f.runtime()

	// The guard simulates firewalld's order: a deny of the owner's own
	// network is refused before anything runs.
	text, kb := typed(t, a, send, "/fw_deny 203.0.113.0/24")
	if !strings.Contains(text, "⛔ <b>Refused</b>\nThis would block SSH 22/tcp for your session from 203.0.113.4.") ||
		tokenData(kb, tgui.ActYes) != "" {
		t.Errorf("deny of own peer = %q", text)
	}
	// Rate limiting has no firewalld equivalent here.
	pressOn(a, "ssh", 9, callData(tgui.Call{Act: askFwPreset, Args: []string{"ssh"}}))
	if html := send.lastEdit().html; !strings.Contains(html, "Rate limiting (limit) is not offered on firewalld") {
		t.Errorf("ssh preset = %q", html)
	}

	// Close SSH: the service goes, a family-less drop comes in.
	closeSSH(t, a, send)
	want := []string{"--zone=public --remove-service=ssh", `--zone=public --add-rich-rule=rule port port="22" protocol="tcp" drop`}
	if got := f.fwdCalls(); !slices.Equal(got, want) {
		t.Fatalf("calls = %q, want %q", got, want)
	}
	fwPress(t, a, "back", buttonDataPrefix(send.lastEdit().kb, "↩️ Roll back"))
	if f.runtime() != before {
		t.Errorf("not rolled back: %s", f.runtime())
	}
}

func TestFirewalldHomeAndRules(t *testing.T) {
	f := newFakeFwd("ssh")
	f.rt.rich = []string{`rule priority="-5" family="ipv4" source address="192.0.2.0/24" accept`}
	a, _, _ := fwdAgent(t, f)
	text, kb := a.firewallView(context.Background())
	for _, want := range []string{"🛡 <b>Firewall</b> · firewalld · zone <b>public</b>", "Keep makes them permanent",
		"Default incoming policy: <b>reject</b>", "SSH port 22: 🔓 <b>open</b> (rule 2: 22/tcp ALLOW IN Anywhere · service ssh)"} {
		if !strings.Contains(text, want) {
			t.Errorf("home lacks %q:\n%s", want, text)
		}
	}
	if d := dumpKeyboard(kb); !strings.Contains(d, "[📋 Rules]") || strings.Contains(d, "Restore previous") {
		t.Errorf("home keyboard = %s", d)
	}
	if got := a.firewallSummary(context.Background()); got != "firewalld · SSH open" {
		t.Errorf("summary = %q", got)
	}
	// A rule the agent did not write has no Delete.
	n, why := a.readFw(context.Background())
	if why != "" {
		t.Fatal(why)
	}
	specs := rowSpecs(n.p.fw, n.added)
	gen := fwGen(n.p.fw)[:6]
	v := a.fwRuleScreen(context.Background(), tgui.Call{Act: tgui.ActView, Args: []string{scrFwRule, gen, ruleID(n.p.fw.rules[0], specs[0])}})
	if !strings.Contains(v.Text, "deleted from a shell only") || len(v.Rows) != 0 {
		t.Errorf("priority rule = %q %v", v.Text, v.Rows)
	}
	v = a.fwRuleScreen(context.Background(), tgui.Call{Act: tgui.ActView, Args: []string{scrFwRule, gen, ruleID(n.p.fw.rules[1], specs[1])}})
	if !strings.Contains(v.Text, "Removed by: <code>firewall-cmd --zone=public --remove-service=ssh</code>") || len(v.Rows) != 1 {
		t.Errorf("ssh rule = %q %v", v.Text, v.Rows)
	}
	// Restore previous is ufw's.
	if v := a.planFor(context.Background(), 42, 42, 0, a.restoreBuild("0123abcd")); !strings.Contains(v.Text, "ufw only") {
		t.Errorf("restore on firewalld = %q", v.Text)
	}
}
