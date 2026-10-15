package agent

import (
	"context"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/eliau2005/statixagent/internal/bot"
	"github.com/eliau2005/statixagent/internal/telegram"
	"github.com/eliau2005/statixagent/internal/tgui"
)

func TestParsePortArg(t *testing.T) {
	cases := []struct {
		in    string
		want  portRange
		proto string
		err   string // substring; "" = valid
	}{
		{"22", portRange{22, 22}, "", ""},
		{"8080/tcp", portRange{8080, 8080}, "tcp", ""},
		{"53/udp", portRange{53, 53}, "udp", ""},
		{"6000:6007/tcp", portRange{6000, 6007}, "tcp", ""},
		{"1:1000/udp", portRange{1, 1000}, "udp", ""},
		{"65535", portRange{65535, 65535}, "", ""},
		{"0", portRange{}, "", "not a port"},
		{"65536", portRange{}, "", "not a port"},
		{"-1", portRange{}, "", "not a port"},
		{"+22", portRange{}, "", "not a port"},
		{"022", portRange{}, "", "not a port"},
		{"http", portRange{}, "", "not a port"},
		{"", portRange{}, "", "not a port"},
		{"22/TCP", portRange{}, "", "not tcp or udp"},
		{"22/icmp", portRange{}, "", "not tcp or udp"},
		{"6000:6007", portRange{}, "", "needs a protocol"},
		{"6007:6000/tcp", portRange{}, "", "low to high"},
		{"22:22/tcp", portRange{}, "", "low to high"},
		{"1:1001/tcp", portRange{}, "", "at most 1000"},
		{"1:2:3/tcp", portRange{}, "", "not a port"},
	}
	for _, tc := range cases {
		r, proto, err := parsePortArg(tc.in)
		switch {
		case tc.err == "" && err != nil:
			t.Errorf("%q: %v", tc.in, err)
		case tc.err != "" && (err == nil || !strings.Contains(err.Error(), tc.err)):
			t.Errorf("%q: err = %v, want %q", tc.in, err, tc.err)
		case tc.err == "" && (r != tc.want || proto != tc.proto):
			t.Errorf("%q = %v %q, want %v %q", tc.in, r, proto, tc.want, tc.proto)
		}
	}
}

func TestParseSourceArg(t *testing.T) {
	cases := []struct {
		in   string
		v6ok bool
		want string // canonical prefix; "" = refused
		err  string
	}{
		{"10.0.0.0/8", true, "10.0.0.0/8", ""},
		{"203.0.113.4", true, "203.0.113.4/32", ""},
		{"2001:db8::/32", true, "2001:db8::/32", ""},
		{"2001:db8::5", true, "2001:db8::5/128", ""},
		{"10.0.0.1/8", true, "", "did you mean 10.0.0.0/8?"},
		{"203.0.113.4/32", true, "", "did you mean 203.0.113.4?"},
		{"2001:DB8::/32", true, "", "did you mean 2001:db8::/32?"},
		{"::ffff:203.0.113.4", true, "", "did you mean 203.0.113.4?"},
		{"::ffff:10.0.0.0/104", true, "", "did you mean 10.0.0.0/8?"},
		{"::ffff:0:0/80", true, "", "not an IPv4 range"},
		{"0.0.0.0/0", true, "", "/0 is every address"},
		{"::/0", true, "", "/0 is every address"},
		{"127.0.0.1", true, "", "loopback"},
		{"127.0.0.0/8", true, "", "loopback"},
		{"::1", true, "", "loopback"},
		{"169.254.0.0/16", true, "", "link-local"},
		{"fe80::1", true, "", "link-local"},
		{"fe80::1%eth0", true, "", "not an IP address"},
		{"224.0.0.1", true, "", "multicast"},
		{"0.0.0.0", true, "", "loopback, link-local"},
		{"2001:db8::/32", false, "", "IPV6=no"},
		{"example.com", true, "", "not an IP address"},
		{"10.0.0.0/33", true, "", "not an IP address"},
		{"-1", true, "", "not an IP address"},
	}
	for _, tc := range cases {
		p, err := parseSourceArg(tc.in, tc.v6ok)
		switch {
		case tc.want != "" && err != nil:
			t.Errorf("%q: %v", tc.in, err)
		case tc.want != "" && p.String() != tc.want:
			t.Errorf("%q = %v, want %s", tc.in, p, tc.want)
		case tc.want == "" && (err == nil || !strings.Contains(err.Error(), tc.err)):
			t.Errorf("%q: err = %v, want %q", tc.in, err, tc.err)
		}
	}
}

func TestParseFwCommand(t *testing.T) {
	cases := []struct {
		cmd   string
		args  string
		spec  string // canonical ufw spec; "" = refused
		title string
		err   string
	}{
		{"fw_open", "8080/tcp", "allow 8080/tcp", "Open 8080/tcp", ""},
		{"fw_open", "8080", "allow 8080", "Open 8080", ""},
		{"fw_open", "6000:6007/udp", "allow 6000:6007/udp", "Open 6000:6007/udp", ""},
		{"fw_allow", "10.0.0.0/8 5432/tcp", "allow from 10.0.0.0/8 to any port 5432 proto tcp", "Allow 5432/tcp from 10.0.0.0/8", ""},
		{"fw_allow", "203.0.113.4 6379", "allow from 203.0.113.4 to any port 6379", "Allow 6379 from 203.0.113.4", ""},
		{"fw_deny", "198.51.100.7", "deny from 198.51.100.7", "Deny all ports from 198.51.100.7", ""},
		{"fw_deny", "2001:db8::/32 25/tcp", "deny from 2001:db8::/32 to any port 25 proto tcp", "Deny 25/tcp from 2001:db8::/32", ""},
		// Databases are never opened to Anywhere, whatever the spelling.
		{"fw_open", "5432/tcp", "", "", "/fw_allow <cidr> 5432/tcp"},
		{"fw_open", "6379", "", "", "Redis is never opened to Anywhere"},
		{"fw_open", "5000:5999/tcp", "", "", "Postgres"},
		{"fw_allow", "0.0.0.0/0 5432/tcp", "", "", "/0 is every address"},
		{"fw_deny", "0.0.0.0/0", "", "", "/0 is every address"},
		{"fw_open", "", "", "", "usage: /fw_open"},
		{"fw_open", "80 443", "", "", "usage: /fw_open"},
		{"fw_allow", "10.0.0.0/8", "", "", "usage: /fw_allow"},
		{"fw_deny", "", "", "", "usage: /fw_deny"},
		{"fw_deny", "1.2.3.4 22/tcp extra", "", "", "usage: /fw_deny"},
		{"fw_allow", "10.0.0.1/8 22", "", "", "did you mean 10.0.0.0/8?"},
		{"fw_deny", "--force 22", "", "", "not an IP address"},
		{"fw_open", "22/tcp;reboot", "", "", "not tcp or udp"},
	}
	for _, tc := range cases {
		spec, title, err := parseFwCommand(tc.cmd, strings.Fields(tc.args), true)
		where := "/" + tc.cmd + " " + tc.args
		if tc.spec == "" {
			if err == nil || !strings.Contains(err.Error(), tc.err) {
				t.Errorf("%s: err = %v, want %q", where, err, tc.err)
			}
			continue
		}
		if err != nil {
			t.Errorf("%s: %v", where, err)
			continue
		}
		if got := strings.Join(spec.args(), " "); got != tc.spec || title != tc.title {
			t.Errorf("%s = %q %q, want %q %q", where, got, title, tc.spec, tc.title)
		}
		// The spec the bot writes is one the model reads back as itself.
		r, _, ok := specRule(spec.args())
		if !ok || r.Action != spec.Action || r.From != spec.From || r.Proto != spec.Proto ||
			(spec.Ports.Lo != 0 && !slices.Equal(r.Ports, []portRange{spec.Ports})) {
			t.Errorf("%s: spec reads back as %+v", where, r)
		}
	}
}

func TestSpecRule(t *testing.T) {
	cases := []struct {
		spec string
		row  string // a status row the spec is listed as; "" = unreadable
		fam  string
	}{
		{"allow 22/tcp", "22/tcp ALLOW IN Anywhere", ""},
		{"allow 22/tcp", "22/tcp (v6) ALLOW IN Anywhere (v6)", ""},
		{"limit OpenSSH", "22/tcp (OpenSSH) LIMIT IN Anywhere", ""},
		{"allow 'Nginx Full'", "80,443/tcp (Nginx Full) ALLOW IN Anywhere", ""},
		{"deny from 198.51.100.7", "Anywhere DENY IN 198.51.100.7", "v4"},
		{"allow from 10.0.0.0/8 to any port 5432 proto tcp", "5432/tcp ALLOW IN 10.0.0.0/8", "v4"},
		{"allow from 2001:db8::/32 to any port 22", "22 ALLOW IN 2001:db8::/32", "v6"},
		{"allow in on eth0 to any port 80 proto tcp", "80/tcp on eth0 ALLOW IN Anywhere", ""},
		{"deny out 25/tcp", "25/tcp DENY OUT Anywhere", ""},
		{"allow log 80/tcp comment 'web'", "80/tcp ALLOW IN Anywhere", ""},
		{"reject from 10.0.0.0/8 port 53 to any", "Anywhere REJECT IN 10.0.0.0/8 53", "v4"},
		{"allow from nowhere", "", ""},
		{"accept 22", "", ""},
		{"allow from 10.0.0.0/8 to", "", ""},
	}
	for _, tc := range cases {
		r, fam, ok := specRule(splitQuoted(tc.spec))
		if tc.row == "" {
			if ok {
				t.Errorf("%q read as %+v", tc.spec, r)
			}
			continue
		}
		row, rok := parseUFWRow(tc.row)
		if !ok || !rok || fam != tc.fam || !rowOf(row, r, fam) {
			t.Errorf("%q (%+v, %q, %v) is not row %q (%+v)", tc.spec, r, fam, ok, tc.row, row)
		}
	}
}

// statusOf is `ufw status verbose` with the given rows.
func statusOf(rows ...string) ufwStatus {
	return parseUFWOutput("Status: active\nDefault: deny (incoming), allow (outgoing), disabled (routed)\n\n" +
		"To                         Action      From\n--                         ------      ----\n" + strings.Join(rows, "\n") + "\n")
}

func mustSpec(t *testing.T, cmd, args string) fwSpec {
	t.Helper()
	s, _, err := parseFwCommand(cmd, strings.Fields(args), true)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func TestPlanSpecs(t *testing.T) {
	var many [][]string
	for i := range fwMaxUserRules {
		many = append(many, []string{"allow", fmt.Sprintf("%d/tcp", 10000+i)})
	}
	cases := []struct {
		name  string
		rows  []string
		added [][]string
		cmd   string
		args  string
		want  []string // argv of each change
		err   string
	}{
		{"allow appends", []string{"22/tcp ALLOW IN Anywhere"}, [][]string{{"allow", "22/tcp"}},
			"fw_open", "8080/tcp", []string{"allow 8080/tcp"}, ""},
		{"deny goes first", []string{"22/tcp ALLOW IN Anywhere"}, [][]string{{"allow", "22/tcp"}},
			"fw_deny", "198.51.100.7", []string{"insert 1 deny from 198.51.100.7"}, ""},
		{"deny into an empty list is added", nil, nil,
			"fw_deny", "198.51.100.7", []string{"deny from 198.51.100.7"}, ""},
		{"IPv6 deny is prepended", []string{"22/tcp ALLOW IN Anywhere"}, [][]string{{"allow", "22/tcp"}},
			"fw_deny", "2001:db8::/32", []string{"prepend deny from 2001:db8::/32"}, ""},
		{"the opposite rule is deleted first", []string{"8080/tcp DENY IN Anywhere"}, [][]string{{"deny", "8080/tcp"}},
			"fw_open", "8080/tcp", []string{"--force delete deny 8080/tcp", "allow 8080/tcp"}, ""},
		{"replacing the only rule adds the deny", []string{"Anywhere ALLOW IN 198.51.100.7"}, [][]string{{"allow", "from", "198.51.100.7"}},
			"fw_deny", "198.51.100.7", []string{"--force delete allow from 198.51.100.7", "deny from 198.51.100.7"}, ""},
		{"already there", []string{"8080/tcp ALLOW IN Anywhere"}, [][]string{{"allow", "8080/tcp"}},
			"fw_open", "8080/tcp", nil, "nothing to change"},
		{"at most 64 rules", nil, many, "fw_open", "8080/tcp", nil, "at most 64"},
	}
	for _, tc := range cases {
		plan, err := planSpecs(tc.added, statusOf(tc.rows...), []fwSpec{mustSpec(t, tc.cmd, tc.args)}, true)
		if tc.err != "" {
			if err == nil || !strings.Contains(err.Error(), tc.err) {
				t.Errorf("%s: err = %v, want %q", tc.name, err, tc.err)
			}
			continue
		}
		var got []string
		for _, c := range plan {
			got = append(got, strings.Join(c.argv(), " "))
		}
		if err != nil || !slices.Equal(got, tc.want) {
			t.Errorf("%s: plan = %q (%v), want %q", tc.name, got, err, tc.want)
		}
	}
}

func TestSimulate(t *testing.T) {
	st := statusOf("22/tcp ALLOW IN Anywhere", "80/tcp ALLOW IN Anywhere",
		"22/tcp (v6) ALLOW IN Anywhere (v6)", "80/tcp (v6) ALLOW IN Anywhere (v6)")
	plan := fwPlan{
		{Op: opInsert, Spec: []string{"deny", "from", "198.51.100.7"}},
		{Op: opPrepend, Spec: []string{"deny", "from", "2001:db8::/32"}},
		{Op: opAdd, Spec: []string{"allow", "443/tcp"}},
		{Op: opDelete, Spec: []string{"allow", "80/tcp"}},
		{Op: opAdd, Spec: []string{"limit", "22/tcp"}}, // ufw updates in place
	}
	var got []string
	for _, r := range simulate(st, plan, true).rules {
		got = append(got, fmt.Sprintf("%d %s %s %s v6=%v", r.Num, r.Action, portLabel(r), fromLabel(r), r.V6))
	}
	want := []string{
		"1 deny any 198.51.100.7 v6=false",
		"2 limit 22/tcp Anywhere v6=false",
		"3 allow 443/tcp Anywhere v6=false",
		"4 deny any 2001:db8::/32 v6=true",
		"5 limit 22/tcp Anywhere (v6) v6=true",
		"6 allow 443/tcp Anywhere (v6) v6=true",
	}
	if !slices.Equal(got, want) {
		t.Errorf("simulated:\n%s\nwant:\n%s", strings.Join(got, "\n"), strings.Join(want, "\n"))
	}
	// Without IPv6 in ufw, a rule for both families is listed once.
	if n := len(simulate(statusOf("22/tcp ALLOW IN Anywhere"), fwPlan{{Op: opAdd, Spec: []string{"allow", "80/tcp"}}}, false).rules); n != 2 {
		t.Errorf("IPV6=no: %d rules, want 2", n)
	}
}

// TestSSHGuard is the guard simulation table (§5.3): each change is
// planned, simulated and checked against the SSH port and the peers.
func TestSSHGuard(t *testing.T) {
	both := []string{"22/tcp ALLOW IN Anywhere", "22/tcp (v6) ALLOW IN Anywhere (v6)"}
	v4peer := []netip.Addr{netip.MustParseAddr("203.0.113.4")}
	v6peer := []netip.Addr{netip.MustParseAddr("2001:db8::5")}
	del := func(spec ...string) fwPlan { return fwPlan{{Op: opDelete, Spec: spec}} }
	cases := []struct {
		name  string
		rows  []string
		added [][]string
		cmd   string // a typed command, or
		args  string
		plan  fwPlan // a plan as it is
		ports []int
		peers []netip.Addr
		want  string // refusal substring; "" = allowed
	}{
		{name: "peer inside a denied CIDR", rows: both, cmd: "fw_deny", args: "203.0.113.0/24 22/tcp", peers: v4peer,
			want: "block SSH 22/tcp for your session from 203.0.113.4"},
		{name: "deny elsewhere", rows: both, cmd: "fw_deny", args: "198.51.100.0/24 22/tcp", peers: v4peer},
		{name: "deny of every port shadows SSH for the peer", rows: both, cmd: "fw_deny", args: "203.0.113.4", peers: v4peer,
			want: "for your session from 203.0.113.4"},
		{name: "deny of another port", rows: both, cmd: "fw_deny", args: "203.0.113.4 25/tcp", peers: v4peer},
		{name: "deleting the last allow for SSH", rows: both, added: [][]string{{"allow", "22/tcp"}},
			plan: del("allow", "22/tcp"), peers: v4peer, want: "block SSH 22/tcp"},
		{name: "deleting the last allow, nobody connected", rows: both, added: [][]string{{"allow", "22/tcp"}},
			plan: del("allow", "22/tcp"), want: "close SSH 22/tcp"},
		{name: "deleting one of two allows", rows: append([]string{"22/tcp (OpenSSH) ALLOW IN Anywhere", "22/tcp (OpenSSH (v6)) ALLOW IN Anywhere (v6)"}, both...),
			plan: del("allow", "22/tcp"), peers: v4peer},
		{name: "deleting the peer's own source rule", rows: []string{"22/tcp ALLOW IN 203.0.113.0/24"},
			plan: del("allow", "from", "203.0.113.0/24", "to", "any", "port", "22", "proto", "tcp"), peers: v4peer,
			want: "for your session from 203.0.113.4"},
		{name: "IPv6 peer in a denied range", rows: both, cmd: "fw_deny", args: "2001:db8::/32 22/tcp", peers: v6peer,
			want: "for your session from 2001:db8::5"},
		{name: "IPv4 deny leaves the IPv6 peer", rows: both, cmd: "fw_deny", args: "203.0.113.0/24", peers: v6peer},
		{name: "other SSH port", rows: append(both, "2222/tcp ALLOW IN Anywhere"), cmd: "fw_deny", args: "203.0.113.0/24 2222/tcp",
			ports: []int{22, 2222}, peers: v4peer, want: "SSH 2222/tcp"},
		{name: "web preset", rows: both, cmd: "fw_open", args: "443/tcp", peers: append(v4peer, v6peer...)},
		{name: "limit keeps SSH open", rows: both, added: [][]string{{"allow", "22/tcp"}},
			plan: fwPlan{{Op: opDelete, Spec: []string{"allow", "22/tcp"}}, {Op: opAdd, Spec: []string{"limit", "22/tcp"}}}, peers: v4peer},
		{name: "unrelated change under an interface rule", rows: []string{"22/tcp on eth0 ALLOW IN Anywhere"},
			cmd: "fw_open", args: "80/tcp", peers: v4peer},
		{name: "deny in front of an interface rule", rows: []string{"22/tcp on eth0 ALLOW IN Anywhere"},
			cmd: "fw_deny", args: "203.0.113.0/24", peers: v4peer, want: "for your session"},
	}
	for _, tc := range cases {
		st := statusOf(tc.rows...)
		plan := tc.plan
		if tc.cmd != "" {
			var err error
			if plan, err = planSpecs(tc.added, st, []fwSpec{mustSpec(t, tc.cmd, tc.args)}, true); err != nil {
				t.Fatalf("%s: %v", tc.name, err)
			}
		}
		ports := tc.ports
		if ports == nil {
			ports = []int{22}
		}
		got := sshGuard(st, simulate(st, plan, true), ports, tc.peers)
		if (tc.want == "") != (got == "") || !strings.Contains(got, tc.want) {
			t.Errorf("%s: guard = %q, want %q", tc.name, got, tc.want)
		}
	}
}

// The confirm screen stays within Telegram's limits for the largest
// diff the bot manages: 64 rules out and 64 in, in both families.
func TestPlanViewFitsWith64Rules(t *testing.T) {
	a := testAgent(&fakeSender{})
	var before, after []string
	for i := range fwMaxUserRules {
		before = append(before, fmt.Sprintf("%d/tcp ALLOW IN 2001:db8:ffff:ffff:ffff:ffff:ffff:%x", 10000+i, i))
		after = append(after, fmt.Sprintf("%d:%d/udp DENY IN 198.51.100.%d", 20000+i, 20999+i, i))
	}
	var plan fwPlan
	for i := range fwMaxUserRules {
		plan = append(plan, fwChange{Op: opDelete, Spec: []string{"allow", "from", fmt.Sprintf("2001:db8:ffff:ffff:ffff:ffff:ffff:%x", i),
			"to", "any", "port", fmt.Sprint(10000 + i), "proto", "tcp"}})
	}
	req := &fwPlanReq{id: "0123abcd", title: "Restore the rules of snapshot 0123abcd <&>", plan: plan,
		diff: diffRows(statusOf(before...), statusOf(after...)), check: "SSH check: ✅", nonce: "AbCdEfGhIjKl"}
	for _, cmds := range []bool{false, true} {
		text, kb := encodeView(a.planView(req, cmds))
		fitted := telegram.FitEdit(text)
		switch {
		case !cmds && len(text) > 4096:
			t.Errorf("diff is %d bytes", len(text))
		case len(fitted) > 4096:
			t.Errorf("cmds=%v: %d bytes after FitEdit", cmds, len(fitted))
		}
		if err := checkTelegramHTML(fitted); err != nil {
			t.Errorf("cmds=%v: %v", cmds, err)
		}
		for _, row := range bot.PreRows(text) {
			if bot.Width(row) > bot.PreCols {
				t.Errorf("<pre> row %q is %d columns", row, bot.Width(row))
			}
		}
		if !strings.Contains(text, "&lt;&amp;&gt;") || !strings.Contains(text, "… 104 more changes") {
			t.Errorf("cmds=%v: %s", cmds, text)
		}
		for _, row := range kb {
			for _, b := range row {
				if len(b.Data) > tgui.MaxData {
					t.Errorf("button %q is %d bytes", b.Text, len(b.Data))
				}
			}
		}
	}
}

func TestParseUFWIPv6(t *testing.T) {
	for text, want := range map[string]bool{
		"":                               true,
		"IPV6=yes\n":                     true,
		"# IPV6=no\nIPV6=yes":            true,
		"IPV6=no\n":                      false,
		"IPV6=\"no\"\n":                  false,
		"IPV6=yes\nDEFAULT_INPUT=DROP\n": true,
	} {
		if got := parseUFWIPv6(text); got != want {
			t.Errorf("%q = %v, want %v", text, got, want)
		}
	}
}

// ---- end to end, over fake ufw ----

// planUFW is fakeUFW listing every spec the plans write (sources, ports
// with a source) and answering prepend.
type planUFW struct{ *fakeUFW }

func (f planUFW) Run(ctx context.Context, name string, args ...string) (string, error) {
	if name != "ufw" || len(args) == 0 || (args[0] != "status" && args[0] != "prepend") {
		return f.fakeUFW.Run(ctx, name, args...)
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = append(f.calls, append([]string{name}, args...))
	if args[0] == "status" {
		return planStatus(f.read("user.rules"), f.read("user6.rules")), nil
	}
	spec := strings.Join(args[1:], " ")
	name = "user.rules"
	if ruleFamily(spec) == "v6" {
		name = "user6.rules"
	}
	f.write(name, append([]string{spec}, f.read(name)...))
	return "Rule inserted", nil
}

// planStatus renders specs as `ufw status verbose` does.
func planStatus(v4, v6 []string) string {
	var b strings.Builder
	b.WriteString("Status: active\nLogging: on (low)\n" +
		"Default: deny (incoming), allow (outgoing), disabled (routed)\nNew profiles: skip\n\n" +
		"To                         Action      From\n--                         ------      ----\n")
	row := func(spec string, six bool) {
		w := strings.Fields(spec)
		to, from := "Anywhere", "Anywhere"
		if len(w) == 2 {
			to = w[1]
			if to == "OpenSSH" {
				to = "22/tcp (OpenSSH)"
			}
		} else {
			from = w[2]
			port, proto := "", ""
			for i := 3; i+1 < len(w); i += 2 {
				switch w[i] {
				case "port":
					port = w[i+1]
				case "proto":
					proto = w[i+1]
				}
			}
			if port != "" {
				to = port
				if proto != "" {
					to += "/" + proto
				}
			}
		}
		if six && from == "Anywhere" {
			to, from = strings.Replace(to+" (v6)", "(OpenSSH) (v6)", "(OpenSSH (v6))", 1), "Anywhere (v6)"
		}
		fmt.Fprintf(&b, "%-26s %-11s %s\n", to, strings.ToUpper(w[0])+" IN", from)
	}
	for _, r := range v4 {
		row(r, false)
	}
	for _, r := range v6 {
		row(r, true)
	}
	return b.String()
}

// planAgent is fwAgent over planUFW, with the owner connected over SSH
// from 203.0.113.4.
func planAgent(t *testing.T, rules ...string) (*Agent, *fakeSender, *fakeClock, *fakeUFW) {
	t.Helper()
	f := newFakeUFW(t, rules...)
	f.setSS(adminPeer)
	a, send, clk := fwAgent(t, f)
	unlimitPresses(a) // these flows press faster than any person; the limit has its own tests
	a.src.Runner = planUFW{f}
	a.cfg.Firewall.AllowCloseSSH = false
	return a, send, clk, f
}

// typed sends text as the owner and returns the reply.
func typed(t *testing.T, a *Agent, send *fakeSender, text string) (string, telegram.Keyboard) {
	t.Helper()
	ctx := context.Background()
	reply, name, ok := a.router.Dispatch(withActor(ctx, 42), telegram.Update{ChatID: 42, FromID: 42, ChatType: "private", Text: text})
	if !ok {
		t.Fatalf("%s: not handled", text)
	}
	a.reply(ctx, name, reply)
	send.mu.Lock()
	defer send.mu.Unlock()
	return send.sent[len(send.sent)-1], send.keyboards[len(send.keyboards)-1]
}

// pressOn is an owner press of data on message msg.
func TestTypedOpenAppliesUnderTrialAndRollsBack(t *testing.T) {
	a, send, clk, f := planAgent(t, "allow 22/tcp")
	before := f.files()

	text, kb := typed(t, a, send, "/fw_open 8080/tcp")
	msg := lastSentID(send)
	for _, want := range []string{"Apply firewall change?", "Open 8080/tcp", "auto-rollback in 2:00",
		"+ 2 ALLOW 8080/tcp\n    from Anywhere", "+ 4 ALLOW 8080/tcp\n    from Anywhere (v6)", "SSH check: ✅ 22/tcp still open for 203.0.113.4"} {
		if !strings.Contains(text, want) {
			t.Errorf("confirm lacks %q:\n%s", want, text)
		}
	}
	yes := tokenData(kb, tgui.ActYes)
	if yes == "" || !strings.HasPrefix(buttonDataPrefix(kb, "✅ Apply (2 min trial)"), "~1y|") || tokenData(kb, tgui.ActNo) == "" {
		t.Fatalf("confirm keyboard = %s", dumpKeyboard(kb))
	}
	if strings.Contains(yes+buttonDataPrefix(kb, "🔍"), "8080") {
		t.Errorf("callback data carries the rule: %s", dumpKeyboard(kb))
	}
	if calls := f.ruleCalls(); len(calls) != 0 {
		t.Fatalf("planning changed rules: %q", calls)
	}

	// Show commands reveals the exact argv and keeps the same Yes.
	pressOn(a, "cmds", msg, buttonDataPrefix(kb, "🔍 Show commands"))
	last := send.lastEdit()
	if !strings.Contains(last.html, "<pre>ufw allow 8080/tcp\nufw reload</pre>") || tokenData(last.kb, tgui.ActYes) != yes {
		t.Fatalf("show commands = %q\n%s", last.html, dumpKeyboard(last.kb))
	}
	pressOn(a, "hide", msg, buttonDataPrefix(last.kb, "🔍 Hide commands"))
	if strings.Contains(send.lastEdit().html, "ufw reload") {
		t.Errorf("hide commands = %q", send.lastEdit().html)
	}

	pressOn(a, "yes", msg, yes)
	if got, want := f.ruleCalls(), []string{"allow 8080/tcp", "reload"}; !slices.Equal(got, want) {
		t.Fatalf("rule calls = %q, want %q", got, want)
	}
	rec, ok := pendingTrial(t, a)
	if !ok || rec.Action != actFwPlan || rec.What != "Open 8080/tcp" || rec.Evidence || len(rec.Plan) != 1 {
		t.Fatalf("trial = %+v", rec)
	}
	last = send.lastEdit()
	if !strings.Contains(last.html, "🧾 Open 8080/tcp · on trial") || !strings.Contains(last.html, "Trial applied</b> · Open 8080/tcp") ||
		buttonDataPrefix(last.kb, "✅ Keep") == "" {
		t.Errorf("countdown = %q", last.html)
	}
	// A second Yes on the same token does nothing more.
	pressOn(a, "yes-again", msg, yes)
	if n := len(f.ruleCalls()); n != 2 {
		t.Errorf("double tap ran %d rule calls", n)
	}

	clk.Advance(125 * time.Second)
	if f.files() != before {
		t.Errorf("not rolled back:\n%s\nwant\n%s", f.files(), before)
	}
	if _, ok := pendingTrial(t, a); ok {
		t.Error("trial left pending")
	}
}

func TestTypedDenyOfOwnPeerIsRefused(t *testing.T) {
	for _, cmd := range []string{"/fw_deny 203.0.113.0/24", "/fw_deny 203.0.113.4 22/tcp", "/fw_deny 203.0.0.0/8 22"} {
		a, send, _, f := planAgent(t, "allow 22/tcp", "allow 80/tcp")
		text, kb := typed(t, a, send, cmd)
		if !strings.Contains(text, "⛔ <b>Refused</b>\nThis would block SSH 22/tcp for your session from 203.0.113.4.") ||
			!strings.Contains(text, "from a shell") {
			t.Errorf("%s: %q", cmd, text)
		}
		if tokenData(kb, tgui.ActYes) != "" || dumpKeyboard(kb) != "[⬅️ Back] → ~1v|fw  [🏠 Home] → ~1v|home\n" {
			t.Errorf("%s: refusal keyboard = %s", cmd, dumpKeyboard(kb))
		}
		if calls := f.ruleCalls(); len(calls) != 0 {
			t.Errorf("%s: changed rules: %q", cmd, calls)
		}
	}
}

func TestTypedCommandErrorsAreEscaped(t *testing.T) {
	a, send, _, _ := planAgent(t, "allow 22/tcp")
	for cmd, want := range map[string]string{
		"/fw_open 5432/tcp":           "Postgres is never opened to Anywhere. Name who may connect: /fw_allow &lt;cidr&gt; 5432/tcp",
		"/fw_allow 0.0.0.0/0 6379":    "/0 is every address",
		"/fw_open <b>":                `"&lt;b&gt;" is not a port`,
		"/fw_deny 10.0.0.1/8":         "did you mean 10.0.0.0/8?",
		"/fw_open 22/tcp":             "Nothing to change",
		"/fw_allow 10.0.0.0/8 1:2000": "needs a protocol",
	} {
		text, kb := typed(t, a, send, cmd)
		if !strings.Contains(text, want) || tokenData(kb, tgui.ActYes) != "" {
			t.Errorf("%s: %q", cmd, text)
		}
		if err := checkTelegramHTML(text); err != nil {
			t.Errorf("%s: %v", cmd, err)
		}
	}
}

func TestRuleDetailAndDelete(t *testing.T) {
	a, send, _, f := planAgent(t, "allow 22/tcp", "allow 80/tcp")
	pressOn(a, "list", trialMsg, callData(tgui.Open(scrFwRules)))
	list := send.lastEdit()
	if !strings.Contains(list.html, "<pre> 1 22/tcp     ALLOW Anywhere\n 2 80/tcp     ALLOW Anywhere\n"+
		" 3 22/tcp     ALLOW Anywhere v6\n 4 80/tcp     ALLOW Anywhere v6</pre>") {
		t.Fatalf("rules = %q", list.html)
	}
	pressOn(a, "ssh", trialMsg, buttonDataPrefix(list.kb, "#1"))
	if d := send.lastEdit(); !strings.Contains(d.html, "Matches 1 current SSH peer.") ||
		!strings.Contains(d.html, "Spec: <code>ufw allow 22/tcp</code>") || !strings.Contains(d.html, "Family   v4") {
		t.Errorf("rule 1 = %q", d.html)
	}
	// Deleting the rule that lets the owner in is refused outright.
	pressOn(a, "del22", trialMsg, buttonDataPrefix(send.lastEdit().kb, "🗑 Delete rule"))
	if d := send.lastEdit(); !strings.Contains(d.html, "⛔ <b>Refused</b>") || tokenData(d.kb, tgui.ActYes) != "" {
		t.Errorf("delete 22 = %q", d.html)
	}

	pressOn(a, "web", trialMsg, buttonDataPrefix(list.kb, "#2"))
	detail := send.lastEdit()
	if !strings.Contains(detail.html, "📋 <b>Rule #2</b>") || !strings.Contains(detail.html, "Matches 0 current SSH peers.") {
		t.Fatalf("rule 2 = %q", detail.html)
	}
	pressOn(a, "del", trialMsg, buttonDataPrefix(detail.kb, "🗑 Delete rule"))
	confirm := send.lastEdit()
	if !strings.Contains(confirm.html, "− 2 ALLOW 80/tcp\n    from Anywhere") || !strings.Contains(confirm.html, "− 4 ALLOW 80/tcp") {
		t.Fatalf("delete confirm = %q", confirm.html)
	}
	pressOn(a, "yes", trialMsg, tokenData(confirm.kb, tgui.ActYes))
	if got, want := f.ruleCalls(), []string{"--force delete allow 80/tcp", "reload"}; !slices.Equal(got, want) {
		t.Fatalf("rule calls = %q, want %q", got, want)
	}
	pressOn(a, "keep", trialMsg, buttonDataPrefix(lastEditKB(send), "✅ Keep"))
	if _, ok := pendingTrial(t, a); ok || !strings.Contains(send.lastEdit().html, "Kept") {
		t.Errorf("keep = %q", send.lastEdit().html)
	}

	// The old list's button now names a rule that is gone.
	pressOn(a, "stale", trialMsg, buttonDataPrefix(list.kb, "#2"))
	if d := send.lastEdit(); !strings.Contains(d.html, itemGoneBanner) || strings.Contains(d.html, "80/tcp") {
		t.Errorf("gone rule = %q", d.html)
	}
}

func TestPresets(t *testing.T) {
	a, send, _, f := planAgent(t, "allow 22/tcp")
	pressOn(a, "add", trialMsg, callData(tgui.Open(scrFwAdd)))
	kb := send.lastEdit().kb
	// The database presets only explain: there is no way to open them
	// to Anywhere from a button.
	for _, label := range []string{"🗄 Postgres", "🗄 Redis"} {
		data := buttonDataPrefix(kb, label)
		if !strings.HasPrefix(data, "~1v|fd|") {
			t.Errorf("%s = %q", label, data)
		}
		pressOn(a, label, trialMsg, data)
		if !strings.Contains(send.lastEdit().html, "never opened to Anywhere") || !strings.Contains(send.lastEdit().html, "/fw_allow 10.0.0.0/8 ") {
			t.Errorf("%s = %q", label, send.lastEdit().html)
		}
	}
	pressOn(a, "web", trialMsg, buttonDataPrefix(kb, "🌍 Web"))
	confirm := send.lastEdit()
	if !strings.Contains(confirm.html, "+ 2 ALLOW 80/tcp") || !strings.Contains(confirm.html, "+ 3 ALLOW 443/tcp") {
		t.Fatalf("web = %q", confirm.html)
	}
	pressOn(a, "cmds", trialMsg, buttonDataPrefix(confirm.kb, "🔍 Show commands"))
	if !strings.Contains(send.lastEdit().html, "<pre>ufw allow 80/tcp\nufw allow 443/tcp\nufw reload</pre>") {
		t.Errorf("web commands = %q", send.lastEdit().html)
	}
	pressOn(a, "ssh", trialMsg, buttonDataPrefix(kb, "🔐 SSH"))
	confirm = send.lastEdit()
	if !strings.Contains(confirm.html, "SSH: limit 22/tcp") || !strings.Contains(confirm.html, "− 1 ALLOW 22/tcp") ||
		!strings.Contains(confirm.html, "LIMIT 22/tcp") {
		t.Fatalf("ssh = %q", confirm.html)
	}
	pressOn(a, "yes", trialMsg, tokenData(confirm.kb, tgui.ActYes))
	if got, want := f.ruleCalls(), []string{"--force delete allow 22/tcp", "limit 22/tcp", "reload"}; !slices.Equal(got, want) {
		t.Errorf("rule calls = %q, want %q", got, want)
	}
	// Forged presets are outdated, not planned.
	for _, data := range []string{"~1fps|db", "~1fps", "~1frd|xyz", "~1frs|../../etc", "~1fx|nope"} {
		send.answered = nil
		pressOn(a, "forged", trialMsg, data)
		if !slices.Equal(send.answered, []string{"forged:" + outdatedToast}) {
			t.Errorf("%s: answered %v", data, send.answered)
		}
	}
}

// The guard runs again when Yes is pressed: a peer that connected since
// the plan was shown is protected, and rules changed since then stop it.
func TestPlanRecheckedAtApply(t *testing.T) {
	a, send, _, f := planAgent(t, "allow 22/tcp")
	_, kb := typed(t, a, send, "/fw_deny 198.51.100.0/24 22/tcp")
	f.setSS(adminPeer + "\n0 0 10.0.0.5:22 198.51.100.9:40000")
	pressOn(a, "yes", lastSentID(send), tokenData(kb, tgui.ActYes))
	if last := send.lastEdit(); !strings.Contains(last.html, "198.51.100.9") || !strings.Contains(last.html, "Refused") {
		t.Errorf("apply-time guard = %q", last.html)
	}
	if calls := f.ruleCalls(); len(calls) != 0 {
		t.Errorf("changed rules: %q", calls)
	}

	_, kb = typed(t, a, send, "/fw_open 8080/tcp")
	f.foreign("allow 9090/tcp")
	pressOn(a, "yes2", lastSentID(send), tokenData(kb, tgui.ActYes))
	if last := send.lastEdit(); !strings.Contains(last.html, "rules changed since this change was planned") {
		t.Errorf("drift = %q", last.html)
	}
	if calls := f.ruleCalls(); len(calls) != 0 {
		t.Errorf("changed rules: %q", calls)
	}
	if _, ok := pendingTrial(t, a); ok {
		t.Error("a trial started")
	}
}

// A plan is bound to the user who asked; it expires with its token.
func TestPlanBoundAndExpires(t *testing.T) {
	a, send, clk, f := planAgent(t, "allow 22/tcp")
	_, kb := typed(t, a, send, "/fw_open 8080/tcp")
	msg := lastSentID(send)
	edits := send.editCount()
	a.handleCallback(context.Background(), &telegram.Callback{ID: "x", ChatID: 42, FromID: 7, ChatType: "private", MessageID: msg,
		Data: buttonDataPrefix(kb, "🔍 Show commands")})
	if send.editCount() != edits {
		t.Error("another user revealed the commands")
	}
	clk.Advance(fwPlanTTL)
	pressOn(a, "yes", msg, tokenData(kb, tgui.ActYes))
	if !strings.Contains(send.lastEdit().html, "expired") || len(f.ruleCalls()) != 0 {
		t.Errorf("expired plan = %q, calls %q", send.lastEdit().html, f.ruleCalls())
	}
	if _, ok := a.fwPlans.get(confirmPlanID(t, kb), clk.Now()); ok {
		t.Error("plan outlived its TTL")
	}
}

// confirmPlanID is the plan ID a confirm keyboard's Show commands names.
func confirmPlanID(t *testing.T, kb telegram.Keyboard) string {
	t.Helper()
	c, err := tgui.Decode(buttonDataPrefix(kb, "🔍"))
	if err != nil || len(c.Args) == 0 {
		t.Fatalf("no plan in %s", dumpKeyboard(kb))
	}
	return c.Args[0]
}

func TestRestorePrevious(t *testing.T) {
	a, send, clk, f := planAgent(t, "allow 22/tcp", "allow 80/tcp")
	original := f.files()
	_, kb := typed(t, a, send, "/fw_open 8080/tcp")
	pressOn(a, "yes", lastSentID(send), tokenData(kb, tgui.ActYes))
	pressOn(a, "keep", lastSentID(send), buttonDataPrefix(lastEditKB(send), "✅ Keep"))
	if _, ok := pendingTrial(t, a); ok {
		t.Fatal("not kept")
	}
	changed := f.files()
	n := len(f.ruleCalls())

	pressOn(a, "list", trialMsg, callData(tgui.Open(scrFwRestore)))
	screen := send.lastEdit()
	if !strings.Contains(screen.html, "1 ") || !strings.Contains(screen.html, " 4 rules") {
		t.Fatalf("restore screen = %q", screen.html)
	}
	pressOn(a, "pick", trialMsg, buttonDataPrefix(screen.kb, "↩️ 1"))
	confirm := send.lastEdit()
	if !strings.Contains(confirm.html, "Restore the rules of snapshot") || !strings.Contains(confirm.html, "− 3 ALLOW 8080/tcp") ||
		!strings.Contains(confirm.html, "SSH check: ✅") {
		t.Fatalf("restore confirm = %q", confirm.html)
	}
	pressOn(a, "cmds", trialMsg, buttonDataPrefix(confirm.kb, "🔍 Show commands"))
	if !strings.Contains(send.lastEdit().html, "from snapshot ") || !strings.Contains(send.lastEdit().html, "user.rules") {
		t.Errorf("restore commands = %q", send.lastEdit().html)
	}
	pressOn(a, "yes", trialMsg, tokenData(confirm.kb, tgui.ActYes))
	if f.files() != original {
		t.Fatalf("restored:\n%s\nwant\n%s", f.files(), original)
	}
	rec, ok := pendingTrial(t, a)
	if !ok || !strings.HasPrefix(rec.What, "Restore the rules") {
		t.Fatalf("restore trial = %+v", rec)
	}
	// The restore only reloaded; the snapshot's specs undo it by spec.
	if got := f.ruleCalls()[n:]; !slices.Equal(got, []string{"reload"}) {
		t.Errorf("restore ran %q", got)
	}
	if want := (fwPlan{{Op: opDelete, Spec: []string{"allow", "8080/tcp"}}}); fmt.Sprint(rec.Plan) != fmt.Sprint(want) {
		t.Errorf("restore plan = %v, want %v", rec.Plan, want)
	}
	clk.Advance(125 * time.Second)
	if f.files() != changed {
		t.Errorf("restore not rolled back:\n%s\nwant\n%s", f.files(), changed)
	}
}

func TestRestoreRefusedWhenItBlocksSSH(t *testing.T) {
	a, send, _, f := planAgent(t, "allow from 203.0.113.4 to any port 22 proto tcp", "deny 22/tcp")
	// A snapshot from before the owner's allow: restoring it locks them out.
	_, kb := typed(t, a, send, "/fw_open 8080/tcp")
	pressOn(a, "yes", lastSentID(send), tokenData(kb, tgui.ActYes))
	if _, ok := pendingTrial(t, a); !ok {
		t.Fatal("no trial")
	}
	pressOn(a, "keep", lastSentID(send), buttonDataPrefix(lastEditKB(send), "✅ Keep"))
	rec := a.listSnapshots()[0]
	snap := filepath.Join(a.src.FwDir, rec.id)
	if err := os.WriteFile(filepath.Join(snap, snapStatusFile), []byte(planStatus([]string{"deny 22/tcp"}, nil)), 0o600); err != nil {
		t.Fatal(err)
	}
	n := len(f.ruleCalls())
	pressOn(a, "pick", trialMsg, "~1frs|"+rec.id)
	if d := send.lastEdit(); !strings.Contains(d.html, "⛔ <b>Refused</b>") || tokenData(d.kb, tgui.ActYes) != "" {
		t.Errorf("restore = %q", d.html)
	}
	if len(f.ruleCalls()) != n {
		t.Error("rules changed")
	}
}

func TestPruneKeepsNewestFiveSnapshots(t *testing.T) {
	a, _, clk, _ := planAgent(t)
	if err := os.MkdirAll(a.src.FwDir, 0o700); err != nil {
		t.Fatal(err)
	}
	for i := range 8 {
		id := fmt.Sprintf("0000000%d", i)
		dir := filepath.Join(a.src.FwDir, id)
		if err := os.Mkdir(dir, 0o700); err != nil {
			t.Fatal(err)
		}
		at := clk.Now().Add(-time.Duration(48+i) * time.Hour) // all past fwSnapKeep, 0 newest
		if i == 7 {
			at = clk.Now().Add(-time.Hour) // recent: kept whatever its rank
		}
		os.Chtimes(dir, at, at)
	}
	a.pruneSnapshots("00000006")
	var left []string
	for _, s := range a.listSnapshots() {
		left = append(left, s.id)
	}
	want := []string{"00000007", "00000000", "00000001", "00000002", "00000003", "00000006"}
	if !slices.Equal(left, want) {
		t.Errorf("left %v, want %v", left, want)
	}
}

// The 🛡 home of §3.8, and the buttons of older versions still on it.
func TestFirewallHomeAndLegacyButtons(t *testing.T) {
	a, send, _, f := planAgent(t, "allow 22/tcp", "allow 80/tcp")
	pressOn(a, "legacy", trialMsg, "firewall")
	home := send.lastEdit()
	for _, want := range []string{"🛡 <b>Firewall</b> · ufw active", "Default incoming policy: <b>deny</b>",
		"Your SSH peer: 203.0.113.4", "Rules: 4 (v4 2 · v6 2)"} {
		if !strings.Contains(home.html, want) {
			t.Errorf("home lacks %q: %q", want, home.html)
		}
	}
	for label, data := range map[string]string{"📋 Rules": "~1v|fl", "➕ Open port": "~1v|fa", "🧱 Presets": "~1v|fp", "↩️ Restore previous": "~1v|fh"} {
		if got := buttonDataPrefix(home.kb, label); got != data {
			t.Errorf("%s = %q, want %q", label, got, data)
		}
	}
	if buttonDataPrefix(home.kb, "🔒") != "" {
		t.Errorf("Close SSH without allow_close_ssh: %s", dumpKeyboard(home.kb))
	}
	for _, data := range []string{"fw_open_ask", "fw_open"} {
		pressOn(a, data, trialMsg, data)
		if !strings.Contains(send.lastEdit().html, "Open SSH port 22?") || tokenData(lastEditKB(send), tgui.ActYes) == "" {
			t.Errorf("%s = %q", data, send.lastEdit().html)
		}
	}
	pressOn(a, "yes", trialMsg, tokenData(lastEditKB(send), tgui.ActYes))
	if got := f.ruleCalls(); !slices.Equal(got, []string{"--force delete allow 22/tcp", "insert 1 allow 22/tcp", "reload"}) {
		t.Errorf("legacy open = %q", got)
	}
	if rec, ok := pendingTrial(t, a); !ok || rec.Action != actFwOpen || !strings.Contains(send.lastEdit().html, "port 22 opened") {
		t.Errorf("legacy open trial = %+v %q", rec, send.lastEdit().html)
	}
	// Planning is refused while that trial is pending.
	text, _ := typed(t, a, send, "/fw_open 8080/tcp")
	if !strings.Contains(text, "Another firewall change is on trial") {
		t.Errorf("plan during a trial = %q", text)
	}
}

func TestFwPlansStore(t *testing.T) {
	var s fwPlans
	now := time.Date(2026, 10, 15, 12, 0, 0, 0, time.UTC)
	for i := range fwMaxPlans + 3 {
		s.put(&fwPlanReq{id: fmt.Sprintf("%08x", i), expires: now.Add(fwPlanTTL)}, now)
	}
	if _, ok := s.get("00000000", now); ok {
		t.Error("oldest plan not evicted")
	}
	if _, ok := s.get(fmt.Sprintf("%08x", fwMaxPlans+2), now); !ok {
		t.Error("newest plan missing")
	}
	id := fmt.Sprintf("%08x", fwMaxPlans)
	if _, ok := s.take(id, now); !ok {
		t.Fatal("take")
	}
	if _, ok := s.take(id, now); ok {
		t.Error("a plan ran twice")
	}
	if _, ok := s.get(fmt.Sprintf("%08x", fwMaxPlans+1), now.Add(fwPlanTTL)); ok {
		t.Error("expired plan returned")
	}
}
