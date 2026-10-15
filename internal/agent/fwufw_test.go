package agent

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/eliau2005/statixagent/internal/dockermon"
)

// Real `ufw status verbose` output from an Ubuntu host where the SSH
// close button had appended `deny 22/tcp` after the OpenSSH profile rule.
const ufwVerboseOpenSSH = `Status: active
Logging: on (low)
Default: deny (incoming), allow (outgoing), disabled (routed)
New profiles: skip

To                         Action      From
--                         ------      ----
22/tcp (OpenSSH)           ALLOW IN    Anywhere
22/tcp                     DENY IN     Anywhere
80,443/tcp (Nginx Full)    ALLOW IN    Anywhere
5432/tcp                   ALLOW IN    10.0.0.0/8
Anywhere                   DENY IN     198.51.100.7
22/tcp (OpenSSH (v6))      ALLOW IN    Anywhere (v6)
22/tcp (v6)                DENY IN     Anywhere (v6)
`

// The same rules as plain `ufw status` prints them: app profiles are not
// expanded, so OpenSSH's port is unknown.
const ufwPlainOpenSSH = `Status: active

To                         Action      From
--                         ------      ----
OpenSSH                    ALLOW       Anywhere
22/tcp                     DENY        Anywhere
Nginx Full                 ALLOW       Anywhere
5432/tcp                   ALLOW       10.0.0.0/8
Anywhere                   DENY        198.51.100.7
OpenSSH (v6)               ALLOW       Anywhere (v6)
22/tcp (v6)                DENY        Anywhere (v6)
`

func TestParseUFWRows(t *testing.T) {
	s := parseUFWOutput(ufwVerboseOpenSSH)
	if !s.found || !s.active || s.policy != "deny" {
		t.Fatalf("status = found %v active %v policy %q", s.found, s.active, s.policy)
	}
	if len(s.rules) != 7 {
		t.Fatalf("rules = %d, want 7: %+v", len(s.rules), s.rules)
	}
	cases := []struct {
		num   int
		app   string
		ports []portRange
		proto string
		from  string
		v6    bool
	}{
		{1, "OpenSSH", []portRange{{22, 22}}, "tcp", "", false},
		{2, "", []portRange{{22, 22}}, "tcp", "", false},
		{3, "Nginx Full", []portRange{{80, 80}, {443, 443}}, "tcp", "", false},
		{4, "", []portRange{{5432, 5432}}, "tcp", "10.0.0.0/8", false},
		{5, "", nil, "", "198.51.100.7/32", false},
		{6, "OpenSSH", []portRange{{22, 22}}, "tcp", "", true},
		{7, "", []portRange{{22, 22}}, "tcp", "", true},
	}
	for _, tc := range cases {
		r := s.rules[tc.num-1]
		from := ""
		if r.From.IsValid() {
			from = r.From.String()
		}
		if r.Num != tc.num || r.App != tc.app || !slices.Equal(r.Ports, tc.ports) ||
			r.Proto != tc.proto || from != tc.from || r.V6 != tc.v6 || r.Dir != "in" || r.unresolved {
			t.Errorf("rule %d = %+v", tc.num, r)
		}
	}
}

func TestParseUFWRowForms(t *testing.T) {
	cases := []struct {
		name, row string
		want      fwRule
	}{
		{"numbered with comment", "[ 3] 22/tcp                     LIMIT IN    Anywhere                   # ssh limit",
			fwRule{Action: "limit", Dir: "in", Proto: "tcp", Ports: []portRange{{22, 22}}}},
		{"bare port", "22  ALLOW  Anywhere", fwRule{Action: "allow", Dir: "in", Ports: []portRange{{22, 22}}}},
		{"range", "6000:6007/udp  ALLOW IN  Anywhere", fwRule{Action: "allow", Dir: "in", Proto: "udp", Ports: []portRange{{6000, 6007}}}},
		{"outgoing", "22/tcp  DENY OUT  Anywhere", fwRule{Action: "deny", Dir: "out", Proto: "tcp", Ports: []portRange{{22, 22}}}},
		{"interface", "22/tcp on eth1  DENY IN  Anywhere", fwRule{Action: "deny", Dir: "in", Proto: "tcp", Ports: []portRange{{22, 22}}, Iface: "eth1"}},
		{"destination", "10.0.0.5 22/tcp  ALLOW IN  Anywhere",
			fwRule{Action: "allow", Dir: "in", Proto: "tcp", Ports: []portRange{{22, 22}}, Dst: netip.MustParsePrefix("10.0.0.5/32")}},
		{"v6 source", "22/tcp  ALLOW IN  2001:db8::/32",
			fwRule{Action: "allow", Dir: "in", Proto: "tcp", Ports: []portRange{{22, 22}}, From: netip.MustParsePrefix("2001:db8::/32"), V6: true}},
		{"plain app", "OpenSSH  ALLOW  Anywhere", fwRule{Action: "allow", Dir: "in", App: "OpenSSH", unresolved: true}},
		{"source port", "22/tcp  ALLOW IN  10.0.0.1 5000/tcp",
			fwRule{Action: "allow", Dir: "in", Proto: "tcp", Ports: []portRange{{22, 22}}, From: netip.MustParsePrefix("10.0.0.1/32"), partial: true}},
	}
	for _, tc := range cases {
		got, ok := parseUFWRow(tc.row)
		if !ok {
			t.Errorf("%s: not parsed", tc.name)
			continue
		}
		got.Raw = ""
		if fmt.Sprintf("%+v", got) != fmt.Sprintf("%+v", tc.want) {
			t.Errorf("%s:\n got %+v\nwant %+v", tc.name, got, tc.want)
		}
	}
	// Header, separator and settings lines are not rules, even though
	// "Default: deny (incoming)" carries an action word.
	for _, line := range []string{"To  Action  From", "--  ------  ----", "Default: deny (incoming), allow (outgoing)", "Logging: on (low)", ""} {
		if r, ok := parseUFWRow(line); ok {
			t.Errorf("%q parsed as rule %+v", line, r)
		}
	}
}

func TestUFWFirstMatch(t *testing.T) {
	head := "Status: active\nDefault: deny (incoming), allow (outgoing), disabled (routed)\n\n"
	anyPeer := netip.Addr{}
	cases := []struct {
		name     string
		rules    string
		port     int
		v6       bool
		peer     netip.Addr
		want     sshPortState
		wantRule int // 0 = decided by policy
		except   int
		unsure   int
	}{
		// The regression: "DENY wins" reported this host closed while
		// OpenSSH, listed first, kept SSH reachable.
		{"openssh before appended deny", ufwVerboseOpenSSH, 22, false, anyPeer, fwOpen, 1, 0, 0},
		{"openssh before appended deny, v6", ufwVerboseOpenSSH, 22, true, anyPeer, fwOpen, 6, 0, 0},
		{"deny first wins", "22/tcp DENY IN Anywhere\n22/tcp (OpenSSH) ALLOW IN Anywhere\n", 22, false, anyPeer, fwClosed, 1, 0, 0},
		{"limit is reachable", "22/tcp LIMIT IN Anywhere\n", 22, false, anyPeer, fwOpen, 1, 0, 0},
		{"bare port covers tcp", "22 ALLOW IN Anywhere\n", 22, false, anyPeer, fwOpen, 1, 0, 0},
		{"udp rule does not match", "22/udp ALLOW IN Anywhere\n", 22, false, anyPeer, fwUnmanaged, 0, 0, 0},
		{"range covers port", "20:30/tcp DENY IN Anywhere\n", 22, false, anyPeer, fwClosed, 1, 0, 0},
		{"all-ports allow", "Anywhere ALLOW IN Anywhere\n", 22, false, anyPeer, fwOpen, 1, 0, 0},
		{"out rule ignored", "22/tcp DENY OUT Anywhere\n", 22, false, anyPeer, fwUnmanaged, 0, 0, 0},
		{"v4 rules do not decide v6", "22/tcp ALLOW IN Anywhere\n", 22, true, anyPeer, fwUnmanaged, 0, 0, 0},
		// Source-restricted rules never decide for an arbitrary host, but
		// an allow among them is reported as an exception.
		{"source-restricted only", "22/tcp ALLOW IN 10.0.0.0/8\n", 22, false, anyPeer, fwUnmanaged, 0, 1, 0},
		{"source-restricted then deny", "22/tcp ALLOW IN 10.0.0.0/8\n22/tcp DENY IN Anywhere\n", 22, false, anyPeer, fwClosed, 2, 1, 0},
		{"deny from one host then allow", "Anywhere DENY IN 198.51.100.7\n22/tcp ALLOW IN Anywhere\n", 22, false, anyPeer, fwOpen, 2, 0, 0},
		{"interface-restricted deny", "22/tcp on eth1 DENY IN Anywhere\n22/tcp ALLOW IN Anywhere\n", 22, false, anyPeer, fwOpen, 2, 0, 0},
		// A specific peer is matched against the source.
		{"peer inside allowed cidr", "22/tcp ALLOW IN 10.0.0.0/8\n22/tcp DENY IN Anywhere\n", 22, false, netip.MustParseAddr("10.1.2.3"), fwOpen, 1, 0, 0},
		{"peer outside allowed cidr", "22/tcp ALLOW IN 10.0.0.0/8\n22/tcp DENY IN Anywhere\n", 22, false, netip.MustParseAddr("192.0.2.1"), fwClosed, 2, 0, 0},
		{"blocked peer", "Anywhere DENY IN 198.51.100.7\n22/tcp ALLOW IN Anywhere\n", 22, false, netip.MustParseAddr("198.51.100.7"), fwClosed, 1, 0, 0},
		// Plain status leaves app profiles unresolved: flagged, not guessed.
		{"plain status app profile", ufwPlainOpenSSH, 22, false, anyPeer, fwClosed, 2, 0, 1},
		{"other ssh port", "2222/tcp ALLOW IN Anywhere\n22/tcp DENY IN Anywhere\n", 2222, false, anyPeer, fwOpen, 1, 0, 0},
	}
	for _, tc := range cases {
		out := tc.rules
		if !strings.HasPrefix(out, "Status:") {
			out = head + out
		}
		v := parseUFWOutput(out).verdict(tc.port, tc.v6, tc.peer)
		num := 0
		if v.rule != nil {
			num = v.rule.Num
		}
		if v.state != tc.want || num != tc.wantRule || len(v.except) != tc.except || len(v.unsure) != tc.unsure {
			t.Errorf("%s: state %v rule %d except %d unsure %d; want %v %d %d %d",
				tc.name, v.state, num, len(v.except), len(v.unsure), tc.want, tc.wantRule, tc.except, tc.unsure)
		}
	}
}

func TestParseUFWStatusFirstMatch(t *testing.T) {
	cases := []struct {
		name string
		out  string
		want sshPortState
	}{
		{"openssh verbose before deny", ufwVerboseOpenSSH, fwOpen},
		{"source-restricted allow is not open", "Status: active\n\n22/tcp  ALLOW  10.0.0.0/8\n", fwUnmanaged},
		{"limit", "Status: active\n\n22/tcp  LIMIT  Anywhere\n", fwOpen},
		{"reject", "Status: active\n\n22/tcp  REJECT  Anywhere\n", fwClosed},
	}
	for _, tc := range cases {
		if got := parseUFWStatus(tc.out); got != tc.want {
			t.Errorf("%s: parseUFWStatus = %v, want %v", tc.name, got, tc.want)
		}
	}
}

func TestSSHPortParsers(t *testing.T) {
	if got := parseSSHDTPorts("port 22\nport 2222\naddressfamily any\nlistenaddress 0.0.0.0:22\n"); !slices.Equal(got, []int{22, 2222}) {
		t.Errorf("sshd -T ports = %v", got)
	}
	socket := "Listen=[::]:22 (Stream)\nActiveState=active\n\nListen=0.0.0.0:2200 (Stream)\nActiveState=inactive\n"
	if got := parseSocketListen(socket); !slices.Equal(got, []int{22}) {
		t.Errorf("socket ports = %v, want only the active socket's", got)
	}
	ss := `LISTEN 0      128          0.0.0.0:2222      0.0.0.0:*    users:(("sshd",pid=812,fd=3))
LISTEN 0      4096   127.0.0.53%lo:53        0.0.0.0:*    users:(("systemd-resolve",pid=500,fd=14))
LISTEN 0      128             [::]:2222         [::]:*    users:(("sshd",pid=812,fd=4))`
	if got := parseSSListen(ss); !slices.Equal(got, []int{2222, 2222}) {
		t.Errorf("ss ports = %v", got)
	}
	cfg := "# Port 22\nPort 2022\n  port   2023\nPort 99999\nListenAddress 0.0.0.0\n"
	if got := parseSSHDConfigPorts(cfg); !slices.Equal(got, []int{2022, 2023}) {
		t.Errorf("config ports = %v", got)
	}
}

// sshProbeRunner answers the SSH port probes; nil entries fail.
type sshProbeRunner map[string]string

func (s sshProbeRunner) Run(_ context.Context, name string, _ ...string) (string, error) {
	if out, ok := s[name]; ok {
		return out, nil
	}
	return "", &exec.Error{Name: name, Err: exec.ErrNotFound}
}

func TestSSHPortsUnion(t *testing.T) {
	a := testAgent(&fakeSender{})
	a.src.Runner = sshProbeRunner{
		"/usr/sbin/sshd": "port 2222\n",
		"systemctl":      "Listen=[::]:22 (Stream)\nActiveState=active\n",
		"ss":             `LISTEN 0 128 0.0.0.0:2200 0.0.0.0:* users:(("sshd",pid=8,fd=3))`,
	}
	a.src.SSHDConfig = func() string { return "Port 2222\n" }
	if got := a.sshPorts(t.Context()); !slices.Equal(got, []int{22, 2200, 2222}) {
		t.Errorf("sshPorts = %v", got)
	}
	// Every probe failing falls back to the default, never to "no SSH".
	a.src.Runner = sshProbeRunner{}
	a.src.SSHDConfig = nil
	if got := a.sshPorts(t.Context()); !slices.Equal(got, []int{22}) {
		t.Errorf("sshPorts with no probes = %v, want [22]", got)
	}
}

// verboseUFW fakes a ufw that knows `status verbose`, plus optional SSH
// port probes. Rule changes are recorded but change nothing, as on a host
// where an earlier rule shadows the one ufw appends.
type verboseUFW struct {
	plain, verbose string
	verboseErr     bool
	ssh            sshProbeRunner
	calls          [][]string
}

func (u *verboseUFW) Run(ctx context.Context, name string, args ...string) (string, error) {
	if name != "ufw" {
		return u.ssh.Run(ctx, name, args...)
	}
	u.calls = append(u.calls, args)
	switch {
	case len(args) == 1 && args[0] == "status":
		return u.plain, nil
	case len(args) == 2 && args[1] == "verbose":
		if u.verboseErr {
			return "ERROR: unknown option", errors.New("exit status 1")
		}
		return u.verbose, nil
	case args[0] == "reload":
		return "Firewall reloaded", nil
	}
	return "Rule added", nil
}

func TestFirewallViewOpenSSHProfile(t *testing.T) {
	a := testAgent(&fakeSender{})
	a.src.Runner = &verboseUFW{plain: ufwPlainOpenSSH, verbose: ufwVerboseOpenSSH}
	a.cfg.Firewall.AllowCloseSSH = true
	text, kb := a.firewallView(t.Context())

	if !strings.Contains(text, "🔓 <b>open</b>") || !strings.Contains(text, "rule 1: 22/tcp (OpenSSH) ALLOW IN Anywhere") {
		t.Errorf("OpenSSH profile must read as open, naming the rule: %q", text)
	}
	if strings.Contains(text, "<b>closed</b>") {
		t.Errorf("false closed: %q", text)
	}
	if !strings.Contains(text, "Default incoming policy: <b>deny</b>") {
		t.Errorf("default policy missing: %q", text)
	}
	// An open port offers Close.
	if buttonDataPrefix(kb, "🔒 Close") != "~1fc" || buttonDataPrefix(kb, "🔓 Open port 22") != "" {
		t.Errorf("keyboard = %+v", kb)
	}
}

func TestFirewallViewFallsBackToPlainStatus(t *testing.T) {
	a := testAgent(&fakeSender{})
	a.src.Runner = &verboseUFW{plain: ufwPlainOpenSSH, verboseErr: true}
	text, kb := a.firewallView(t.Context())

	// Without verbose the profile's port is unknown: the view says so
	// instead of silently trusting the later DENY.
	if !strings.Contains(text, "🔒 <b>closed</b>") || !strings.Contains(text, "ports are unknown") {
		t.Errorf("plain fallback view = %q", text)
	}
	if strings.Contains(text, "Default incoming policy") {
		t.Errorf("plain status has no policy line: %q", text)
	}
	if buttonDataPrefix(kb, "🔓 Open port 22") != "~1fo" {
		t.Errorf("keyboard = %+v", kb)
	}
}

func TestFirewallViewRestrictedAndOtherPorts(t *testing.T) {
	a := testAgent(&fakeSender{})
	verbose := "Status: active\nDefault: deny (incoming), allow (outgoing), disabled (routed)\n\n" +
		"22/tcp  ALLOW IN  10.0.0.0/8\n2222/tcp  LIMIT IN  Anywhere\n"
	a.src.Runner = &verboseUFW{plain: verbose, verbose: verbose,
		ssh: sshProbeRunner{"sshd": "port 2222\n"}}
	a.cfg.Firewall.AllowCloseSSH = true
	text, kb := a.firewallView(t.Context())

	for _, want := range []string{
		"default incoming policy <b>deny</b> applies (🔒 blocked)",
		"still allowed by rule 1: 22/tcp ALLOW IN 10.0.0.0/8",
		"sshd does not appear to accept connections on 22",
		"SSH port 2222: 🔓 <b>open</b> (rule 2: 2222/tcp LIMIT IN Anywhere)",
	} {
		if !strings.Contains(text, want) {
			t.Errorf("view missing %q:\n%s", want, text)
		}
	}
	// No rule decides 22: both buttons, as before.
	if buttonDataPrefix(kb, "🔓 Open port 22") != "~1fo" || buttonDataPrefix(kb, "🔒 Close") != "~1fc" {
		t.Errorf("keyboard = %+v", kb)
	}
}

// TestFirewallCloseVerifiesResult: ufw exiting 0 is not success. Here
// the rule changes take no effect, so the re-probe still finds the
// OpenSSH profile first: the result is "failed", and the trial is ended
// at once.
func TestFirewallCloseVerifiesResult(t *testing.T) {
	send := &fakeSender{}
	a := testAgent(send)
	ufw := &verboseUFW{plain: ufwPlainOpenSSH, verbose: ufwVerboseOpenSSH}
	a.src.Runner = ufw
	allowFw(t, a)
	if err := os.WriteFile(filepath.Join(a.src.UFWDir, "user.rules"), []byte("rules\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	id := confirmThrough(t, a, send, "fw_close_ask", 4)

	last := send.lastEdit()
	if !strings.Contains(last.html, "Change failed") || !strings.Contains(last.html, "port 22 is not closed") ||
		!strings.Contains(last.html, "rule 1 (22/tcp (OpenSSH) ALLOW IN Anywhere) matches first") ||
		!strings.Contains(last.html, "Rolled back") {
		t.Errorf("a shadowed close must be reported as failed: %q", last.html)
	}
	if strings.Contains(last.html, "ReadWritePaths") {
		t.Errorf("a shadowed rule is not a sandbox problem: %q", last.html)
	}
	if out := slowOutcome(t, send, id); strings.Contains(out, "Port 22 closed") {
		t.Errorf("a failed close must not report success: %q", out)
	}
	if a.FwTrialPending() {
		t.Error("a failed change left its trial pending")
	}
	// The corrected write path: insert at 1, then reload.
	var applied []string
	for _, c := range ufw.calls {
		if c[0] != "status" && c[0] != "show" {
			applied = append(applied, strings.Join(c, " "))
		}
	}
	if want := []string{"insert 1 deny 22/tcp", "reload"}; !slices.Equal(applied, want) {
		t.Errorf("ufw writes = %v, want %v", applied, want)
	}
}

func TestVerifySSHPort(t *testing.T) {
	probe := func(out string) ufwProbe {
		return ufwProbe{state: parseUFWStatus(out), fw: parseUFWOutput(out)}
	}
	closed := probe("Status: active\n\n22/tcp DENY IN Anywhere\n22/tcp (v6) DENY IN Anywhere (v6)\n")
	if f := verifySSHPort(closed, false); f != nil {
		t.Errorf("closed in both families must verify: %s", f.display())
	}
	if f := verifySSHPort(closed, true); f == nil {
		t.Error("an open request on a closed port must fail")
	}
	v6Open := probe("Status: active\n\n22/tcp DENY IN Anywhere\n22/tcp (v6) ALLOW IN Anywhere (v6)\n")
	if f := verifySSHPort(v6Open, false); f == nil || !strings.Contains(f.display(), "for IPv6") {
		t.Errorf("IPv6 still open must fail: %+v", f)
	}
	if f := verifySSHPort(ufwProbe{state: fwUnusable}, false); f == nil || !strings.Contains(f.display(), "could not read") {
		t.Errorf("an unreadable re-probe must fail: %+v", f)
	}
}

func TestFirewallDockerWarning(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `[{"Names":["/web"],"Ports":[
			{"IP":"0.0.0.0","PrivatePort":80,"PublicPort":8080,"Type":"tcp"},
			{"IP":"::","PrivatePort":80,"PublicPort":8080,"Type":"tcp"},
			{"IP":"127.0.0.1","PrivatePort":9000,"PublicPort":9000,"Type":"tcp"},
			{"PrivatePort":443,"Type":"tcp"}]}]`)
	}))
	defer srv.Close()
	a := testAgent(&fakeSender{})
	a.cfg.Monitors.Docker = true
	a.src.Docker = dockermon.New(srv.Client(), srv.URL)
	a.src.Runner = &verboseUFW{plain: "Status: active\n\n8080/tcp DENY IN Anywhere\n", verbose: "Status: active\n\n8080/tcp DENY IN Anywhere\n"}
	text, _ := a.firewallView(t.Context())

	if !strings.Contains(text, "Docker publishes 8080/tcp (web) — ufw does not filter these") {
		t.Errorf("docker warning missing: %q", text)
	}
	if strings.Contains(text, "9000") || strings.Contains(text, "443") {
		t.Errorf("loopback and unpublished ports are not exposed: %q", text)
	}
}
