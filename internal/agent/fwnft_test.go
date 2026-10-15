package agent

import (
	"context"
	"errors"
	"os/exec"
	"strings"
	"testing"

	"github.com/eliau2005/statixagent/internal/bot"
)

// `nft list ruleset` of a host firewalled by hand, with a comment that
// must come out escaped.
const nftRuleset = `table inet filter {
	chain input {
		type filter hook input priority filter; policy drop;
		ct state established,related accept
		iif "lo" accept comment "<&>"
		tcp dport 22 accept comment "ssh admin access from the office network"
		tcp dport { 80, 443 } accept
	}
	chain forward {
		type filter hook forward priority filter; policy drop;
	}
}
table ip nat {
	chain postrouting {
		type nat hook postrouting priority srcnat; policy accept;
		oifname "eth0" masquerade
	}
}
`

const iptablesRules = `-P INPUT DROP
-P FORWARD DROP
-P OUTPUT ACCEPT
-A INPUT -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
-A INPUT -p tcp -m tcp --dport 22 -j ACCEPT
`

// hostFw answers the detection probes: each field is that tool's output,
// "" when it is not installed.
type hostFw struct {
	ufw, firewalld, nft, iptables string
}

func (h hostFw) runner() runFunc {
	return func(name string, args ...string) (string, error) {
		out := ""
		switch {
		case strings.HasSuffix(name, "ufw"):
			out = h.ufw
		case strings.HasSuffix(name, "firewall-cmd"):
			if h.firewalld == "" {
				break
			}
			switch args[len(args)-1] {
			case "--state":
				if h.firewalld != "running" {
					return h.firewalld, errors.New("exit status 252")
				}
				return h.firewalld, nil
			case "--get-default-zone":
				return "public", nil
			case "--list-all":
				return "public (active)\n  target: default\n  services: ssh\n  ports: \n  rich rules: \n", nil
			}
			return "ssh\n  ports: 22/tcp\n", nil
		case strings.HasSuffix(name, "nft"):
			out = h.nft
		case strings.HasSuffix(name, "iptables"):
			out = h.iptables
		}
		if out == "" {
			return "", &exec.Error{Name: name, Err: exec.ErrNotFound}
		}
		return out, nil
	}
}

const ufwActive = "Status: active\n\nTo                         Action      From\n--                         ------      ----\n22/tcp                     ALLOW       Anywhere\n"

func TestDetectFwOrder(t *testing.T) {
	for _, tc := range []struct {
		name     string
		host     hostFw
		kind     string
		conflict bool
	}{
		{"ufw only", hostFw{ufw: ufwActive, nft: nftRuleset}, fwKindUFW, false},
		{"ufw and firewalld", hostFw{ufw: ufwActive, firewalld: "running"}, fwKindUFW, true},
		{"ufw inactive, firewalld", hostFw{ufw: "Status: inactive", firewalld: "running", nft: nftRuleset}, fwKindFirewalld, false},
		{"firewalld stopped, nft", hostFw{firewalld: "not running", nft: nftRuleset, iptables: iptablesRules}, fwKindNft, false},
		{"empty nft, iptables", hostFw{nft: "", iptables: iptablesRules}, fwKindIptables, false},
		{"nft without tables", hostFw{nft: "# nothing\n", iptables: "-P INPUT ACCEPT\n-P FORWARD ACCEPT\n-P OUTPUT ACCEPT\n"}, "", false},
		{"nothing", hostFw{}, "", false},
	} {
		a := testAgent(&fakeSender{})
		a.src.Runner = tc.host.runner()
		f := a.detectFw(context.Background())
		if f.kind != tc.kind || f.conflict != tc.conflict {
			t.Errorf("%s: kind %q conflict %v, want %q %v", tc.name, f.kind, f.conflict, tc.kind, tc.conflict)
		}
		managed := (tc.kind == fwKindUFW || tc.kind == fwKindFirewalld) && !tc.conflict
		if (f.refusal() == nil) != managed {
			t.Errorf("%s: refusal %+v", tc.name, f.refusal())
		}
	}
}

func TestReadOnlyRowsClip(t *testing.T) {
	var lines []string
	for range fwReadOnlyRows + 10 {
		lines = append(lines, "\t\t\t\t\t\tip saddr 198.51.100.0/24 tcp dport 22 counter drop", "")
	}
	rows := readOnlyRows(strings.Join(lines, "\n"))
	if len(rows) != fwReadOnlyRows+1 || rows[fwReadOnlyRows] != "… 10 more lines" ||
		rows[0] != "    ip saddr 198.51.100.0/24 tc…" {
		t.Errorf("rows = %q", rows)
	}
	for _, r := range rows {
		if bot.Width(r) > bot.PreCols {
			t.Errorf("row %q is %d columns", r, bot.Width(r))
		}
	}
}

func TestReadOnlyFirewallViews(t *testing.T) {
	for _, tc := range []struct {
		name  string
		host  hostFw
		wants []string
	}{
		{"nft", hostFw{ufw: "Status: inactive", nft: nftRuleset}, []string{
			"🛡 <b>Firewall</b> · nftables (read-only)", "manages ufw or firewalld only", "(2 tables, 3 chains)",
			"<pre>table inet filter {\n chain input {\n", "&lt;&amp;&gt;", "\n}</pre>", "ufw is installed but inactive."}},
		{"iptables", hostFw{iptables: iptablesRules}, []string{
			"🛡 <b>Firewall</b> · iptables (read-only)", "(2 rules)", "-A INPUT -p tcp -m tcp --dport …"}},
	} {
		a := testAgent(&fakeSender{})
		a.src.Runner = tc.host.runner()
		allowFw(t, a)
		text, kb := a.firewallView(context.Background())
		for _, want := range tc.wants {
			if !strings.Contains(text, want) {
				t.Errorf("%s: view lacks %q:\n%s", tc.name, want, text)
			}
		}
		for _, row := range bot.PreRows(text) {
			if bot.Width(row) > bot.PreCols {
				t.Errorf("%s: <pre> row %q is %d columns", tc.name, row, bot.Width(row))
			}
		}
		if err := checkTelegramHTML(text); err != nil {
			t.Errorf("%s: %v", tc.name, err)
		}
		// Only the footer: nothing that changes rules.
		if d := dumpKeyboard(kb); strings.Contains(d, "Rules") || strings.Contains(d, "Open") || len(kb) != 1 {
			t.Errorf("%s: keyboard = %s", tc.name, d)
		}
		if got := a.firewallSummary(context.Background()); got != strings.Split(tc.wants[0], " · ")[1] {
			t.Errorf("%s: summary = %q", tc.name, got)
		}
		// A typed change is refused, naming what enforces.
		reply := a.fwCommand("fw_open")(withActor(context.Background(), 42), []string{"8080/tcp"})
		if !strings.Contains(reply.Text, "manages ufw or firewalld only") {
			t.Errorf("%s: typed open = %q", tc.name, reply.Text)
		}
	}
}

func TestFirewallConflictMakesNoChange(t *testing.T) {
	a := testAgent(&fakeSender{})
	a.src.Runner = hostFw{ufw: ufwActive, firewalld: "running"}.runner()
	allowFw(t, a)
	text, kb := a.firewallView(context.Background())
	if !strings.Contains(text, "⚠️ Ufw and firewalld are both active") || !strings.Contains(text, "ufw active") {
		t.Errorf("view = %q", text)
	}
	if d := dumpKeyboard(kb); !strings.Contains(d, "[📋 Rules]") || strings.Contains(d, "Open") || strings.Contains(d, "Presets") {
		t.Errorf("keyboard = %s", d)
	}
	if got := a.firewallSummary(context.Background()); got != "ufw + firewalld conflict" {
		t.Errorf("summary = %q", got)
	}
	reply := a.fwCommand("fw_open")(withActor(context.Background(), 42), []string{"8080/tcp"})
	if !strings.Contains(reply.Text, "both active") {
		t.Errorf("typed open = %q", reply.Text)
	}
	if res := a.runFirewallTrial(context.Background(), true); !strings.Contains(res.text, "both active") || res.ok {
		t.Errorf("trial = %+v", res)
	}
}
