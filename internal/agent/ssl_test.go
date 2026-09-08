package agent

import (
	"context"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/eliau2005/statixagent/internal/config"
	"github.com/eliau2005/statixagent/internal/netcheck"
)

func TestSSLCommand(t *testing.T) {
	send := &fakeSender{}
	a := testAgent(send)

	// Nothing watched yet: onboarding hint.
	if reply := dispatchText(t, a, "/ssl"); !strings.Contains(reply, "/ssl add") {
		t.Errorf("/ssl empty: %q", reply)
	}

	a.cfg.Watch.SSLHosts = []string{"good.example", "bad.example"}
	a.src.CheckCerts = func(_ context.Context, hosts []string) []netcheck.CertStatus {
		return []netcheck.CertStatus{
			{Host: "good.example", DaysLeft: 92, NotAfter: time.Date(2026, 9, 13, 0, 0, 0, 0, time.UTC)},
			{Host: "bad.example", Err: "connection refused"},
		}
	}
	reply := dispatchText(t, a, "/ssl")
	if !strings.Contains(reply, "92d") || !strings.Contains(reply, "connection refused") {
		t.Errorf("/ssl reply: %q", reply)
	}
	// Errors sort before healthy certs.
	if strings.Index(reply, "bad.example") > strings.Index(reply, "good.example") {
		t.Errorf("error host not listed first: %q", reply)
	}
}

func TestSSLAddRemove(t *testing.T) {
	send := &fakeSender{}
	a := testAgent(send)
	a.src.ConfigPath = filepath.Join(t.TempDir(), "config.toml")

	if reply := dispatchText(t, a, "/ssl add example.com"); !strings.Contains(reply, "Watching example.com") {
		t.Fatalf("/ssl add: %q", reply)
	}
	if reply := dispatchText(t, a, "/ssl add example.com"); !strings.Contains(reply, "already watched") {
		t.Errorf("duplicate add: %q", reply)
	}
	saved, err := config.Load(a.src.ConfigPath)
	if err != nil || len(saved.Watch.SSLHosts) != 1 || saved.Watch.SSLHosts[0] != "example.com" {
		t.Errorf("persisted hosts = %+v err=%v", saved.Watch.SSLHosts, err)
	}

	if reply := dispatchText(t, a, "/ssl remove nope.com"); !strings.Contains(reply, "not watched") {
		t.Errorf("remove unknown: %q", reply)
	}
	if reply := dispatchText(t, a, "/ssl remove example.com"); !strings.Contains(reply, "Removed example.com") {
		t.Errorf("remove: %q", reply)
	}
	if hosts := a.watchCopy().SSLHosts; len(hosts) != 0 {
		t.Errorf("hosts after remove = %v", hosts)
	}
}

func TestCheckCertsAlerts(t *testing.T) {
	send := &fakeSender{}
	a := testAgent(send)
	a.cfg.Watch.SSLHosts = []string{"soon", "verysoon", "old.example", "justdied.example", "fine", "broken"}
	a.src.CheckCerts = func(_ context.Context, hosts []string) []netcheck.CertStatus {
		return []netcheck.CertStatus{
			{Host: "soon", DaysLeft: 14},
			{Host: "verysoon", DaysLeft: 2},
			{Host: "old.example", DaysLeft: -5},
			{Host: "justdied.example", DaysLeft: -1},
			{Host: "fine", DaysLeft: 200},
			{Host: "broken", Err: "tls: handshake failure"},
		}
	}
	a.checkCerts(context.Background())

	for _, want := range []string{
		"soon expires in 14 days",
		"verysoon expires in 2 days",
		"old.example expired 5 days ago",
		"justdied.example expired less than a day ago",
		"handshake failure",
	} {
		if !send.find(want) {
			t.Errorf("missing alert %q in %v", want, send.all())
		}
	}
	if send.find("fine expires") {
		t.Errorf("healthy cert alerted: %v", send.all())
	}

	// Within the cooldown a second sweep stays silent.
	before := len(send.all())
	a.checkCerts(context.Background())
	if after := len(send.all()); after != before {
		t.Errorf("re-alerted within cooldown: %d -> %d messages", before, after)
	}
}
