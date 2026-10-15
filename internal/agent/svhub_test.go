package agent

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"

	"github.com/eliau2005/statixagent/internal/bot"
	"github.com/eliau2005/statixagent/internal/config"
	"github.com/eliau2005/statixagent/internal/dockermon"
	"github.com/eliau2005/statixagent/internal/netcheck"
	"github.com/eliau2005/statixagent/internal/services"
	"github.com/eliau2005/statixagent/internal/telegram"
	"github.com/eliau2005/statixagent/internal/tgui"
)

// unitRunner answers `systemctl list-units --all` with list and
// `systemctl show` for the units in show, counting the listings; every
// other command goes to next.
type unitRunner struct {
	next  services.Runner
	mu    sync.Mutex
	list  string
	show  map[string]string
	lists int
}

func (u *unitRunner) Run(ctx context.Context, name string, args ...string) (string, error) {
	u.mu.Lock()
	defer u.mu.Unlock()
	if name == "systemctl" && len(args) > 1 && args[0] == "list-units" && args[1] == "--all" {
		u.lists++
		return u.list, nil
	}
	if name == "systemctl" && len(args) > 0 && args[0] == "show" {
		if out, ok := u.show[args[len(args)-1]]; ok {
			return out, nil
		}
	}
	if u.next == nil {
		return "", errors.New("not installed")
	}
	return u.next.Run(ctx, name, args...)
}

func (u *unitRunner) listCalls() int {
	u.mu.Lock()
	defer u.mu.Unlock()
	return u.lists
}

// hubUnits is the screen fixtures' systemd: a failed unit, a hostile
// name, and units the Units list leaves out (inactive, not a service).
const hubUnits = "" +
	"cron.service loaded active running Regular background program processing daemon\n" +
	"nginx.service loaded active running A high performance web server\n" +
	"● postgresql.service loaded failed failed PostgreSQL RDBMS\n" +
	"ssh.service loaded active running OpenBSD Secure Shell server\n" +
	"apt-daily.timer loaded active waiting Daily apt download activities\n" +
	"rsync.service loaded inactive dead fast remote file copy\n" +
	"x<evil>&.service loaded activating start hostile\n"

// hubShow is `systemctl show` for the failed unit.
var hubShow = map[string]string{"postgresql.service": "LoadState=loaded\nActiveState=failed\nSubState=failed\nResult=exit-code\n" +
	"UnitFileState=enabled\nStateChangeTimestamp=Thu 2026-10-15 14:03:00 UTC\nNRestarts=3\nMemoryCurrent=[not set]\n"}

// fakeEngine is a Docker Engine API holding cts, inspected from inspect
// (by full ID), counting requests by path.
type fakeEngine struct {
	mu       sync.Mutex
	cts      []map[string]any
	inspect  map[string]string
	requests []string
	// posts records the actions (svaction.go), answered 204; logs is
	// every container's log output.
	posts []string
	logs  string
}

func (f *fakeEngine) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.requests = append(f.requests, r.URL.RequestURI())
	switch {
	case r.Method == http.MethodPost:
		f.posts = append(f.posts, r.URL.RequestURI())
		w.WriteHeader(http.StatusNoContent)
	case strings.HasSuffix(r.URL.Path, "/logs"):
		fmt.Fprint(w, f.logs)
	case r.URL.Path == "/containers/json":
		json.NewEncoder(w).Encode(f.cts)
	case strings.HasSuffix(r.URL.Path, "/stats"):
		fmt.Fprint(w, `{"cpu_stats":{"cpu_usage":{"total_usage":400000000},"system_cpu_usage":2000000000,"online_cpus":2},
			"precpu_stats":{"cpu_usage":{"total_usage":200000000},"system_cpu_usage":1000000000},
			"memory_stats":{"usage":314572800,"limit":1073741824,"stats":{"inactive_file":14572800}}}`)
	default:
		id := strings.TrimSuffix(strings.TrimPrefix(r.URL.Path, "/containers/"), "/json")
		if body, ok := f.inspect[id]; ok {
			fmt.Fprint(w, body)
			return
		}
		http.NotFound(w, r)
	}
}

func (f *fakeEngine) paths() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return slices.Clone(f.requests)
}

// Container IDs of the fixtures.
var (
	webID = "3f2a9b7c1d0e" + strings.Repeat("a", 52)
	apiID = "9c8b7a6f5e4d" + strings.Repeat("b", 52)
)

// dockerEngine starts the screen fixtures' Docker: web exited, api up.
func dockerEngine(t *testing.T) (*dockermon.Client, *fakeEngine) {
	t.Helper()
	f := &fakeEngine{
		cts: []map[string]any{
			{"Id": apiID, "Names": []string{"/api"}, "Image": "sha256:1", "State": "running", "Status": "Up 3 days"},
			{"Id": webID, "Names": []string{"/web"}, "Image": "sha256:2", "State": "exited", "Status": "Exited (1) 5 minutes ago"},
		},
		inspect: map[string]string{
			webID: `{"RestartCount":7,"Config":{"Image":"ghcr.io/acme/a-long-registry-path/web:1.4"},
				"State":{"Status":"exited","ExitCode":1,"StartedAt":"2026-10-15T13:00:00Z","FinishedAt":"2026-10-15T14:00:00Z"}}`,
			apiID: `{"RestartCount":0,"Config":{"Image":"ghcr.io/acme/api:2.0"},
				"State":{"Status":"running","StartedAt":"2026-10-12T14:05:00Z","FinishedAt":"0001-01-01T00:00:00Z","Health":{"Status":"healthy"}}}`,
		},
	}
	srv := httptest.NewServer(f)
	t.Cleanup(srv.Close)
	return dockermon.New(srv.Client(), srv.URL), f
}

// hubAgent is screenAgent with something in every hub kind: a failing
// HTTP check and one that errs, certificates expiring, failing and fine,
// a watched port nothing listens on, and processes up and down.
func hubAgent(t *testing.T, send *fakeSender) *Agent {
	t.Helper()
	a := screenAgent(t, send)
	a.cfg.Watch.Services = []string{"nginx", "postgresql.service", "gone.service"}
	a.cfg.Watch.HTTPChecks = []config.HTTPCheck{{URL: "https://api.example.com/hz"}, {URL: "http://down.example/<x>&"}}
	a.cfg.Watch.SSLHosts = []string{"example.com", "api.example.com:8443", "old.example"}
	a.cfg.Watch.Ports = []config.PortCheck{{Port: 1, Label: "<tcpmux>"}}
	a.cfg.Watch.Processes = []string{"postgres", "redis-server"}
	a.src.CheckCerts = func(_ context.Context, hosts []string) []netcheck.CertStatus {
		return []netcheck.CertStatus{
			{Host: "api.example.com:8443", DaysLeft: 61, NotAfter: screenEpoch.AddDate(0, 0, 61)},
			{Host: "example.com", DaysLeft: 12, NotAfter: screenEpoch.AddDate(0, 0, 12)},
			{Host: "old.example", Err: "x509: <expired>"},
		}
	}
	a.src.ProcFS = func(names []string) ([]services.Result, error) {
		return []services.Result{{Name: "postgres", State: services.StateOK, Detail: "2 running"},
			{Name: "redis-server", State: services.StateDown, Detail: "not running"}}, nil
	}
	// Every HTTP check answers 503 at once, or fails, without a network.
	prev := httpClient
	httpClient = &http.Client{Transport: roundTrip(func(r *http.Request) (*http.Response, error) {
		if r.URL.Host == "down.example" {
			return nil, errors.New("no route to <host>")
		}
		return &http.Response{StatusCode: 503, Body: http.NoBody, Request: r}, nil
	})}
	t.Cleanup(func() { httpClient = prev })
	return a
}

type roundTrip func(*http.Request) (*http.Response, error)

func (f roundTrip) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func TestGoldenServicesHub(t *testing.T) {
	ctx := context.Background()
	a := hubAgent(t, &fakeSender{})
	for _, tc := range []struct {
		name string
		c    tgui.Call
	}{
		{"hub", tgui.Open(scrServices)},
		{"failing", tgui.Open(scrFailing)},
		{"units", tgui.Open(scrUnits)},
		{"units_watched", tgui.Open(scrUnitsWatched)},
		{"unit", tgui.Call{Act: tgui.ActView, Args: []string{scrUnit, callbackDigest("postgresql.service")}, From: scrUnits}},
		{"unit_not_found", tgui.Call{Act: tgui.ActView, Args: []string{scrUnit, callbackDigest("gone.service")}, From: scrUnitsWatched}},
		{"unit_hostile", tgui.Call{Act: tgui.ActView, Args: []string{scrUnit, callbackDigest("x<evil>&.service")}, From: scrFailing}},
		{"unit_gone", tgui.Call{Act: tgui.ActView, Args: []string{scrUnit, callbackDigest("vanished.service")}, From: scrUnits}},
		{"docker", tgui.Open(scrDocker)},
		{"container_exited", tgui.Call{Act: tgui.ActView, Args: []string{scrContainer, webID[:12]}, From: scrDocker}},
		{"container_running", tgui.Call{Act: tgui.ActView, Args: []string{scrContainer, apiID[:12]}, From: scrDocker}},
		{"container_gone", tgui.Call{Act: tgui.ActView, Args: []string{scrContainer, "0123456789ab"}, From: scrDocker}},
		{"http", tgui.Open(scrHTTP)},
		{"certs", tgui.Open(scrSSL)},
		{"ports", tgui.Open(scrPorts)},
		{"procs", tgui.Open(scrProcs)},
	} {
		text, kb := a.screen(ctx, tc.c)
		checkGolden(t, "svhub__"+tc.name, text, kb)
	}
	// Nothing configured, no sources: every list says how to start.
	bare := testAgent(&fakeSender{})
	for _, id := range []string{scrServices, scrUnits, scrDocker, scrHTTP, scrSSL, scrPorts, scrProcs, scrFailing} {
		text, kb := bare.screen(ctx, tgui.Open(id))
		checkGolden(t, "svhub__bare_"+id, text, kb)
	}
}

// Every list makes one systemctl list-units call per render, and the
// Docker list one request with no inspect.
func TestServicesHubCalls(t *testing.T) {
	a := hubAgent(t, &fakeSender{})
	units := a.src.Runner.(*unitRunner)
	for _, id := range []string{scrUnits, scrUnitsWatched, scrServices, scrFailing} {
		before := units.listCalls()
		a.screen(context.Background(), tgui.Open(id))
		if n := units.listCalls() - before; n != 1 {
			t.Errorf("%s: %d list-units calls, want 1", id, n)
		}
	}

	client, f := dockerEngine(t)
	a.src.Docker = client
	a.screen(context.Background(), tgui.Open(scrDocker))
	if got := f.paths(); !slices.Equal(got, []string{"/containers/json?all=true"}) {
		t.Errorf("Docker list requests = %q, want the list only", got)
	}
	// The detail inspects that one container, lazily.
	a.screen(context.Background(), tgui.Call{Act: tgui.ActView, Args: []string{scrContainer, webID[:12]}})
	if got := f.paths()[1:]; !slices.Equal(got, []string{"/containers/json?all=true", "/containers/" + webID + "/json"}) {
		t.Errorf("Docker detail requests = %q", got)
	}
}

// longUnit is unit i of longUnits: 256 characters.
func longUnit(i int) string {
	return fmt.Sprintf("%s%04d.service", strings.Repeat("u", 256-len(".service")-4), i)
}

// longUnits is a systemd with n units whose names are 256 characters,
// every third one failed.
func longUnits(n int) string {
	var b strings.Builder
	for i := range n {
		name := longUnit(i)
		state := "active running"
		if i%3 == 0 {
			state = "failed failed"
		}
		fmt.Fprintf(&b, "%s loaded %s Unit number %d with <markup> & a long description\n", name, state, i)
	}
	return b.String()
}

// 300 units with 256-character names page within Telegram's limits, and
// each button opens its own unit.
func TestServicesHubManyLongUnits(t *testing.T) {
	send := &fakeSender{}
	a := hubAgent(t, send)
	a.src.Runner.(*unitRunner).list = longUnits(300)
	a.cfg.Watch.Services = nil
	pages := (300 + pageSize - 1) / pageSize
	seen := map[string]bool{}
	for p := 1; p <= pages; p++ {
		c := tgui.Call{Act: tgui.ActView, Args: []string{scrUnits, strconv.Itoa(p)}}
		res, err := a.ui.Show(context.Background(), c)
		if err != nil || res.Outcome != tgui.Shown {
			t.Fatalf("page %d: %v %v", p, res.Outcome, err)
		}
		if len(res.Text) > 4096 || len(telegram.FitEdit(res.Text)) != len(res.Text) {
			t.Errorf("page %d: %d bytes", p, len(res.Text))
		}
		if err := checkTelegramHTML(res.Text); err != nil {
			t.Errorf("page %d: %v", p, err)
		}
		for _, row := range bot.PreRows(res.Text) {
			if bot.Width(row) > bot.PreCols {
				t.Errorf("page %d: row %q is %d columns", p, row, bot.Width(row))
			}
		}
		checkButtons(t, a, fmt.Sprintf("page %d", p), res.Keyboard, a.ui.Screens())
		for _, row := range res.Keyboard {
			for _, b := range row {
				if strings.HasPrefix(b.Data, "~1v|"+scrUnit+"|") {
					seen[b.Data] = true
				}
			}
		}
	}
	// 100 failed units first, then the rest: every unit once.
	if len(seen) != 300 {
		t.Errorf("%d unit buttons across %d pages, want 300", len(seen), pages)
	}
	// A button opens exactly its unit.
	for data := range seen {
		c, _ := tgui.Decode(data)
		press(a, "u", data)
		text := send.lastEdit().html
		name := ""
		for i := range 300 {
			n := longUnit(i)
			if callbackDigest(n) == c.Args[1] {
				name = n
			}
		}
		if name == "" || !strings.HasPrefix(text, "🧩 <b>"+name+"</b>") {
			t.Fatalf("%s opened %.80q, want %.40q", data, text, name)
		}
		break
	}
}

// An item that vanished between the list and the press shows its list
// again, saying so, and the press is answered once.
func TestServicesHubVanishedItem(t *testing.T) {
	send := &fakeSender{}
	a := hubAgent(t, send)
	units := a.src.Runner.(*unitRunner)
	press(a, "c1", "~1v|"+scrUnits)
	data := ""
	for _, row := range send.lastEdit().kb {
		for _, b := range row {
			if b.Text == "❌ postgresql" {
				data = b.Data
			}
		}
	}
	if data != "~1v|ud|"+callbackDigest("postgresql.service")+"^un" {
		t.Fatalf("postgresql button = %q in\n%s", data, dumpKeyboard(send.lastEdit().kb))
	}
	units.mu.Lock()
	units.list = strings.Replace(units.list, "● postgresql.service loaded failed failed PostgreSQL RDBMS\n", "", 1)
	units.mu.Unlock()
	a.cfg.Watch.Services = []string{"nginx"}
	press(a, "c2", data)
	got := send.lastEdit()
	if !strings.HasPrefix(got.html, "⚠️ Item gone, refreshed\n🧩 <b>Units</b>") || strings.Contains(got.html, "postgresql") {
		t.Errorf("vanished unit: %q", got.html)
	}
	if !slices.Equal(send.answered, []string{"c1:", "c2:"}) {
		t.Errorf("answered = %v", send.answered)
	}

	// A container too.
	client, f := dockerEngine(t)
	a.src.Docker = client
	f.mu.Lock()
	f.cts = f.cts[:1]
	f.mu.Unlock()
	press(a, "c3", "~1v|cd|"+webID[:12]+"^dk")
	if got := send.lastEdit().html; !strings.HasPrefix(got, "⚠️ Item gone, refreshed\n🐳 <b>Docker</b> · 1 container") {
		t.Errorf("vanished container: %q", got)
	}
}

// Lists page at 8, failing first, and pages keep working past the end.
func TestServicesHubPaging(t *testing.T) {
	send := &fakeSender{}
	a := hubAgent(t, send)
	a.src.Runner.(*unitRunner).list = longUnits(20)
	a.cfg.Watch.Services = []string{longUnit(1), longUnit(3), "gone.service"}
	press(a, "c1", "~1v|un")
	first := send.lastEdit()
	if !strings.Contains(first.html, "· 21 units · 8 failing · 1/3") ||
		!strings.Contains(dumpKeyboard(first.kb), "[1/3] → ~1v|un|1  [Next ▶️] → ~1v|un|2") {
		t.Fatalf("page 1:\n%s\n%s", first.html, dumpKeyboard(first.kb))
	}
	// The failing units come first: the 7 failed, then the watched one
	// systemd does not list.
	if n := strings.Count(first.html, "❌"); n != 7 || !strings.Contains(first.html, "❔ gone") {
		t.Errorf("page 1 has %d failed units, want 7 and gone:\n%s", n, first.html)
	}
	press(a, "c2", "~1v|un|99")
	last := send.lastEdit()
	if !strings.Contains(last.html, "· 3/3") || !strings.Contains(dumpKeyboard(last.kb), "[◀️ Prev] → ~1v|un|2  [3/3] → ~1v|un|3") {
		t.Errorf("page 99:\n%s\n%s", last.html, dumpKeyboard(last.kb))
	}
	// Watched only, and back to all.
	press(a, "c3", "~1v|uw")
	if got := send.lastEdit().html; !strings.HasPrefix(got, "🧩 <b>Watched units</b> · 3 units · 2 failing\n") ||
		!strings.Contains(got, "⭐ uuu") {
		t.Errorf("watched only: %q", got)
	}
}

// The bare commands open the hub's views; with arguments they still
// manage the watch lists.
func TestServicesHubCommands(t *testing.T) {
	for cmd, id := range map[string]string{"/services": scrServices, "/docker": scrDocker, "/ssl": scrSSL, "/http": scrHTTP} {
		send := &fakeSender{}
		a := hubAgent(t, send)
		ctx := context.Background()
		reply, name, ok := a.router.Dispatch(ctx, telegram.Update{ChatID: 42, Text: cmd})
		if !ok {
			t.Fatalf("%s: not handled", cmd)
		}
		a.reply(ctx, name, reply)
		wantText, wantKB := a.screen(ctx, tgui.Open(id))
		if got := send.all(); len(got) != 1 || got[0] != wantText || dumpKeyboard(send.keyboards[0]) != dumpKeyboard(wantKB) {
			t.Errorf("%s: sent %q, want screen %q", cmd, got, id)
		}
	}
	a := hubAgent(t, &fakeSender{})
	if reply := dispatchText(t, a, "/ssl add new.example"); !strings.Contains(reply, "Watching new.example") {
		t.Errorf("/ssl add: %q", reply)
	}
	if reply := dispatchText(t, a, "/http add https://new.example/"); !strings.Contains(reply, "checking https://new.example/") {
		t.Errorf("/http add: %q", reply)
	}
	if reply := dispatchText(t, a, "/http remove https://new.example/"); !strings.Contains(reply, "stopped checking") {
		t.Errorf("/http remove: %q", reply)
	}
}

// Home's failing row and its Services button open the hub.
func TestHomeOpensServicesHub(t *testing.T) {
	a := hubAgent(t, &fakeSender{})
	_, kb := a.screen(context.Background(), tgui.Open(scrHome))
	dump := dumpKeyboard(kb)
	if !strings.Contains(dump, "failing] → ~1v|svf\n") || !strings.Contains(dump, "[🧩 Services] → ~1v|svc") {
		t.Errorf("home keyboard:\n%s", dump)
	}
}

// Certificates list failed checks first, then the soonest expiry.
func TestCertItemsOrder(t *testing.T) {
	a := hubAgent(t, &fakeSender{})
	items, err := a.certItems(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	var got []string
	for _, it := range sortItems(items) {
		got = append(got, it.icon()+" "+it.name+" "+it.status)
	}
	want := []string{"❌ old.example x509: <expired>", "⚠️ example.com 12d · Oct 27", "✅ api.example.com:8443 61d · Dec 15"}
	if !slices.Equal(got, want) {
		t.Errorf("certificates = %q, want %q", got, want)
	}
}
