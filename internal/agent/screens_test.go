package agent

import (
	"context"
	"errors"
	"fmt"
	"maps"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/eliau2005/statixagent/internal/alert"
	"github.com/eliau2005/statixagent/internal/bot"
	"github.com/eliau2005/statixagent/internal/collect"
	"github.com/eliau2005/statixagent/internal/config"
	"github.com/eliau2005/statixagent/internal/dockermon"
	"github.com/eliau2005/statixagent/internal/procfs"
	"github.com/eliau2005/statixagent/internal/sshwatch"
	"github.com/eliau2005/statixagent/internal/sysfs"
	"github.com/eliau2005/statixagent/internal/telegram"
	"github.com/eliau2005/statixagent/internal/tgui"
)

// press sends one owner press of data in a private chat.
func press(a *Agent, id, data string) {
	a.handleCallback(context.Background(), &telegram.Callback{
		ID: id, ChatID: 42, ChatType: "private", FromID: 42, MessageID: 4, Data: data,
	})
}

// screenEpoch is the fixed clock of the screen fixtures.
var screenEpoch = time.Date(2026, 10, 15, 14, 5, 0, 0, time.UTC)

// hostile carries every character that breaks Telegram HTML.
const hostile = "<evil>&"

// geoServer answers every geo lookup with a hostile place name, so a
// public address renders deterministically and offline.
func geoServer(t *testing.T) *sshwatch.GeoResolver {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		fmt.Fprint(w, `{"status":"success","country":"<NL>","city":"A&B","isp":""}`)
	}))
	t.Cleanup(srv.Close)
	return &sshwatch.GeoResolver{Client: srv.Client(), BaseURL: srv.URL}
}

// screenAgent is an agent with something on every screen: readings,
// sessions (IPv4, full IPv6, a hostile user), SSH history over several
// pages, trusted sources from both lists, a ufw that has SSH open, an
// update on offer, a watched unit that cannot be checked, a systemd that
// lists units (one failed) and a Docker with one container down.
func screenAgent(t *testing.T, send *fakeSender) *Agent {
	t.Helper()
	cfg := testConfig()
	cfg.SSH.TrustedIPs = config.MustTrustedIPs("10.0.0.0/8", "192.168.1.0/24")
	cfg.Watch.Services = []string{"nginx.service"}
	a := New(cfg, send, nil, testAgent(send).src)
	a.now = func() time.Time { return screenEpoch }
	a.geo = geoServer(t)
	a.src.Hostname = "web-01" + hostile
	a.snap = collect.Snapshot{
		CPUTotal: collect.CPUUsage{Percent: 23},
		PerCore:  []collect.CPUUsage{{Name: "cpu0", Percent: 30}, {Name: "cpu1", Percent: 16}},
		Load:     procfs.LoadAvg{Load1: 0.41, Load5: 0.38, Load15: 0.3},
		Mem:      procfs.MemInfo{Total: 4 << 30, Available: 3 << 29, Buffers: 1 << 28, Cached: 1 << 28},
		Mounts: []collect.MountUsage{
			{MountPoint: "/", TotalBytes: 40 << 30, FreeBytes: 11 << 30, UsedPercent: 72},
			{MountPoint: "/var/lib/docker/overlay2/" + strings.Repeat("f", 64) + "/merged", TotalBytes: 100 << 30, FreeBytes: 59 << 30, UsedPercent: 41},
		},
		Net:     []collect.NetRate{{Name: "eth0", RxBytesPerSec: 1.2e6, TxBytesPerSec: 3e5, RxTotal: 5 << 30, TxTotal: 1 << 30}},
		Uptime:  12*24*time.Hour + 3*time.Hour,
		NumProc: 142,
	}
	a.thermal = sysfs.Thermal{Sensors: []sysfs.TempSensor{{Label: "Package id 0", Celsius: 54}}}
	a.power = sysfs.Power{HasAC: true, ACOnline: true, HasBattery: true,
		Batteries: []sysfs.Battery{{Name: "BAT0", Percent: 80, Status: "Charging", HealthPercent: 91}}}
	a.src.Runner = &unitRunner{
		next: ufwOnly("Status: active\n\nTo                         Action      From\n--                         ------      ----\n22/tcp                     ALLOW       Anywhere\n", nil),
		list: hubUnits, show: hubShow,
	}
	a.src.Docker, _ = dockerEngine(t)
	a.src.Sessions = func() ([]sshwatch.Session, error) {
		return []sshwatch.Session{
			{User: "alice", TTY: "pts/0", Host: "203.0.113.4", Since: screenEpoch.Add(-2 * time.Hour)},
			{User: "bob", TTY: "pts/1", Host: "2001:db8:ffff:ffff:ffff:ffff:ffff:ffff", Since: screenEpoch.Add(-5 * time.Minute)},
			{User: hostile, TTY: "pts/2", Host: "10.0.0.9", Since: screenEpoch.Add(-time.Minute)},
		}, nil
	}
	a.src.TopProcs = func(context.Context) ([]collect.Proc, error) {
		return []collect.Proc{{PID: 412, Comm: "postgres", CPUPercent: 31, RSSBytes: 412 << 20}, {PID: 9, Comm: hostile, CPUPercent: 4, RSSBytes: 96 << 20}}, nil
	}
	a.src.UpdateCheck = func(context.Context) (string, bool, error) { return "v1.9.0", true, nil }
	a.src.UpdateApply = func(context.Context) error { return nil }
	for i := 19; i >= 0; i-- { // oldest first, as the log is read
		e := sshwatch.Event{Kind: sshwatch.EventFailed, User: "root", IP: fmt.Sprintf("45.83.12.%d", i%11), Method: "password",
			At: screenEpoch.Add(-time.Duration(i) * time.Minute)}
		if i%5 == 0 {
			e = sshwatch.Event{Kind: sshwatch.EventLogin, User: "alice", IP: "203.0.113.4", Method: "publickey", At: e.At}
		}
		a.hist.Add(e)
	}
	a.hist.Add(sshwatch.Event{Kind: sshwatch.EventInvalidUser, User: hostile, IP: "2001:db8::9", InvalidUser: true, At: screenEpoch})
	for _, p := range []string{"203.0.113.4", "2001:db8::/32", "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff", "198.51.100.0/24",
		"198.51.100.7", "203.0.113.0/28", "2001:db8:1::1", "100.64.0.1", "100.64.0.2"} {
		if _, err := a.trustStore.Add(netip.MustParsePrefix(canonicalPrefix(p))); err != nil {
			t.Fatal(err)
		}
	}
	a.rebuildTrust()
	a.digest = digestStats{since: screenEpoch.Add(-24 * time.Hour), peakCPU: 88, peakMem: 70, alerts: 2, logins: 4, fails: 16}
	return a
}

// canonicalPrefix adds the host length to a bare address.
func canonicalPrefix(s string) string {
	if strings.Contains(s, "/") {
		return s
	}
	if strings.Contains(s, ":") {
		return s + "/128"
	}
	return s + "/32"
}

// screenCalls is every call worth rendering on a: each screen, and each
// page of the paged ones.
func screenCalls(a *Agent) []tgui.Call {
	var calls []tgui.Call
	for _, id := range a.ui.Screens() {
		calls = append(calls, tgui.Open(id))
		for p := 2; p <= 10; p++ {
			calls = append(calls, tgui.Call{Act: tgui.ActView, Args: []string{id, strconv.Itoa(p)}})
		}
	}
	return calls
}

func TestGoldenScreens(t *testing.T) {
	a := screenAgent(t, &fakeSender{})
	for _, id := range a.ui.Screens() {
		text, kb := a.screen(context.Background(), tgui.Open(id))
		checkGolden(t, "screen__"+id, text, kb)
	}
	for _, c := range []tgui.Call{
		{Act: tgui.ActView, Args: []string{scrHistory, "2"}},
		{Act: tgui.ActView, Args: []string{scrFailed, "2"}},
		{Act: tgui.ActView, Args: []string{scrTrusted, "2"}},
		{Act: tgui.ActView, Args: []string{scrTop}, From: scrCPU},
	} {
		text, kb := a.screen(context.Background(), c)
		name := strings.Join(c.Args, "_")
		if c.From != "" {
			name += "_from_" + c.From
		}
		checkGolden(t, "screen__"+name, text, kb)
	}
	// A bare host: nothing failing, no sessions source, nothing recorded.
	bare := testAgent(&fakeSender{})
	bare.now = func() time.Time { return screenEpoch }
	for _, id := range []string{scrHome, scrSecurity, scrSessions, scrHistory, scrFailed, scrTrusted, scrFirewall, scrUpdate} {
		text, kb := bare.screen(context.Background(), tgui.Open(id))
		checkGolden(t, "screen__"+id+"_bare", text, kb)
	}
}

// footerLabels is the fixed last row of every screen but these.
var footerLabels = map[string][]string{
	scrHome: {"▶️ Live", "🔄 Refresh"},
	scrHelp: {"🏠 Home"},
	"":      {"⬅️ Back", "🏠 Home", "🔄 Refresh"},
}

// TestScreenInvariants renders every registered screen and page on a
// populated host, a bare one and a crowded one, and checks the rules of
// docs/telegram-ux-redesign.md §2 and §4.4 on each.
func TestScreenInvariants(t *testing.T) {
	crowded := screenAgent(t, &fakeSender{})
	var many []sshwatch.Session
	for i := range 300 {
		many = append(many, sshwatch.Session{User: strings.Repeat("u", 256), TTY: fmt.Sprintf("pts/%d", i),
			Host: fmt.Sprintf("2001:db8::%x", i), Since: screenEpoch.Add(-time.Hour)})
	}
	crowded.src.Sessions = func() ([]sshwatch.Session, error) { return many, nil }
	for i := range 300 {
		crowded.hist.Add(sshwatch.Event{Kind: sshwatch.EventFailed, User: strings.Repeat("x", 256),
			IP: fmt.Sprintf("2001:db8:ffff:ffff:ffff:ffff:ffff:%x", i), At: screenEpoch})
	}
	crowded.cfg.Watch.Services = []string{strings.Repeat("s", 250) + ".service"}
	crowded.src.Runner.(*unitRunner).list = longUnits(300)
	engine := &fakeEngine{}
	for i := range 100 {
		engine.cts = append(engine.cts, map[string]any{"Id": fmt.Sprintf("%064x", i+1), "Names": []string{"/" + strings.Repeat("c", 200) + strconv.Itoa(i)},
			"State": "exited", "Status": "Exited (137) 1 hour ago"})
	}
	srv := httptest.NewServer(engine)
	t.Cleanup(srv.Close)
	crowded.src.Docker = dockermon.New(srv.Client(), srv.URL)

	agents := map[string]*Agent{"populated": screenAgent(t, &fakeSender{}), "bare": testAgent(&fakeSender{}), "crowded": crowded}
	for name, a := range agents {
		screens := a.ui.Screens()
		for _, c := range screenCalls(a) {
			where := name + " " + strings.Join(c.Args, "|")
			id := c.Args[0]
			res, err := a.ui.Show(context.Background(), c)
			if err != nil || res.Outcome != tgui.Shown {
				t.Errorf("%s: not shown: %v %v", where, res.Outcome, err)
				continue
			}
			fitted := telegram.FitEdit(res.Text)
			if len(fitted) > 4096 {
				t.Errorf("%s: %d bytes after FitEdit", where, len(fitted))
			}
			if err := checkTelegramHTML(fitted); err != nil {
				t.Errorf("%s: invalid HTML after FitEdit: %v", where, err)
			}
			if err := checkTelegramHTML(res.Text); err != nil {
				t.Errorf("%s: invalid HTML: %v", where, err)
			}
			for _, row := range bot.PreRows(res.Text) {
				if bot.Width(row) > bot.PreCols {
					t.Errorf("%s: <pre> row %q is %d columns", where, row, bot.Width(row))
				}
			}
			checkButtons(t, a, where, res.Keyboard, screens)
			want, ok := footerLabels[id]
			if !ok {
				want = footerLabels[""]
			}
			last := res.Keyboard[len(res.Keyboard)-1]
			var got []string
			for _, b := range last {
				got = append(got, b.Text)
			}
			if !slices.Equal(got, want) {
				t.Errorf("%s: footer %v, want %v", where, got, want)
			}
			if refresh := last[len(last)-1]; id != scrHelp && refresh.Data != callData(c) {
				t.Errorf("%s: Refresh %q does not re-open %q", where, refresh.Data, callData(c))
			}
		}
	}
}

// checkButtons checks every button of kb: it encodes within Telegram's
// limits, routes to something registered, and says what it does in text.
func checkButtons(t *testing.T, a *Agent, where string, kb telegram.Keyboard, screens []string) {
	t.Helper()
	for _, row := range kb {
		if len(row) == 0 {
			t.Errorf("%s: empty row", where)
		}
		for _, b := range row {
			if !strings.ContainsFunc(b.Text, func(r rune) bool {
				return r < 0x2000 && (r == '%' || 'a' <= r && r <= 'z' || 'A' <= r && r <= 'Z' || '0' <= r && r <= '9')
			}) {
				t.Errorf("%s: button %q has no text, only symbols", where, b.Text)
			}
			if b.Style != "" && b.Style != "danger" && b.Style != "success" && b.Style != "primary" {
				t.Errorf("%s: button %q has style %q", where, b.Text, b.Style)
			}
			if b.Copy != "" {
				if len([]rune(b.Copy)) > 256 || b.Data != "" {
					t.Errorf("%s: copy button %q is malformed", where, b.Text)
				}
				continue
			}
			if len(b.Data) == 0 || len(b.Data) > tgui.MaxData {
				t.Errorf("%s: button %q data %q is %d bytes", where, b.Text, b.Data, len(b.Data))
				continue
			}
			if !tgui.IsCall(b.Data) {
				if _, ok := legacyViews[b.Data]; ok {
					t.Errorf("%s: button %q sends retired navigation token %q", where, b.Text, b.Data)
				}
				if _, ok := a.legacy.Lookup(b.Data); !ok {
					t.Errorf("%s: legacy data %q of %q routes nowhere", where, b.Data, b.Text)
				}
				continue
			}
			c, err := tgui.Decode(b.Data)
			if err != nil {
				t.Errorf("%s: %q does not decode: %v", where, b.Data, err)
				continue
			}
			if enc := callData(c); enc != b.Data {
				t.Errorf("%s: %q re-encodes as %q", where, b.Data, enc)
			}
			_, ask := a.asks[c.Act]
			_, act := a.acts[c.Act]
			live := c.Act == actLive || c.Act == actLiveStop
			if !ask && !act && !live && !a.ui.Known(c.Act) {
				t.Errorf("%s: act %q of %q is not registered", where, c.Act, b.Text)
			}
			if (c.Act == tgui.ActView || c.Act == tgui.ActOpen) && !slices.Contains(screens, c.Args[0]) {
				t.Errorf("%s: %q opens unregistered screen %q", where, b.Text, c.Args[0])
			}
			if c.From != "" && !slices.Contains(screens, c.From) {
				t.Errorf("%s: %q goes back to unregistered %q", where, b.Text, c.From)
			}
		}
	}
}

// Ask acts, config acts and the built-in acts share one namespace.
func TestAskActsDistinct(t *testing.T) {
	a := testAgent(&fakeSender{})
	acts := slices.Collect(maps.Keys(a.asks))
	for act := range a.acts {
		acts = append(acts, act)
		if _, ask := a.asks[act]; ask {
			t.Errorf("config act %q is also an ask act", act)
		}
	}
	for _, act := range acts {
		if a.ui.Known(act) || act == tgui.ActYes || act == tgui.ActNo {
			t.Errorf("act %q collides", act)
		}
		if _, err := tgui.Encode(tgui.Call{Act: act}); err != nil {
			t.Errorf("ask act %q: %v", act, err)
		}
	}
}

func TestCallHomeToCPUAndBack(t *testing.T) {
	send := &fakeSender{}
	a := screenAgent(t, send)
	follow := func(id, label string) edit {
		t.Helper()
		kb := send.lastEdit().kb
		for _, row := range kb {
			for _, b := range row {
				if b.Text == label {
					press(a, id, b.Data)
					return send.lastEdit()
				}
			}
		}
		t.Fatalf("no %q button in %s", label, dumpKeyboard(kb))
		return edit{}
	}
	press(a, "c1", "~1v|home")
	if !strings.HasPrefix(send.lastEdit().html, "🏠 <b>web-01&lt;evil&gt;&amp;</b> · up 12d 3h · 14:05") {
		t.Fatalf("home = %q", send.lastEdit().html)
	}
	if e := follow("c2", "📈 Metrics"); !strings.HasPrefix(e.html, "📈 <b>Metrics</b>") {
		t.Fatalf("metrics = %q", e.html)
	}
	if e := follow("c3", "🖥 CPU"); !strings.Contains(e.html, "<b>CPU</b>") {
		t.Fatalf("cpu = %q", e.html)
	}
	// Top opened from CPU goes Back to CPU; CPU goes Back to Metrics.
	if e := follow("c4", "🔝 Top processes"); !strings.Contains(e.html, "Top processes") {
		t.Fatalf("top = %q", e.html)
	}
	if e := follow("c5", "⬅️ Back"); !strings.Contains(e.html, "<b>CPU</b>") {
		t.Fatalf("back from top = %q", e.html)
	}
	if e := follow("c6", "⬅️ Back"); !strings.HasPrefix(e.html, "📈 <b>Metrics</b>") {
		t.Fatalf("back from cpu = %q", e.html)
	}
	if e := follow("c7", "🏠 Home"); !strings.HasPrefix(e.html, "🏠 ") {
		t.Fatalf("home button = %q", e.html)
	}
	if len(send.answered) != 7 {
		t.Errorf("answered = %v, want each press answered once", send.answered)
	}
	if len(send.all()) != 0 {
		t.Errorf("views must edit in place, sent %v", send.all())
	}
}

// Every screen is reachable by button from Home.
func TestEveryScreenReachable(t *testing.T) {
	a := screenAgent(t, &fakeSender{})
	// The logs screens open from the first unit and container listed,
	// once service actions allow them.
	a.cfg.Actions = config.Actions{Enabled: true, Allow: []string{"postgresql", "web"}}
	seen := map[string]bool{scrHome: true}
	queue := []tgui.Call{tgui.Open(scrHome)}
	for len(queue) > 0 {
		c := queue[0]
		queue = queue[1:]
		_, kb := a.screen(context.Background(), c)
		for _, row := range kb {
			for _, b := range row {
				next, err := tgui.Decode(b.Data)
				if err != nil || next.Act != tgui.ActView || seen[next.Args[0]] {
					continue
				}
				seen[next.Args[0]] = true
				queue = append(queue, next)
			}
		}
	}
	for _, id := range a.ui.Screens() {
		if !seen[id] {
			t.Errorf("screen %q is reachable by no button", id)
		}
	}
}

func TestCallKeepsFrom(t *testing.T) {
	send := &fakeSender{}
	a := testAgent(send)

	// Opened from another screen, Back and Refresh both remember it.
	press(a, "c1", "~1v|top^cpu")
	kb := send.lastEdit().kb
	want := "[⬅️ Back] → ~1v|cpu  [🏠 Home] → ~1v|home  [🔄 Refresh] → ~1v|top^cpu\n"
	if got := dumpKeyboard(kb[len(kb)-1:]); got != want {
		t.Errorf("footer:\n%s\nwant:\n%s", got, want)
	}
}

func TestCallPaging(t *testing.T) {
	send := &fakeSender{}
	a := screenAgent(t, send)
	press(a, "c1", "~1v|his")
	first := send.lastEdit()
	if !strings.Contains(dumpKeyboard(first.kb), "[1/3] → ~1v|his|1  [Next ▶️] → ~1v|his|2") {
		t.Fatalf("page 1 keyboard:\n%s", dumpKeyboard(first.kb))
	}
	press(a, "c2", "~1v|his|3")
	last := send.lastEdit()
	if !strings.Contains(dumpKeyboard(last.kb), "[◀️ Prev] → ~1v|his|2  [3/3] → ~1v|his|3\n") || last.html == first.html {
		t.Fatalf("page 3 keyboard:\n%s", dumpKeyboard(last.kb))
	}
	// Pages out of range clamp; they never fail.
	press(a, "c3", "~1v|his|99")
	if send.lastEdit().html != last.html {
		t.Errorf("page 99 = %q, want the last page", send.lastEdit().html)
	}
}

// Old bare navigation tokens, still on keyboards in chats, open the
// screens that replaced them, in place.
func TestLegacyNavTokensRoute(t *testing.T) {
	for token, id := range legacyViews {
		send := &fakeSender{}
		a := screenAgent(t, send)
		press(a, "c", token)
		wantText, wantKB := a.screen(context.Background(), tgui.Open(id))
		got := send.lastEdit()
		if got.html != wantText || dumpKeyboard(got.kb) != dumpKeyboard(wantKB) {
			t.Errorf("%q: got\n%s\n%s\nwant screen %q:\n%s\n%s", token, got.html, dumpKeyboard(got.kb), id, wantText, dumpKeyboard(wantKB))
		}
		if !slices.Equal(send.answered, []string{"c:"}) {
			t.Errorf("%q: answered = %v", token, send.answered)
		}
	}
	// The other old entry points too.
	for token, want := range map[string]string{"settings": "⚙️ <b>Settings</b>", "firewall": "🛡 <b>Firewall</b>"} {
		send := &fakeSender{}
		a := screenAgent(t, send)
		press(a, "c", token)
		if !strings.HasPrefix(send.lastEdit().html, want) {
			t.Errorf("%q: %q", token, send.lastEdit().html)
		}
	}
}

// Typed commands reply with the screens they map to.
func TestCommandsReplyWithScreens(t *testing.T) {
	for cmd, id := range map[string]string{
		"/status": scrHome, "/metrics": scrMetrics, "/security": scrSecurity, "/cpu": scrCPU,
		"/ssh": scrSessions, "/ssh history": scrHistory, "/ssh fails": scrFailed, "/ssh_fails": scrFailed,
		"/trusted": scrTrusted, "/firewall": scrFirewall, "/settings": scrSettings, "/update": scrUpdate,
		"/help": scrHelp, "/digest": scrDigest, "/start cpu": scrCPU, "/start ses": scrSessions,
		"/start nope": scrHome, "/start <b>": scrHome, "/start update_confirm": scrHome,
		"/watching": scrWatching, "/services_scan": scrScanServices, "/ports_scan": scrScanPorts, "/start wat": scrWatching,
	} {
		send := &fakeSender{}
		a := screenAgent(t, send)
		ctx := context.Background()
		reply, name, ok := a.router.Dispatch(ctx, telegram.Update{ChatID: 42, Text: cmd})
		if !ok {
			t.Fatalf("%s: not handled", cmd)
		}
		a.reply(ctx, name, reply)
		wantText, wantKB := a.screen(ctx, tgui.Open(id))
		if got := send.all(); len(got) != 1 || got[0] != wantText || dumpKeyboard(send.keyboards[0]) != dumpKeyboard(wantKB) {
			t.Errorf("%s: sent %q with\n%s\nwant screen %q", cmd, got, dumpKeyboard(send.keyboards[0]), id)
		}
	}
}

func TestCommandMenuHasSections(t *testing.T) {
	var names []string
	for _, c := range commandMenu {
		names = append(names, c.Command)
		if _, ok := commandScreens[c.Command]; ok && !isView(c.Command, nil) {
			t.Errorf("/%s opens a screen but is not classified as a view", c.Command)
		}
	}
	for _, want := range []string{"status", "metrics", "security", "settings"} {
		if !slices.Contains(names, want) {
			t.Errorf("command menu lacks /%s", want)
		}
	}
}

// Decision 1a: an alert's view buttons send a new message replying to
// the alert; the alert itself, text and keyboard, is never touched.
func TestAlertViewsOpenNewMessages(t *testing.T) {
	send := &fakeSender{}
	a := screenAgent(t, send)
	ctx := context.Background()
	alertID, err := a.pushAlertKB(ctx, alert.Alert{Key: "cpu", Title: "CPU usage", Body: "97%"}, a.alertKeyboard("cpu"))
	if err != nil {
		t.Fatal(err)
	}
	kb := send.keyboards[0]
	for i, b := range kb[0] { // the views; snooze is the row below
		cb := &telegram.Callback{ID: fmt.Sprint("v", i), ChatID: 42, ChatType: "private", FromID: 42, MessageID: alertID, Data: b.Data}
		a.handleCallback(ctx, cb)
		sent := send.all()
		if len(sent) != i+2 || send.replyTo[i+1] != alertID {
			t.Fatalf("%s: sent %d messages, replying to %v; want a reply to %d", b.Text, len(sent), send.replyTo, alertID)
		}
		id, _ := tgui.Decode(b.Data)
		wantText, wantKB := a.screen(ctx, tgui.Open(id.Args[0]))
		if sent[i+1] != wantText || dumpKeyboard(send.keyboards[i+1]) != dumpKeyboard(wantKB) {
			t.Errorf("%s: new message %q, want screen %q", b.Text, sent[i+1], id.Args[0])
		}
	}
	// Snooze changes only the alert's keyboard; the views never edit it.
	a.handleCallback(ctx, &telegram.Callback{ID: "s", ChatID: 42, ChatType: "private", FromID: 42, MessageID: alertID, Data: kb[1][0].Data})
	if len(send.edits) != 0 || len(send.markups) != 1 || send.markups[0].id != alertID {
		t.Errorf("the alert was edited: %v %v", send.edits, send.markups)
	}
	if len(send.answered) != len(kb[0])+1 {
		t.Errorf("answered = %v, want each press once", send.answered)
	}

	// A failed send says so, once.
	failing := &failingReplySender{fakeSender: &fakeSender{}}
	b := New(testConfig(), failing, nil, testAgent(failing.fakeSender).src)
	b.handleCallback(ctx, &telegram.Callback{ID: "f", ChatID: 42, MessageID: 9, Data: "~1o|cpu"})
	if !slices.Equal(failing.answered, []string{"f:" + openFailedToast}) {
		t.Errorf("answered = %v", failing.answered)
	}
}

// failingReplySender fails every send.
type failingReplySender struct{ *fakeSender }

func (f *failingReplySender) SendReplyKB(context.Context, int64, int64, string, telegram.Keyboard) (int64, error) {
	return 0, hostileErr
}

// The Untrust buttons on the Trusted IPs screen go through a confirm
// token; config entries and forged data are refused.
func TestUntrustFlow(t *testing.T) {
	send := &fakeSender{}
	a := screenAgent(t, send)
	ctx := context.Background()
	press(a, "c0", "~1v|tru")
	data := ""
	for _, row := range send.lastEdit().kb {
		for _, b := range row {
			if b.Text == "🗑 203.0.113.4" {
				data = b.Data
			}
		}
	}
	if data != "~1ut|203.0.113.4" {
		t.Fatalf("untrust button = %q in\n%s", data, dumpKeyboard(send.lastEdit().kb))
	}
	before := a.trustStore.Len()
	press(a, "c1", data)
	ask := send.lastEdit()
	if !strings.Contains(ask.html, "Untrust <code>203.0.113.4</code>?") || a.trustStore.Len() != before {
		t.Fatalf("ask = %q", ask.html)
	}
	// Cancel changes nothing and returns to the list.
	press(a, "c2", tokenData(ask.kb, tgui.ActNo))
	if a.trustStore.Len() != before || !strings.HasPrefix(send.lastEdit().html, "🤝 <b>Trusted IPs</b>") {
		t.Fatalf("cancel: %d entries, %q", a.trustStore.Len(), send.lastEdit().html)
	}
	press(a, "c3", data)
	a.handleCallback(ctx, &telegram.Callback{ID: "c4", ChatID: 42, ChatType: "private", FromID: 42, MessageID: 4,
		Data: tokenData(send.lastEdit().kb, tgui.ActYes)})
	out := send.lastEdit().html
	if a.trustStore.Len() != before-1 || slices.Contains(a.trustStore.Entries(), netip.MustParsePrefix("203.0.113.4/32")) ||
		!strings.Contains(out, "🧾 Source untrusted · 203.0.113.4") || !strings.Contains(out, "🗑 Removed") {
		t.Errorf("after Yes: %d entries, %q", a.trustStore.Len(), out)
	}

	for _, forged := range []string{"~1ut|10.0.0.0/8", "~1ut|0.0.0.0/0", "~1ut|010.0.0.7", "~1ut|::ffff:10.0.0.7", "~1ut", "~1ut|a|b"} {
		send := &fakeSender{}
		a := screenAgent(t, send)
		n := a.trustStore.Len()
		press(a, "f", forged)
		if a.trustStore.Len() != n || tokenData(lastEditKB(send), tgui.ActYes) != "" {
			t.Errorf("%s: offered a Yes or changed the list", forged)
		}
		if len(send.answered) != 1 {
			t.Errorf("%s: answered = %v", forged, send.answered)
		}
	}
}

// The ask acts never act themselves and are refused to group viewers.
func TestAskActsOnlyAsk(t *testing.T) {
	for _, data := range []string{"~1fc", "~1fo", "~1up", "~1cc", "~1kk|0123456789abcdef", "~1ut|203.0.113.4",
		"~1ua|restart|0123456789abcdef", "~1ca|stop|0123456789ab"} {
		send := &fakeSender{}
		a, _ := authAgent(t, send, -100, 7)
		var ran []string
		a.src.Runner = runFunc(func(name string, args ...string) (string, error) {
			ran = append(ran, name+" "+strings.Join(args, " "))
			return "", errors.New("no")
		})
		applied := false
		a.src.UpdateApply = func(context.Context) error { applied = true; return nil }
		a.handleCallback(context.Background(), &telegram.Callback{ID: "m", ChatID: -100, ChatType: "supergroup", FromID: 5, MessageID: 3, Data: data})
		if !slices.Equal(send.answered, []string{"m:" + adminOnlyToast}) {
			t.Errorf("%s from a non-admin: answered %v", data, send.answered)
		}
		a.handleCallback(context.Background(), &telegram.Callback{ID: "a", ChatID: -100, ChatType: "supergroup", FromID: 7, MessageID: 3, Data: data})
		for _, r := range ran {
			if !strings.Contains(r, "status") {
				t.Errorf("%s ran %q before any Yes", data, r)
			}
		}
		if applied || len(send.deleted) != 0 {
			t.Errorf("%s acted before any Yes", data)
		}
	}
}

func TestCallOutdated(t *testing.T) {
	for _, data := range []string{"~1zz", "~1v|nope", "~1v", "~1v|cpu^", "~2v|cpu", "~", "~1v|<b>", "~1o|nope", "~1o"} {
		send := &fakeSender{}
		a := testAgent(send)
		press(a, "c", data)
		if !slices.Equal(send.answered, []string{"c:" + outdatedToast}) {
			t.Errorf("%q: answered = %v", data, send.answered)
		}
		if len(send.edits) != 0 || len(send.all()) != 0 {
			t.Errorf("%q: outdated data changed the chat: edits %v sent %v", data, send.edits, send.all())
		}
	}
}

func TestCallAuthorize(t *testing.T) {
	ctx := context.Background()
	cases := []struct {
		name   string
		admins []int64
		cb     telegram.Callback
		answer []string // nil: ignored, not even answered
		edited bool
	}{
		{"foreign chat", nil,
			telegram.Callback{ID: "c", ChatID: 7, ChatType: "private", FromID: 7, Data: "~1v|cpu"}, nil, false},
		{"foreign chat, unknown act", nil,
			telegram.Callback{ID: "c", ChatID: 7, ChatType: "private", FromID: 7, Data: "~1zz"}, nil, false},
		{"foreign chat, ask act", nil,
			telegram.Callback{ID: "c", ChatID: 7, ChatType: "private", FromID: 7, Data: "~1fc"}, nil, false},
		{"impostor in private chat", nil,
			telegram.Callback{ID: "c", ChatID: 42, ChatType: "private", FromID: 99, Data: "~1v|cpu"}, nil, false},
		{"group viewer opens a view", []int64{1},
			telegram.Callback{ID: "c", ChatID: 42, ChatType: "group", FromID: 99, Data: "~1v|cpu"}, []string{"c:"}, true},
		{"group viewer, unknown act", []int64{1},
			telegram.Callback{ID: "c", ChatID: 42, ChatType: "group", FromID: 99, Data: "~1zz"}, []string{"c:" + adminOnlyToast}, false},
		{"group viewer, config action", []int64{1},
			telegram.Callback{ID: "c", ChatID: 42, ChatType: "group", FromID: 99, Data: "~1cf"}, []string{"c:" + adminOnlyToast}, false},
		{"group admin, config action", []int64{1},
			telegram.Callback{ID: "c", ChatID: 42, ChatType: "group", FromID: 1, Data: "~1cf"}, []string{"c:"}, true},
		{"inaccessible message", nil,
			telegram.Callback{ID: "c", ChatID: 42, ChatType: "private", FromID: 42, Data: "~1v|cpu", Inaccessible: true},
			[]string{"c:" + inaccessibleToast}, false},
	}
	for _, tc := range cases {
		send := &fakeSender{}
		a, _ := authAgent(t, send, 42, tc.admins...)
		// The class authorize sees comes from the registered action.
		a.ui.AddScreen(tgui.Screen{ID: "cfg", Render: func(context.Context, tgui.Call) tgui.View { return tgui.View{Text: "changed"} }})
		a.ui.AddAction(tgui.Action{ID: "cf", Class: tgui.ClassConfig, Screen: "cfg"})
		cb := tc.cb
		cb.MessageID = 4
		a.handleCallback(ctx, &cb)
		if !slices.Equal(send.answered, tc.answer) {
			t.Errorf("%s: answered = %v, want %v", tc.name, send.answered, tc.answer)
		}
		if (len(send.edits) > 0) != tc.edited {
			t.Errorf("%s: edits = %v, want edited %v", tc.name, send.edits, tc.edited)
		}
	}
}

// A slow screen is answered before it renders, once.
func TestCallSlowAnsweredFirst(t *testing.T) {
	send := &fakeSender{}
	a := testAgent(send)
	press(a, "c", "~1v|top")
	if got := send.eventLog(); !slices.Equal(got, []string{"answer", "edit"}) {
		t.Errorf("events = %v, want answer then edit", got)
	}
}

func TestCallRenderFailure(t *testing.T) {
	send := &fakeSender{}
	a := testAgent(send)
	a.ui.AddScreen(tgui.Screen{ID: "big", Render: func(context.Context, tgui.Call) tgui.View {
		return tgui.View{Text: "big", Rows: [][]tgui.Button{{{Label: "x", Call: tgui.Open(strings.Repeat("a", 64))}}}}
	}})
	press(a, "c", "~1v|big")
	if !slices.Equal(send.answered, []string{"c:" + renderFailedToast}) || len(send.edits) != 0 {
		t.Errorf("answered = %v, edits = %v", send.answered, send.edits)
	}
}

func TestCallEditFailureFallsBack(t *testing.T) {
	send := &fakeSender{editErr: errors.New("Bad Request: message to edit not found")}
	a := testAgent(send)
	press(a, "c", "~1v|cpu")
	if len(send.all()) != 1 || !strings.Contains(dumpKeyboard(send.keyboards[0]), "~1v|cpu") {
		t.Errorf("failed edit must resend the view: sent %v", send.all())
	}
	if !slices.Equal(send.answered, []string{"c:" + editFailedToast}) {
		t.Errorf("answered = %v", send.answered)
	}
	if got := strings.Join(send.eventLog(), ","); got != "edit,send,answer" {
		t.Errorf("events = %s, want the answer after the fallback", got)
	}
}

// New screens never send the bare navigation tokens of older versions:
// every navigation button in the goldens is "~1" data.
func TestGoldensUseNoRetiredNavTokens(t *testing.T) {
	files, err := filepath.Glob(filepath.Join("testdata", "*.golden"))
	if err != nil || len(files) == 0 {
		t.Fatalf("no goldens: %v", err)
	}
	for _, f := range files {
		b, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		_, kb, _ := strings.Cut(string(b), "--- keyboard ---\n")
		for token := range legacyViews {
			if strings.Contains(kb, "→ "+token+"\n") || strings.Contains(kb, "→ "+token+"  ") || strings.Contains(kb, "→ "+token+" (") {
				t.Errorf("%s sends the retired token %q", f, token)
			}
		}
	}
}
