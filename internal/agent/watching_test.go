package agent

import (
	"context"
	"fmt"
	"slices"
	"strings"
	"testing"

	"github.com/eliau2005/statixagent/internal/config"
	"github.com/eliau2005/statixagent/internal/telegram"
)

func TestWatchingShowsSSLAndHTTP(t *testing.T) {
	send := &fakeSender{}
	a := testAgent(send)
	a.cfg.Watch.SSLHosts = []string{"example.com"}
	a.cfg.Watch.HTTPChecks = []config.HTTPCheck{{URL: "https://example.com/healthz", ExpectStatus: 200}}

	text, kb := a.watchingView()
	if !strings.Contains(text, "📜 example.com") || !strings.Contains(text, "🌐 https://example.com/healthz") {
		t.Fatalf("watching view: %q", text)
	}
	flat := dumpKeyboard(kb)
	for _, want := range []string{
		"[🗑 example.com] → ~1wr|c|" + callbackDigest("example.com") + "|1",
		"[🗑 example.com…] → ~1wr|h|" + callbackDigest("https://example.com/healthz") + "|1",
	} {
		if !strings.Contains(flat, want) {
			t.Errorf("missing %s in\n%s", want, flat)
		}
	}
}

func TestWatchingRemovesSSLAndHTTP(t *testing.T) {
	send := &fakeSender{}
	a := testAgent(send)
	ctx := context.Background()
	a.cfg.Watch.SSLHosts = []string{"example.com"}
	a.cfg.Watch.HTTPChecks = []config.HTTPCheck{{URL: "https://example.com/healthz"}}

	if _, _, toast, ok := a.handleWatchCallback(ctx, watchIndexData("cr:", 0, "example.com")); !ok || !strings.Contains(toast, "example.com") {
		t.Errorf("cr callback: ok=%v toast=%q", ok, toast)
	}
	if hosts := a.watchCopy().SSLHosts; len(hosts) != 0 {
		t.Errorf("ssl hosts after remove = %v", hosts)
	}

	if _, _, toast, ok := a.handleWatchCallback(ctx, watchIndexData("hr:", 0, "https://example.com/healthz")); !ok || !strings.Contains(toast, "healthz") {
		t.Errorf("hr callback: ok=%v toast=%q", ok, toast)
	}
	if checks := a.watchCopy().HTTPChecks; len(checks) != 0 {
		t.Errorf("http checks after remove = %v", checks)
	}

	// A stale index re-renders instead of removing the wrong item.
	if _, _, toast, ok := a.handleWatchCallback(ctx, watchIndexData("hr:", 5, "https://example.com/healthz")); !ok || toast != "stale list" {
		t.Errorf("stale hr callback: ok=%v toast=%q", ok, toast)
	}
}

func TestWatchedSummaryCountsSSLAndHTTP(t *testing.T) {
	send := &fakeSender{}
	a := testAgent(send)
	a.cfg.Watch.SSLHosts = []string{"a.com", "b.com"}
	a.cfg.Watch.HTTPChecks = []config.HTTPCheck{{URL: "https://a.com"}}
	s := a.watchedSummary()
	if !strings.Contains(s, "2 ssl") || !strings.Contains(s, "1 http") {
		t.Errorf("summary = %q", s)
	}
}

func TestWatchingLongHostCallbackData(t *testing.T) {
	send := &fakeSender{}
	a := testAgent(send)
	longHost := "status.some-long-customer-domain.example.co.uk:8443" + strings.Repeat("x", 20)
	if len("cr:"+longHost) <= 64 {
		t.Fatalf("fixture should exceed 64 when prefixed the old way; got %d", len("cr:"+longHost))
	}
	a.cfg.Watch.SSLHosts = []string{longHost}
	a.cfg.Watch.Services = []string{"systemd-networkd-wait-online.service"}
	_, kb := a.watchingView()
	for _, row := range kb {
		for _, b := range row {
			if len(b.Data) > 64 {
				t.Errorf("callback_data %q is %d bytes, want ≤ 64", b.Data, len(b.Data))
			}
		}
	}
	flat := dumpKeyboard(kb)
	for _, want := range []string{"~1wr|c|" + callbackDigest(longHost) + "|1", "~1wr|u|" + callbackDigest("systemd-networkd-wait-online.service") + "|1"} {
		if !strings.Contains(flat, want) {
			t.Errorf("expected %s in\n%s", want, flat)
		}
	}
}

// A 🗑 button names its item by digest, so a list that shifted after the
// screen was drawn still removes exactly that item; the index buttons of
// older versions are refused instead.
func TestWatchCallbackStaleAfterShift(t *testing.T) {
	send := &fakeSender{}
	a := testAgent(send)
	ctx := context.Background()
	a.cfg.Watch.SSLHosts = []string{"a.example", "b.example", "c.example"}
	_, kb := a.watchingView()
	var bData string
	for _, row := range kb {
		for _, b := range row {
			if strings.Contains(b.Text, "b.example") {
				bData = b.Data
			}
		}
	}
	if bData == "" {
		t.Fatal("missing 🗑 b.example button")
	}
	legacy := watchIndexData("cr:", 1, "b.example")
	// Remove a.example via manage path (shifts the list).
	a.sslManage([]string{"remove", "a.example"})
	if _, _, toast, ok := a.handleWatchCallback(ctx, legacy); !ok || toast != "stale list" {
		t.Fatalf("shifted legacy index must be stale, got ok=%v toast=%q", ok, toast)
	}
	press(a, "c1", bData)
	if got := a.watchCopy().SSLHosts; len(got) != 1 || got[0] != "c.example" {
		t.Fatalf("digest button removed the wrong host: %v", got)
	}
	// Pressed again, the item is gone: nothing changes.
	press(a, "c2", bData)
	if got := a.watchCopy().SSLHosts; len(got) != 1 || got[0] != "c.example" {
		t.Fatalf("replay changed the list: %v", got)
	}
	if want := []string{"c1:🗑 Stopped watching b.example (not persisted: no config path)", "c2:" + itemGoneToast}; !slices.Equal(send.answered, want) {
		t.Errorf("answered = %v", send.answered)
	}
}

// 120 watched items page 8 at a time; every page's 🗑 buttons route,
// and each removes exactly its own item from whatever page it is on.
func TestWatchingPages120Items(t *testing.T) {
	send := &fakeSender{}
	a := testAgent(send)
	for i := range 40 {
		a.cfg.Watch.Services = append(a.cfg.Watch.Services, fmt.Sprintf("svc-%02d.service", i))
		a.cfg.Watch.Processes = append(a.cfg.Watch.Processes, fmt.Sprintf("proc-%02d", i))
		a.cfg.Watch.Ports = append(a.cfg.Watch.Ports, config.PortCheck{Port: 1000 + i})
	}
	var want []string
	for _, it := range watchItems(a.watchCopy()) {
		want = append(want, it.line())
	}
	if len(want) != 120 {
		t.Fatalf("fixture has %d items", len(want))
	}

	// Walk the pages with Next, as a user would.
	var seen []string
	buttons := map[string]string{} // item line → its 🗑 data
	press(a, "p1", "~1v|wat")
	for page := 1; ; page++ {
		e := send.lastEdit()
		if !strings.Contains(e.html, fmt.Sprintf("120 items · %d/15", page)) {
			t.Fatalf("page %d title: %q", page, e.html)
		}
		_, body, _ := strings.Cut(e.html, "<pre>")
		body, _, _ = strings.Cut(body, "</pre>")
		lines := strings.Split(body, "\n")
		var rm []string
		next := ""
		for _, row := range e.kb {
			for _, b := range row {
				switch {
				case strings.HasPrefix(b.Text, "🗑 "):
					rm = append(rm, b.Data)
				case b.Text == "Next ▶️":
					next = b.Data
				}
			}
		}
		if len(lines) != pageSize || len(rm) != pageSize {
			t.Fatalf("page %d lists %d items with %d 🗑 buttons", page, len(lines), len(rm))
		}
		for i, l := range lines {
			seen = append(seen, l)
			buttons[l] = rm[i]
			if !strings.HasSuffix(rm[i], fmt.Sprintf("|%d", page)) {
				t.Errorf("page %d button %q does not return to its page", page, rm[i])
			}
		}
		if next == "" {
			if page != 15 {
				t.Fatalf("no Next on page %d", page)
			}
			break
		}
		press(a, fmt.Sprint("n", page), next)
	}
	if !slices.Equal(seen, want) {
		t.Fatalf("pages listed %d items, not each once in order", len(seen))
	}

	// Remove one item from each of three pages, in an order that shifts
	// the list under the buttons drawn before: each removes its own.
	pressed := []string{want[5], want[60], want[119]}
	for _, line := range pressed {
		press(a, "rm", buttons[line])
		if got := send.answered[len(send.answered)-1]; !strings.HasPrefix(got, "rm:🗑 Stopped watching") {
			t.Errorf("%s: answered %q", line, got)
		}
	}
	var left []string
	for _, it := range watchItems(a.watchCopy()) {
		left = append(left, it.line())
	}
	if gone := slices.DeleteFunc(slices.Clone(want), func(l string) bool { return slices.Contains(pressed, l) }); !slices.Equal(left, gone) {
		t.Errorf("after removals %d items left, want %d without the three pressed", len(left), len(gone))
	}
	// The last removal was on page 15: 117 items still fill 15 pages.
	if e := send.lastEdit(); !strings.Contains(e.html, "117 items · 15/15") {
		t.Errorf("after removing from the last page: %q", e.html)
	}
}

// Watching opened from Services keeps going Back there, through pages
// and removals.
func TestWatchingKeepsFrom(t *testing.T) {
	send := &fakeSender{}
	a := testAgent(send)
	for i := range 10 {
		a.cfg.Watch.Processes = append(a.cfg.Watch.Processes, fmt.Sprintf("p%d", i))
	}
	press(a, "c1", "~1v|wat^svc")
	kb := send.lastEdit().kb
	if got := dumpKeyboard(kb[len(kb)-1:]); got != "[⬅️ Back] → ~1v|svc  [🏠 Home] → ~1v|home  [🔄 Refresh] → ~1v|wat^svc\n" {
		t.Errorf("footer: %s", got)
	}
	press(a, "c2", kb[0][0].Data)
	kb = send.lastEdit().kb
	if kb[len(kb)-1][0].Data != "~1v|svc" || !strings.HasSuffix(kb[0][0].Data, "^svc") || len(a.watchCopy().Processes) != 9 {
		t.Errorf("after removal:\n%s", dumpKeyboard(kb))
	}
}

// Forged watch data is refused without changing anything.
func TestWatchForged(t *testing.T) {
	x := callbackDigest("x")
	for _, data := range []string{"~1wr", "~1wr|u|nothex|1", "~1wr|u|" + x + "|0", "~1wr|u|" + x + "|01", "~1wr|z|" + x + "|1",
		"~1wr|p|0|1", "~1wr|p|65536|1", "~1wr|p|022|1", "~1wr|p|22", "~1wa|x|" + x + "|1", "~1wa|p|70000|1",
		"~1wa|u|ABCDEF0123456789|1", "~1wa|p|22|1|2"} {
		send := &fakeSender{}
		a := testAgent(send)
		a.cfg.Watch.Ports = []config.PortCheck{{Port: 22}}
		press(a, "f", data)
		if !slices.Equal(send.answered, []string{"f:" + outdatedToast}) || len(send.edits) != 0 || len(a.watchCopy().Ports) != 1 {
			t.Errorf("%s: answered %v", data, send.answered)
		}
	}
}

// Watch changes are the bot's settings: a group viewer is refused.
func TestWatchNeedsAdmin(t *testing.T) {
	send := &fakeSender{}
	a, _ := authAgent(t, send, -100, 7)
	a.cfg.Watch.Ports = []config.PortCheck{{Port: 22}}
	a.handleCallback(context.Background(), &telegram.Callback{ID: "v", ChatID: -100, ChatType: "supergroup", FromID: 5, MessageID: 3, Data: "~1wr|p|22|1"})
	if len(a.watchCopy().Ports) != 1 || !slices.Equal(send.answered, []string{"v:" + adminOnlyToast}) {
		t.Errorf("viewer unwatched: answered %v", send.answered)
	}
}

func TestWatchCallbackStaleListPath(t *testing.T) {
	send := &fakeSender{}
	a := testAgent(send)
	ctx := context.Background()
	a.cfg.Watch.SSLHosts = []string{"only.example"}
	// Wrong fingerprint at a valid index.
	bad := fmt.Sprintf("cr:0:%s", callbackDigest("other"))
	if _, _, toast, ok := a.handleWatchCallback(ctx, bad); !ok || toast != "stale list" {
		t.Fatalf("bad fingerprint: ok=%v toast=%q", ok, toast)
	}
	if _, _, toast, ok := a.handleWatchCallback(ctx, "cr:not-an-index"); !ok || toast != "stale list" {
		t.Fatalf("malformed: ok=%v toast=%q", ok, toast)
	}
}

func TestWatchCallbackRemovesProcess(t *testing.T) {
	send := &fakeSender{}
	a := testAgent(send)
	ctx := context.Background()
	a.cfg.Watch.Processes = []string{"nginx", "redis"}
	data := watchIndexData("xr:", 1, "redis")
	if _, _, toast, ok := a.handleWatchCallback(ctx, data); !ok || toast != "🗑 redis" {
		t.Fatalf("xr callback: ok=%v toast=%q", ok, toast)
	}
	if got := a.watchCopy().Processes; len(got) != 1 || got[0] != "nginx" {
		t.Fatalf("processes after xr = %v", got)
	}
}

func TestWatchLegacyCRC32Fingerprint(t *testing.T) {
	send := &fakeSender{}
	a := testAgent(send)
	ctx := context.Background()
	a.cfg.Watch.SSLHosts = []string{"legacy.example"}
	a.cfg.Watch.Processes = []string{"nginx", "redis"}
	a.cfg.Watch.HTTPChecks = []config.HTTPCheck{{URL: "https://legacy.example/healthz"}}

	// Legacy #64 form: prefix + index + 8-char CRC32 hex.
	cr := fmt.Sprintf("cr:0:%s", legacyCRC32Hex("legacy.example"))
	if _, _, toast, ok := a.handleWatchCallback(ctx, cr); !ok || !strings.Contains(toast, "legacy.example") {
		t.Fatalf("legacy cr: ok=%v toast=%q", ok, toast)
	}
	if hosts := a.watchCopy().SSLHosts; len(hosts) != 0 {
		t.Fatalf("ssl hosts after legacy remove = %v", hosts)
	}

	xr := fmt.Sprintf("xr:1:%s", legacyCRC32Hex("redis"))
	if _, _, toast, ok := a.handleWatchCallback(ctx, xr); !ok || toast != "🗑 redis" {
		t.Fatalf("legacy xr: ok=%v toast=%q", ok, toast)
	}

	hr := fmt.Sprintf("hr:0:%s", legacyCRC32Hex("https://legacy.example/healthz"))
	if _, _, toast, ok := a.handleWatchCallback(ctx, hr); !ok || !strings.Contains(toast, "healthz") {
		t.Fatalf("legacy hr: ok=%v toast=%q", ok, toast)
	}

	// Emit path must still be 16-char SHA-256 only.
	got := watchIndexData("cr:", 0, "new.example")
	parts := strings.Split(got, ":")
	if len(parts) != 3 || len(parts[2]) != 16 {
		t.Fatalf("watchIndexData must emit 16-hex SHA-256, got %q", got)
	}
}

func TestParseWatchIndexDataAcceptsBothFingerprints(t *testing.T) {
	i, fp, ok := parseWatchIndexData("sr:2:"+callbackDigest("svc"), "sr:")
	if !ok || i != 2 || len(fp) != 16 {
		t.Fatalf("sha256 parse: i=%d fp=%q ok=%v", i, fp, ok)
	}
	i, fp, ok = parseWatchIndexData("sr:2:"+legacyCRC32Hex("svc"), "sr:")
	if !ok || i != 2 || len(fp) != 8 {
		t.Fatalf("crc32 parse: i=%d fp=%q ok=%v", i, fp, ok)
	}
	if _, _, ok := parseWatchIndexData("sr:2:abcd", "sr:"); ok {
		t.Fatal("4-char fingerprint must be rejected")
	}
	if _, _, ok := parseWatchIndexData("sr:2:gggggggg", "sr:"); ok {
		t.Fatal("non-hex fingerprint must be rejected")
	}
}
