package agent

import (
	"context"
	"fmt"
	"strings"
	"testing"

	"github.com/eliau2005/statixagent/internal/config"
)

func TestWatchingShowsSSLAndHTTP(t *testing.T) {
	send := &fakeSender{}
	a := testAgent(send)
	a.cfg.Watch.SSLHosts = []string{"example.com"}
	a.cfg.Watch.HTTPChecks = []config.HTTPCheck{{URL: "https://example.com/healthz", ExpectStatus: 200}}

	text, kb := a.watchingView()
	if !strings.Contains(text, "example.com") || !strings.Contains(text, "🔒") || !strings.Contains(text, "🌐") {
		t.Fatalf("watching view: %q", text)
	}
	var haveCR, haveHR bool
	wantCR := watchIndexData("cr:", 0, "example.com")
	wantHR := watchIndexData("hr:", 0, "https://example.com/healthz")
	for _, row := range kb {
		for _, b := range row {
			if b.Data == wantCR {
				haveCR = true
			}
			if b.Data == wantHR {
				haveHR = true
			}
		}
	}
	if !haveCR || !haveHR {
		t.Fatalf("missing remove buttons (cr=%v hr=%v): %+v", haveCR, haveHR, kb)
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
	var haveCR, haveSR bool
	wantCR := watchIndexData("cr:", 0, longHost)
	wantSR := watchIndexData("sr:", 0, "systemd-networkd-wait-online.service")
	for _, row := range kb {
		for _, b := range row {
			if b.Data == wantCR {
				haveCR = true
			}
			if b.Data == wantSR {
				haveSR = true
			}
		}
	}
	if !haveCR || !haveSR {
		t.Fatalf("expected fingerprinted callbacks in %+v", kb)
	}
}

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
	// Remove a.example via manage path (shifts the list).
	a.sslManage([]string{"remove", "a.example"})
	_, _, toast, ok := a.handleWatchCallback(ctx, bData)
	if !ok || toast != "stale list" {
		t.Fatalf("shifted index must be stale, got ok=%v toast=%q", ok, toast)
	}
	if got := a.watchCopy().SSLHosts; len(got) != 2 || got[0] != "b.example" || got[1] != "c.example" {
		t.Fatalf("must not remove wrong host: %v", got)
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
