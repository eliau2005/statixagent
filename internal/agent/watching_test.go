package agent

import (
	"context"
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
	for _, row := range kb {
		for _, b := range row {
			if b.Data == "cr:0" {
				haveCR = true
			}
			if b.Data == "hr:0" {
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

	if _, _, toast, ok := a.handleWatchCallback(ctx, "cr:0"); !ok || !strings.Contains(toast, "example.com") {
		t.Errorf("cr callback: ok=%v toast=%q", ok, toast)
	}
	if hosts := a.watchCopy().SSLHosts; len(hosts) != 0 {
		t.Errorf("ssl hosts after remove = %v", hosts)
	}

	if _, _, toast, ok := a.handleWatchCallback(ctx, "hr:0"); !ok || !strings.Contains(toast, "healthz") {
		t.Errorf("hr callback: ok=%v toast=%q", ok, toast)
	}
	if checks := a.watchCopy().HTTPChecks; len(checks) != 0 {
		t.Errorf("http checks after remove = %v", checks)
	}

	// A stale index re-renders instead of removing the wrong item.
	if _, _, toast, ok := a.handleWatchCallback(ctx, "hr:5"); !ok || toast != "stale list" {
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
	for _, row := range kb {
		for _, b := range row {
			if b.Data == "cr:0" {
				haveCR = true
			}
			if b.Data == "sr:0" {
				haveSR = true
			}
		}
	}
	if !haveCR || !haveSR {
		t.Fatalf("expected index callbacks cr:0/sr:0 in %+v", kb)
	}
}
