package agent

import (
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"github.com/eliau2005/statixagent/internal/config"
)

func TestHTTPManage(t *testing.T) {
	send := &fakeSender{}
	a := testAgent(send)
	a.src.ConfigPath = filepath.Join(t.TempDir(), "config.toml")

	if reply := dispatchText(t, a, "/http"); !strings.Contains(reply, "/http add") {
		t.Errorf("/http empty: %q", reply)
	}
	if reply := dispatchText(t, a, "/http add ftp://nope"); !strings.Contains(reply, "http:// or https://") {
		t.Errorf("bad scheme: %q", reply)
	}
	if reply := dispatchText(t, a, "/http add https://example.com/healthz 999"); !strings.Contains(reply, "100-599") {
		t.Errorf("bad status: %q", reply)
	}

	if reply := dispatchText(t, a, "/http add https://example.com/healthz 204"); !strings.Contains(reply, "checking https://example.com/healthz") {
		t.Fatalf("add: %q", reply)
	}
	if reply := dispatchText(t, a, "/http add https://example.com/healthz"); !strings.Contains(reply, "already checked") {
		t.Errorf("duplicate add: %q", reply)
	}
	saved, err := config.Load(a.src.ConfigPath)
	if err != nil || len(saved.Watch.HTTPChecks) != 1 || saved.Watch.HTTPChecks[0].ExpectStatus != 204 {
		t.Errorf("persisted checks = %+v err=%v", saved.Watch.HTTPChecks, err)
	}

	// Remove by 1-based index.
	if reply := dispatchText(t, a, "/http remove 1"); !strings.Contains(reply, "stopped checking https://example.com/healthz") {
		t.Errorf("remove by index: %q", reply)
	}
	if checks := a.watchCopy().HTTPChecks; len(checks) != 0 {
		t.Errorf("checks after remove = %v", checks)
	}
	if reply := dispatchText(t, a, "/http remove https://gone.example"); !strings.Contains(reply, "not checked") {
		t.Errorf("remove unknown: %q", reply)
	}
}

func TestHTTPRunChecks(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/ok" {
			w.WriteHeader(http.StatusOK)
			return
		}
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	send := &fakeSender{}
	a := testAgent(send)
	a.cfg.Watch.HTTPChecks = []config.HTTPCheck{
		{URL: srv.URL + "/ok"},
		{URL: srv.URL + "/down"},
	}
	reply := dispatchText(t, a, "/http")
	// Healthy endpoint is ✅; wrong status renders degraded (⚠️), not down.
	if !strings.Contains(reply, "✅") || !strings.Contains(reply, "⚠️ ") || !strings.Contains(reply, "got 500, want 200") {
		t.Errorf("/http results: %q", reply)
	}
}
