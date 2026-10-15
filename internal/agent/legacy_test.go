package agent

import (
	"context"
	"testing"

	"github.com/eliau2005/statixagent/internal/telegram"
)

// TestLegacyRuleClaims pins which legacy rule claims every callback datum
// the other tests press, plus the forged and outdated ones they refuse,
// so a reordered or widened rule cannot quietly reroute a button.
func TestLegacyRuleClaims(t *testing.T) {
	a := testAgent(&fakeSender{})
	sess := sshTestSessions()[0]
	cases := []struct{ data, rule string }{
		// Snooze: the four forms, stale ones included (refused by the handler).
		{"snz:d:cpu", "snooze"},
		{"snz:d:docker:api", "snooze"},
		{"snz:d:", "snooze"},
		{"snz:h:deadbeefdeadbeef", "snooze"},
		{"snz:h:", "snooze"},
		{"snz:h", "snooze"},
		{"snz:cpu", "snooze"},
		{"snz:", "snooze"},
		{a.snoozeCallbackData("mem"), "snooze"},
		{a.snoozeCallbackData("a-very-long-alert-key-that-needs-the-hashed-snooze-form-to-fit-in-64-bytes"), "snooze"},
		// Trust: tipk: and tipc: before tip:.
		{"tip:10.0.0.7", "trust"},
		{"tip:10.0.0.0/8", "trust"},
		{"tipk:10.0.0.7", "trust"},
		{"tipk:::ffff:10.0.0.7", "trust"},
		{"tipk:fe80::1%eth0", "trust"},
		{"tipk:", "trust"},
		{"tipc:10.0.0.7", "trust"},
		{"tipc:garbage", "trust"},
		{"dismiss", "dismiss"},
		{"live", "live"},
		{"live_stop", "live_stop"},
		// Firewall: the two that run ufw are slow.
		{"fw_close", "firewall-apply"},
		{"fw_open", "firewall-apply"},
		{"firewall", "firewall"},
		{"fw_close_ask", "firewall"},
		{"fw_open_ask", "firewall"},
		// SSH: skk: kicks (slow); sk: and the list are not. "ssh" is also
		// a nav view, but it renders the sessions list with kick buttons.
		{"skk:1", "ssh-kick"},
		{"skk:3", "ssh-kick"},
		{"skk:1:zzzzzzzzzzzzzzzz", "ssh-kick"},
		{sessionCallbackData("skk:", 1, sess), "ssh-kick"},
		{"ssh", "ssh"},
		{"sk:1", "ssh"},
		{sessionCallbackData("sk:", 1, sess), "ssh"},
		// Settings.
		{"settings", "settings"},
		{"noop", "settings"},
		{"dg:toggle", "settings"},
		{"dg:hour:+1", "settings"},
		{"dg:hour:-1", "settings"},
		{"th:cpu:-5", "settings"},
		{"th:cpu:+5", "settings"},
		{"th:batt:-5", "settings"},
		{"th:cpu:NaN", "settings"},
		{"th:cpu:-Inf", "settings"},
		{"th:cpu:+50", "settings"},
		{"th:cpu:", "settings"},
		// Watching and the scans.
		{"watching", "watch"},
		{"scan_svc", "watch"},
		{"scan_port", "watch"},
		{"sa:1", "watch"},
		{watchIndexData("sa:", 0, "nginx.service"), "watch"},
		{"pa:443", "watch"},
		{"pr:443", "watch"},
		{"sr:2:abcd", "watch"},
		{"sr:2:gggggggg", "watch"},
		{watchIndexData("xr:", 1, "redis"), "watch"},
		{watchIndexData("cr:", 0, "example.com"), "watch"},
		{"cr:not-an-index", "watch"},
		{watchIndexData("hr:", 0, "https://example.com/healthz"), "watch"},
		// Update and clear-chat prompts.
		{cbUpdateYes, "update-yes"},
		{cbClearYes, "clear-yes"},
		{cbClearNo, "confirm"},
		{"update_confirm", "confirm"},
		// Navigation views reach the router.
		{"docker", "docker"},
		{"status", "view"},
		{"cpu", "view"},
		{"ssh_fails", "view"},
		{"ssh_history", "view"},
		// Claimed by nothing: outdated.
		{"clear_chat", ""},
		{"update", ""},
		{"start", ""},
		{"help", ""},
		{"ping", ""},
		{"trust", ""},
		{"untrust", ""},
		{"services_add", ""},
		{"ports_remove", ""},
		{"procs_add", ""},
		{"trusted", ""},
		{"no_such_action", ""},
		{"dg:", ""},
		{"dg:hour", ""},
		{"tip", ""},
		{"snz", ""},
		{"sk", ""},
		{"Status", ""},
		{"", ""},
	}
	for _, tc := range cases {
		rule, ok := a.legacy.Lookup(tc.data)
		if ok != (tc.rule != "") || rule.Name != tc.rule {
			t.Errorf("%q claimed by %q (ok=%v), want %q", tc.data, rule.Name, ok, tc.rule)
		}
	}
	// Every navigation view is claimed by some rule.
	for v := range navViews {
		if _, ok := a.legacy.Lookup(v); !ok {
			t.Errorf("nav view %q is claimed by no rule", v)
		}
	}
}

// TestLegacySlowRules pins which presses are answered before their work,
// and with what.
func TestLegacySlowRules(t *testing.T) {
	a := testAgent(&fakeSender{})
	want := map[string]string{
		"fw_close": "Working…", "fw_open": "Working…", "skk:1": "Working…",
		cbUpdateYes: "Updating…", cbClearYes: "Clearing…", "docker": "",
	}
	for data, ack := range want {
		if rule, ok := a.legacy.Lookup(data); !ok || !rule.Slow || rule.Ack != ack {
			t.Errorf("%q: slow=%v ack=%q, want slow with %q", data, rule.Slow, rule.Ack, ack)
		}
	}
	for _, data := range []string{"firewall", "fw_close_ask", "sk:1", "ssh", "status", "settings", "snz:cpu", "live", "update_confirm", cbClearNo} {
		if rule, _ := a.legacy.Lookup(data); rule.Slow {
			t.Errorf("%q is slow; only work that takes seconds should be", data)
		}
	}
}

// TestViewCallbackRefusesUnhandled: data a rule claims but its handler
// declines is refused like unclaimed data, answered at most once.
func TestViewCallbackRefusesUnhandled(t *testing.T) {
	send := &fakeSender{}
	a := testAgent(send)
	h := a.viewCallback(func(context.Context, string) (string, telegram.Keyboard, string, bool) { return "", nil, "", false })
	h(context.Background(), &telegram.Callback{ID: "c1", ChatID: 42, MessageID: 5, Data: "x"}, false)
	h(context.Background(), &telegram.Callback{ID: "c2", ChatID: 42, MessageID: 5, Data: "x"}, true)
	send.mu.Lock()
	defer send.mu.Unlock()
	if len(send.answered) != 1 || send.answered[0] != "c1:"+outdatedToast || len(send.edits)+len(send.sent) != 0 {
		t.Errorf("answered = %v edits = %v sent = %v; want only c1 refused", send.answered, send.edits, send.sent)
	}
}
