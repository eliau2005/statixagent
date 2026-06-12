package agent

import (
	"strings"
	"testing"
)

func TestStartOnboarding(t *testing.T) {
	send := &fakeSender{}
	a := testAgent(send)

	reply := dispatchText(t, a, "/start")
	for _, want := range []string{"testhost", "SSH login", "daily digest at 09:00", "CPU, RAM or disk"} {
		if !strings.Contains(reply, want) {
			t.Errorf("/start missing %q: %q", want, reply)
		}
	}
	// Nothing is watched in the test config, so no watch line.
	if strings.Contains(reply, "services, processes and ports") {
		t.Errorf("/start lists a watch line with empty watch config: %q", reply)
	}

	// The reply carries the entry-point keyboard.
	kb := a.popKB()
	if kb == nil || len(kb) != 2 || kb[0][0].Data != "status" || kb[1][1].Data != "settings" {
		t.Errorf("/start keyboard = %+v", kb)
	}
}

func TestStartReflectsConfig(t *testing.T) {
	send := &fakeSender{}
	c := testConfig()
	c.Monitors.SSH = false
	c.Digest.Enabled = false
	c.Watch.Services = []string{"nginx", "postgres"}
	a := New(c, send, nil, Sources{Hostname: "bare"})

	reply := dispatchText(t, a, "/start")
	if strings.Contains(reply, "SSH login") || strings.Contains(reply, "daily digest") {
		t.Errorf("/start advertises disabled features: %q", reply)
	}
	if !strings.Contains(reply, "2 services") {
		t.Errorf("/start missing watch count: %q", reply)
	}
	a.popKB()
}
