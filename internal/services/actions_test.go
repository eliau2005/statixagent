package services

import (
	"context"
	"slices"
	"strings"
	"testing"
	"time"
)

func TestActionDenied(t *testing.T) {
	for _, tc := range []struct {
		unit string
		want bool
	}{
		{"statix-agent.service", true},
		{"dbus.service", true},
		{"dbus-broker.service", true},
		{"dbus.socket", true},
		{"systemd-journald.service", true},
		{"systemd-networkd.service", true},
		{"systemd-fsck@sda1.service", true},
		{"multi-user.target", true},
		{"nginx.service", false},
		{"ssh.service", false},
		{"statix-agent-helper.service", false},
		{"my-systemd-thing.service", false},
	} {
		if got := ActionDenied(tc.unit); got != tc.want {
			t.Errorf("ActionDenied(%q) = %v, want %v", tc.unit, got, tc.want)
		}
	}
}

func TestLockoutRisk(t *testing.T) {
	for _, tc := range []struct {
		unit string
		want bool
	}{
		{"ssh.service", true},
		{"sshd.service", true},
		{"ssh.socket", true},
		{"ssh@1-10.0.0.1:22-10.0.0.9:5000.service", true},
		{"docker.service", true},
		{"docker.socket", true},
		{"containerd.service", true},
		{"NetworkManager.service", true},
		{"systemd-networkd.service", true},
		{"networking.service", true},
		{"nginx.service", false},
		{"sshguard.service", false},
		{"docker-cleanup.timer", false},
		{"networkmanager.service", false},
	} {
		if got := LockoutRisk(tc.unit); got != tc.want {
			t.Errorf("LockoutRisk(%q) = %v, want %v", tc.unit, got, tc.want)
		}
	}
}

// stateRunner answers `systemctl show` with states in turn (the last one
// repeats) and records every call.
type stateRunner struct {
	states []string
	calls  [][]string
}

func (r *stateRunner) Run(_ context.Context, name string, args ...string) (string, error) {
	r.calls = append(r.calls, append([]string{name}, args...))
	if len(args) == 0 || args[0] != "show" {
		return "", nil
	}
	s := r.states[0]
	if len(r.states) > 1 {
		r.states = r.states[1:]
	}
	return s, nil
}

func TestActUnit(t *testing.T) {
	prev := pollEvery
	pollEvery = time.Millisecond
	t.Cleanup(func() { pollEvery = prev })
	const (
		oldRun    = "ActiveState=active\nInvocationID=aaa\n"
		oldFailed = "ActiveState=failed\nInvocationID=aaa\n"
		newRun    = "ActiveState=active\nInvocationID=bbb\n"
		newFailed = "ActiveState=failed\nInvocationID=bbb\n"
		inactive  = "ActiveState=inactive\nInvocationID=aaa\n"
		stopping  = "ActiveState=deactivating\nInvocationID=aaa\n"
		starting  = "ActiveState=activating\nInvocationID=bbb\n"
	)
	for _, tc := range []struct {
		name, verb string
		states     []string // before the job, then each poll
		wantState  string
		wantErr    bool
		wantPolls  int
	}{
		{"start", VerbStart, []string{inactive, starting, newRun}, "active", false, 2},
		{"start running", VerbStart, []string{oldRun, oldRun}, "active", false, 1},
		{"start fails", VerbStart, []string{inactive, starting, newFailed}, "failed", true, 2},
		{"stop", VerbStop, []string{oldRun, oldRun, stopping, inactive}, "inactive", false, 3},
		{"restart waits for the new run", VerbRestart, []string{oldRun, oldRun, stopping, starting, newRun}, "active", false, 4},
		{"restart of a failed unit", VerbRestart, []string{oldFailed, oldFailed, starting, newRun}, "active", false, 3},
		{"restart fails again", VerbRestart, []string{oldFailed, oldFailed, newFailed}, "failed", true, 2},
		{"old systemd", VerbRestart, []string{"ActiveState=active\n", "ActiveState=active\n"}, "active", false, 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := &stateRunner{states: tc.states}
			o, err := ActUnit(context.Background(), r, tc.verb, "nginx.service")
			if (err != nil) != tc.wantErr || o.State != tc.wantState {
				t.Fatalf("ActUnit = %+v, %v; want state %q, error %v", o, err, tc.wantState, tc.wantErr)
			}
			want := []string{"systemctl", "--no-ask-password", "--no-block", tc.verb, "--", "nginx.service"}
			if !slices.Equal(o.Argv, want) || !slices.Equal(r.calls[1], want) {
				t.Errorf("argv = %q, ran %q; want %q", o.Argv, r.calls[1], want)
			}
			if polls := len(r.calls) - 2; polls != tc.wantPolls {
				t.Errorf("%d state reads after the job, want %d", polls, tc.wantPolls)
			}
			for _, c := range r.calls {
				if i := slices.Index(c, "--"); i < 0 || c[len(c)-1] != "nginx.service" || i != len(c)-2 || !slices.Contains(c, "--no-ask-password") {
					t.Errorf("call %q does not end in --no-ask-password ... -- unit", c)
				}
			}
		})
	}
}

func TestActUnitTimesOut(t *testing.T) {
	prev := pollEvery
	pollEvery = time.Millisecond
	t.Cleanup(func() { pollEvery = prev })
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	_, err := ActUnit(ctx, &stateRunner{states: []string{"ActiveState=deactivating\n"}}, VerbStop, "nginx.service")
	if err == nil || !strings.Contains(err.Error(), "deactivating") {
		t.Errorf("err = %v, want the unsettled state", err)
	}
}

func TestActUnitRefusesBadInput(t *testing.T) {
	for _, tc := range [][2]string{
		{"enable", "nginx.service"},
		{"disable", "nginx.service"},
		{"mask", "nginx.service"},
		{VerbStart, "--host=evil.service"},
		{VerbStart, "nginx"},
		{VerbStart, "x y.service"},
		{VerbStart, "multi-user.target"},
	} {
		r := &stateRunner{states: []string{""}}
		if _, err := ActUnit(context.Background(), r, tc[0], tc[1]); err == nil || len(r.calls) != 0 {
			t.Errorf("ActUnit(%q, %q) = %v after %d calls, want refused before running", tc[0], tc[1], err, len(r.calls))
		}
	}
}

func TestUnitLogs(t *testing.T) {
	r := &stateRunner{states: []string{""}}
	if _, err := UnitLogs(context.Background(), r, "nginx.service"); err != nil {
		t.Fatal(err)
	}
	want := []string{"journalctl", "-u", "nginx.service", "-n", "30", "--no-pager", "-o", "short-iso"}
	if len(r.calls) != 1 || !slices.Equal(r.calls[0], want) {
		t.Errorf("ran %q, want %q", r.calls, want)
	}
	if _, err := UnitLogs(context.Background(), r, "--since=x.service"); err == nil || len(r.calls) != 1 {
		t.Errorf("an option-shaped name ran: %v", err)
	}
}
