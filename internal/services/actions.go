package services

import (
	"context"
	"fmt"
	"strings"
	"time"
)

// Unit actions (docs/telegram-ux-redesign.md §6): start, stop and restart
// only, never enable or disable (Decision 6), always with a name that
// passed ValidUnitName after "--", and never on the units ActionDenied
// names.

// The unit verbs the bot may run.
const (
	VerbStart   = "start"
	VerbStop    = "stop"
	VerbRestart = "restart"
)

// ValidVerb reports whether verb is one the bot may run.
func ValidVerb(verb string) bool {
	return verb == VerbStart || verb == VerbStop || verb == VerbRestart
}

// ActionDenied reports whether a unit is never acted on from the bot,
// whatever the config allows: the agent itself, D-Bus, systemd's own
// units and targets. Losing any of them takes the bot or the host down.
func ActionDenied(unit string) bool {
	return unit == "statix-agent.service" || strings.HasPrefix(unit, "dbus") ||
		strings.HasPrefix(unit, "systemd-") || strings.HasSuffix(unit, ".target")
}

// lockoutUnits are the units whose loss can cut the user off from the
// host: remote login, the container runtime, the network.
var lockoutUnits = map[string]bool{
	"ssh": true, "sshd": true,
	"docker": true, "containerd": true,
	"NetworkManager": true, "systemd-networkd": true, "networking": true,
}

// LockoutRisk reports whether stopping or restarting unit risks cutting
// the user off, so it is confirmed twice. A template instance
// ("ssh@1-10.0.0.1:22.service", one SSH connection) counts as its template.
func LockoutRisk(unit string) bool {
	base, _, _ := strings.Cut(unit, ".")
	base, _, _ = strings.Cut(base, "@")
	return lockoutUnits[base]
}

const (
	// settleTimeout bounds how long ActUnit waits for the unit to settle
	// after queueing the job (docs §6).
	settleTimeout = 30 * time.Second
	// logLines is how many journal lines UnitLogs reads.
	logLines = 30
)

// pollEvery is the wait between two state reads; tests shorten it.
var pollEvery = time.Second

// UnitOutcome is what ActUnit ran and how the unit ended up.
type UnitOutcome struct {
	Argv  []string // the systemctl command that queued the job
	Out   string   // its output
	State string   // ActiveState once settled, "" when never read
}

// ActUnit runs verb on unit: the job is queued with --no-block, then the
// unit's state is polled until it settles, for at most 30 s. The error
// says why it did not end where verb leads: active after a start or
// restart, inactive (or failed) after a stop.
func ActUnit(ctx context.Context, r Runner, verb, unit string) (UnitOutcome, error) {
	if !ValidVerb(verb) || !ValidUnitName(unit) {
		return UnitOutcome{}, fmt.Errorf("refusing %s on unit %q", verb, unit)
	}
	ctx, cancel := context.WithTimeout(ctx, settleTimeout)
	defer cancel()
	// A restart must be seen to start again: a new invocation ID.
	before, _ := unitState(ctx, r, unit)
	o := UnitOutcome{Argv: []string{"systemctl", "--no-ask-password", "--no-block", verb, "--", unit}}
	var err error
	if o.Out, err = r.Run(ctx, o.Argv[0], o.Argv[1:]...); err != nil {
		return o, err
	}
	for {
		st, err := unitState(ctx, r, unit)
		if err == nil {
			o.State = st.active
			if done, err := settled(verb, before, st); done {
				return o, err
			}
		}
		select {
		case <-ctx.Done():
			return o, fmt.Errorf("not settled after %s (state %q)", settleTimeout, o.State)
		case <-time.After(pollEvery):
		}
	}
}

// state is the part of `systemctl show` ActUnit follows.
type state struct{ active, invocation string }

func unitState(ctx context.Context, r Runner, unit string) (state, error) {
	out, err := r.Run(ctx, "systemctl", "show", "--property=ActiveState,InvocationID",
		"--no-pager", "--no-ask-password", "--", unit)
	if err != nil {
		return state{}, err
	}
	p := parseKV(out)
	return state{active: p["ActiveState"], invocation: p["InvocationID"]}, nil
}

// settled reports whether a verb's job is over, given the state before it
// was queued and now, and with what error. A start or restart is over
// once a new run is active or has failed: the state read before systemd
// picks the job up is still the old run's (a failed unit being restarted
// reads "failed"). systemd without InvocationID cannot tell runs apart,
// so there the first settled state counts.
func settled(verb string, before, now state) (bool, error) {
	if verb == VerbStop {
		return now.active == "inactive" || now.active == "failed", nil
	}
	fresh := now.invocation == "" || now.invocation != before.invocation
	switch now.active {
	case "active":
		// Starting a running unit does nothing, and that is success.
		return verb == VerbStart || fresh, nil
	case "failed":
		if fresh {
			return true, fmt.Errorf("unit failed")
		}
	}
	return false, nil // not picked up yet, or activating, deactivating, ...
}

// UnitLogs reads the last lines of unit's journal. unit must pass
// ValidUnitName, so it cannot be read as an option.
func UnitLogs(ctx context.Context, r Runner, unit string) (string, error) {
	if !ValidUnitName(unit) {
		return "", fmt.Errorf("invalid unit name")
	}
	ctx, cancel := context.WithTimeout(ctx, listTimeout)
	defer cancel()
	return r.Run(ctx, "journalctl", "-u", unit, "-n", fmt.Sprint(logLines), "--no-pager", "-o", "short-iso")
}
