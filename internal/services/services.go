// Package services checks the health of the things the user asked to watch:
// systemd units, named processes, local TCP ports, and HTTP endpoints.
// External access (systemctl, /proc, the network) is injected so every check
// is unit-testable.
package services

import (
	"context"
	"fmt"
	"io"
	"io/fs"
	"math"
	"net"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// State is the result of one check.
type State int

const (
	StateOK State = iota
	StateDegraded
	StateDown
	StateUnknown
)

func (s State) String() string {
	switch s {
	case StateOK:
		return "ok"
	case StateDegraded:
		return "degraded"
	case StateDown:
		return "down"
	default:
		return "unknown"
	}
}

// Result is one named check outcome.
type Result struct {
	Name   string
	State  State
	Detail string
}

// Runner executes an external command and returns its combined output.
// The linux implementation wraps exec.CommandContext.
type Runner interface {
	Run(ctx context.Context, name string, args ...string) (string, error)
}

// unitNameRE is the unit-name shape we pass to systemctl: it cannot start
// with "-", so a name can never be read as an option.
var unitNameRE = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9:_.@-]{0,250}\.(service|socket|timer)$`)

// ValidUnitName reports whether name is a unit name we will hand to
// systemctl.
func ValidUnitName(name string) bool {
	return unitNameRE.MatchString(name)
}

// CheckSystemdUnits queries each unit's ActiveState/SubState via
// `systemctl show`, which is script-safe output (key=value lines). A name
// that fails ValidUnitName (one already in an older config, say) is
// reported as unknown and never reaches systemctl.
func CheckSystemdUnits(ctx context.Context, r Runner, units []string) []Result {
	out := make([]Result, 0, len(units))
	for _, u := range units {
		// systemctl reads a name with no type suffix as a .service, so a
		// hand-written "nginx" keeps working; query it under that full name.
		unit := u
		if !strings.Contains(unit, ".") {
			unit += ".service"
		}
		if !ValidUnitName(unit) {
			out = append(out, Result{Name: u, State: StateUnknown, Detail: "invalid unit name"})
			continue
		}
		raw, err := r.Run(ctx, "systemctl", "show",
			"--property=ActiveState,SubState,NRestarts", "--no-pager", "--no-ask-password", "--", unit)
		if err != nil {
			out = append(out, Result{Name: u, State: StateUnknown, Detail: err.Error()})
			continue
		}
		props := parseKV(raw)
		active, sub := props["ActiveState"], props["SubState"]
		res := Result{Name: u, Detail: active + "/" + sub}
		switch active {
		case "active":
			res.State = StateOK
		case "activating", "deactivating", "reloading":
			res.State = StateDegraded
		case "failed", "inactive":
			res.State = StateDown
		default:
			res.State = StateUnknown
		}
		if n := props["NRestarts"]; n != "" && n != "0" && res.State == StateOK {
			res.Detail += ", restarts=" + n
		}
		out = append(out, res)
	}
	return out
}

// listTimeout bounds one list-units or show call (docs §6).
const listTimeout = 5 * time.Second

// Unit is one line of `systemctl list-units`.
type Unit struct {
	Name        string
	Load        string // loaded, not-found, masked, ...
	Active      string // active, failed, inactive, activating, ...
	Sub         string // running, exited, dead, ...
	Description string
}

// ListUnits lists every loaded service, socket and timer, whatever its
// state, in one systemctl call. Names are as systemd prints them and may
// carry escapes ("\x2d"), so callers check ValidUnitName before handing
// one back to systemctl.
func ListUnits(ctx context.Context, r Runner) ([]Unit, error) {
	ctx, cancel := context.WithTimeout(ctx, listTimeout)
	defer cancel()
	out, err := r.Run(ctx, "systemctl", "list-units", "--all", "--type=service,socket,timer",
		"--no-legend", "--plain", "--no-pager", "--no-ask-password")
	if err != nil {
		return nil, err
	}
	var units []Unit
	for line := range strings.SplitSeq(out, "\n") {
		f := strings.Fields(line)
		if len(f) > 0 && f[0] == "●" { // a failed unit's marker on older systemd
			f = f[1:]
		}
		if len(f) < 4 || strings.HasPrefix(f[0], "-") {
			continue
		}
		units = append(units, Unit{Name: f[0], Load: f[1], Active: f[2], Sub: f[3], Description: strings.Join(f[4:], " ")})
	}
	return units, nil
}

// UnitDetail is what `systemctl show` reports about one unit.
type UnitDetail struct {
	Load, Active, Sub string
	// Result is how the last run ended: success, exit-code, signal, ...
	Result string
	// UnitFile is whether it starts at boot: enabled, disabled, static, ...
	UnitFile string
	// Since is the last state change; zero when systemd has none.
	Since    time.Time
	Restarts string // "" when unknown
	// Memory is the unit's current memory use; ok is false when systemd
	// does not account it.
	Memory   uint64
	MemoryOK bool
}

// ShowUnit reads one unit's state with `systemctl show`. name must pass
// ValidUnitName; it always follows "--".
func ShowUnit(ctx context.Context, r Runner, name string) (UnitDetail, error) {
	if !ValidUnitName(name) {
		return UnitDetail{}, fmt.Errorf("invalid unit name")
	}
	ctx, cancel := context.WithTimeout(ctx, listTimeout)
	defer cancel()
	raw, err := r.Run(ctx, "systemctl", "show",
		"--property=LoadState,ActiveState,SubState,Result,UnitFileState,StateChangeTimestamp,NRestarts,MemoryCurrent",
		"--no-pager", "--no-ask-password", "--", name)
	if err != nil {
		return UnitDetail{}, err
	}
	p := parseKV(raw)
	d := UnitDetail{Load: p["LoadState"], Active: p["ActiveState"], Sub: p["SubState"], Result: p["Result"],
		UnitFile: p["UnitFileState"], Restarts: p["NRestarts"]}
	// "Thu 2026-10-15 12:41:00 UTC", in the host's zone (LC_ALL=C).
	if t, err := time.Parse("Mon 2006-01-02 15:04:05 MST", p["StateChangeTimestamp"]); err == nil {
		d.Since = t
	}
	// Unaccounted memory reads "[not set]", or as the maximum uint64.
	if n, err := strconv.ParseUint(p["MemoryCurrent"], 10, 64); err == nil && n != math.MaxUint64 {
		d.Memory, d.MemoryOK = n, true
	}
	return d, nil
}

func parseKV(s string) map[string]string {
	m := map[string]string{}
	for _, line := range strings.Split(s, "\n") {
		if k, v, ok := strings.Cut(strings.TrimSpace(line), "="); ok {
			m[k] = v
		}
	}
	return m
}

// CheckProcesses scans a /proc-shaped filesystem for the named executables
// (matched against each PID's comm, which is the kernel's 15-char task name).
func CheckProcesses(procfs fs.FS, names []string) []Result {
	running := map[string]int{} // comm → count
	pids, _ := fs.Glob(procfs, "[0-9]*")
	for _, pid := range pids {
		b, err := fs.ReadFile(procfs, pid+"/comm")
		if err != nil {
			continue
		}
		running[strings.TrimSpace(string(b))]++
	}
	out := make([]Result, 0, len(names))
	for _, n := range names {
		// comm is truncated to 15 chars; match accordingly
		key := n
		if len(key) > 15 {
			key = key[:15]
		}
		if c := running[key]; c > 0 {
			out = append(out, Result{Name: n, State: StateOK, Detail: fmt.Sprintf("%d running", c)})
		} else {
			out = append(out, Result{Name: n, State: StateDown, Detail: "not running"})
		}
	}
	return out
}

// Dialer matches net.Dialer.DialContext, injectable for tests.
type Dialer func(ctx context.Context, network, addr string) (net.Conn, error)

// CheckPorts verifies each TCP port accepts a connection on localhost.
func CheckPorts(ctx context.Context, dial Dialer, ports []PortSpec) []Result {
	out := make([]Result, 0, len(ports))
	for _, p := range ports {
		name := p.Label
		if name == "" {
			name = fmt.Sprintf("port %d", p.Port)
		}
		dctx, cancel := context.WithTimeout(ctx, 3*time.Second)
		conn, err := dial(dctx, "tcp", fmt.Sprintf("127.0.0.1:%d", p.Port))
		cancel()
		if err != nil {
			out = append(out, Result{Name: name, State: StateDown, Detail: err.Error()})
			continue
		}
		conn.Close()
		out = append(out, Result{Name: name, State: StateOK, Detail: "listening"})
	}
	return out
}

// PortSpec mirrors config.PortCheck without importing config.
type PortSpec struct {
	Port  int
	Label string
}

// HTTPSpec mirrors config.HTTPCheck without importing config.
type HTTPSpec struct {
	URL          string
	ExpectStatus int
	Timeout      time.Duration
}

// CheckHTTP probes each endpoint and compares the status code.
func CheckHTTP(ctx context.Context, client *http.Client, checks []HTTPSpec) []Result {
	if client == nil {
		client = http.DefaultClient
	}
	// Health checks report the configured endpoint's own status. Following a
	// redirect would hide both expected 3xx responses and unexpected redirects.
	probeClient := *client
	probeClient.CheckRedirect = func(_ *http.Request, _ []*http.Request) error {
		return http.ErrUseLastResponse
	}

	out := make([]Result, 0, len(checks))
	for _, c := range checks {
		want := c.ExpectStatus
		if want == 0 {
			want = http.StatusOK
		}
		timeout := c.Timeout
		if timeout <= 0 {
			timeout = 10 * time.Second
		}
		rctx, cancel := context.WithTimeout(ctx, timeout)
		req, err := http.NewRequestWithContext(rctx, http.MethodGet, c.URL, nil)
		if err != nil {
			cancel()
			out = append(out, Result{Name: c.URL, State: StateUnknown, Detail: err.Error()})
			continue
		}
		start := time.Now()
		resp, err := probeClient.Do(req)
		elapsed := time.Since(start).Round(time.Millisecond)
		if err != nil {
			cancel()
			out = append(out, Result{Name: c.URL, State: StateDown, Detail: err.Error()})
			continue
		}
		io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
		resp.Body.Close()
		cancel()
		if resp.StatusCode == want {
			out = append(out, Result{Name: c.URL, State: StateOK,
				Detail: fmt.Sprintf("%d in %s", resp.StatusCode, elapsed)})
		} else {
			out = append(out, Result{Name: c.URL, State: StateDegraded,
				Detail: fmt.Sprintf("got %d, want %d", resp.StatusCode, want)})
		}
	}
	return out
}
