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
	"net"
	"net/http"
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

// CheckSystemdUnits queries each unit's ActiveState/SubState via
// `systemctl show`, which is script-safe output (key=value lines).
func CheckSystemdUnits(ctx context.Context, r Runner, units []string) []Result {
	out := make([]Result, 0, len(units))
	for _, u := range units {
		raw, err := r.Run(ctx, "systemctl", "show", u,
			"--property=ActiveState,SubState,NRestarts", "--no-pager")
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
	noFollow := *client
	noFollow.CheckRedirect = func(*http.Request, []*http.Request) error {
		return http.ErrUseLastResponse
	}
	client = &noFollow
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
		resp, err := client.Do(req)
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
