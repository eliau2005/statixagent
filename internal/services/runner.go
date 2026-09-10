package services

import (
	"context"
	"os"
	"os/exec"
	"strings"
	"time"
)

// ExecRunner is the production Runner: it executes the command with a
// safety timeout and returns combined output.
type ExecRunner struct {
	// Timeout bounds each invocation; zero means 10s.
	Timeout time.Duration
}

// Run implements Runner.
func (e ExecRunner) Run(ctx context.Context, name string, args ...string) (string, error) {
	timeout := e.Timeout
	if timeout <= 0 {
		timeout = 10 * time.Second
	}
	cctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	cmd := exec.CommandContext(cctx, name, args...)
	cmd.Env = cmdEnv()
	out, err := cmd.CombinedOutput()
	return strings.TrimSpace(string(out)), err
}

// cmdEnv is the child environment: the agent's own, with the locale forced
// to C. Several of the tools we shell out to ship translations — `ufw`
// prints "Status: active" only under a C/English locale — and every caller
// here parses the output. exec keeps the last occurrence of a duplicated
// key, so appending wins over an inherited LC_ALL.
func cmdEnv() []string {
	return append(os.Environ(), "LC_ALL=C", "LANG=C")
}
