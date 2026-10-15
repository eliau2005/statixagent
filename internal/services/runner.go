package services

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// maxOutput caps the combined output kept from one command. Every caller
// parses a few lines; a runaway child must not grow the agent's memory.
const maxOutput = 64 << 10

// waitDelay bounds how long Run keeps reading output after the child has
// exited or been killed. Without it, a grandchild that inherited the pipes
// holds Run open until it exits on its own.
const waitDelay = 2 * time.Second

// defaultPath is the child PATH when the agent itself has none.
const defaultPath = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"

// ExecRunner is the production Runner: it executes the command with a
// safety timeout and returns combined output.
type ExecRunner struct {
	// Timeout bounds each invocation; zero means 10s.
	Timeout time.Duration
}

// Run implements Runner. The command runs in its own process group so a
// timeout kills everything it spawned, and its output is capped at 64 KiB.
func (e ExecRunner) Run(ctx context.Context, name string, args ...string) (string, error) {
	timeout := e.Timeout
	if timeout <= 0 {
		timeout = 10 * time.Second
	}
	cctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	cmd := exec.CommandContext(cctx, name, args...)
	// exec resolves a bare name through PATH to an absolute path and refuses
	// a match relative to the working directory, but a name containing a
	// separator is used as given, so insist on an absolute path there too.
	if cmd.Err == nil && !filepath.IsAbs(cmd.Path) {
		return "", fmt.Errorf("refusing to run %q: not an absolute path", name)
	}
	cmd.Env = cmdEnv()
	cmd.WaitDelay = waitDelay
	setProcessGroup(cmd)
	out := &cappedBuffer{max: maxOutput}
	cmd.Stdout = out
	cmd.Stderr = out
	err := cmd.Run()
	return strings.TrimSpace(out.String()), err
}

// cmdEnv is the child environment: PATH and a locale forced to C, nothing
// else, so the bot token or anything else in the agent's own environment
// never reaches a child. Several of the tools we shell out to ship
// translations — `ufw` prints "Status: active" only under a C/English
// locale — and every caller here parses the output.
//
// LANGUAGE must be cleared too, not just LC_ALL: ufw is a Python program,
// and Python's gettext.find() reads LANGUAGE *first* and uses it whenever
// it is non-empty. Unlike GNU gettext it does not suppress LANGUAGE for a
// C locale, so LC_ALL=C alone still yields "Statut : actif" on a host whose
// service environment carries LANGUAGE=fr_FR:fr.
func cmdEnv() []string {
	path := os.Getenv("PATH")
	if path == "" {
		path = defaultPath
	}
	return []string{"PATH=" + path, "LC_ALL=C", "LANG=C", "LANGUAGE="}
}

// cappedBuffer keeps the first max bytes written to it and drops the rest
// while still reporting success, so the child never gets a broken pipe
// because we stopped keeping its output.
type cappedBuffer struct {
	mu  sync.Mutex
	max int
	buf []byte
}

func (c *cappedBuffer) Write(p []byte) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if room := c.max - len(c.buf); room > 0 {
		c.buf = append(c.buf, p[:min(room, len(p))]...)
	}
	return len(p), nil
}

func (c *cappedBuffer) String() string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return string(c.buf)
}
