//go:build linux || darwin || freebsd || netbsd || openbsd || dragonfly

package agent

import (
	"os"
	"syscall"
)

// lockFile takes an exclusive lock on path, shared with every other
// process that locks it: the agent and a `--fw-rollback` run started by
// the rollback timer never touch the rules at the same time.
func lockFile(path string) (func(), error) {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, err
	}
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX); err != nil {
		f.Close()
		return nil, err
	}
	return func() {
		syscall.Flock(int(f.Fd()), syscall.LOCK_UN)
		f.Close()
	}, nil
}
