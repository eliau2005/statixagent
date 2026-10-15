//go:build unix

package services

import (
	"os/exec"
	"syscall"
)

// setProcessGroup starts the child as the leader of a new process group and
// makes cancellation kill the whole group, so a timeout also reaches the
// grandchildren a shell or wrapper script spawned.
func setProcessGroup(cmd *exec.Cmd) {
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	cmd.Cancel = func() error {
		return syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
	}
}
