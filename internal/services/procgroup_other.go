//go:build !unix

package services

import "os/exec"

// setProcessGroup is a no-op off Unix: the agent runs on Linux only and
// other builds exist for development. WaitDelay still bounds Run.
func setProcessGroup(*exec.Cmd) {}
