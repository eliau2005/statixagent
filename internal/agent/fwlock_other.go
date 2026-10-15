//go:build !(linux || darwin || freebsd || netbsd || openbsd || dragonfly)

package agent

// lockFile is a no-op where flock is unavailable; the agent only runs on
// Linux, and the in-process mutex still serializes its own trials.
func lockFile(string) (func(), error) { return func() {}, nil }
