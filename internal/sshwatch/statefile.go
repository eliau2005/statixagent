package sshwatch

import (
	"fmt"
	"os"
	"path/filepath"
)

// writeStateFile replaces path with data atomically and owner-only. The
// temp file is synced before the rename and the directory after it, so a
// power loss leaves either the old file or the new one, never an empty one.
// It backs the small state files kept next to the config (known_keys,
// trusted_ips).
func writeStateFile(path string, data []byte) error {
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, "."+filepath.Base(path)+"-*")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName) // no-op after successful rename
	if err := tmp.Chmod(0o600); err != nil {
		tmp.Close()
		return err
	}
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmpName, path); err != nil {
		return err
	}
	// Best effort: make the rename itself durable. Not every platform
	// supports syncing a directory, and the data is already safe.
	if d, err := os.Open(dir); err == nil {
		d.Sync()
		d.Close()
	}
	return nil
}

// errNotSaved builds the error for a store whose existing file could not
// be read: rewriting it would replace entries the agent never saw.
func errNotSaved(what string) error {
	return fmt.Errorf("%s: not saved, the existing file could not be read", what)
}
