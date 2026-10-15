package sshwatch

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
)

// KnownKeys remembers which public keys (by SHA256 fingerprint) each user
// has logged in with, so a login from a trusted source can still alert when
// it uses a key never seen before for that user.
//
// The set is persisted as a small text file of "user fingerprint" lines next
// to the config, rewritten atomically whenever a new pair is learned. SSH
// history itself lives only in memory, so there is nothing else to seed
// from: after an upgrade (or with the file deleted) the first key login per
// user and key is new once. An empty path keeps the set in memory only.
type KnownKeys struct {
	path string

	mu   sync.Mutex
	keys map[knownKey]struct{}
}

type knownKey struct{ user, fingerprint string }

// LoadKnownKeys reads the set from path. A missing file is an empty set.
func LoadKnownKeys(path string) (*KnownKeys, error) {
	k := &KnownKeys{path: path, keys: map[knownKey]struct{}{}}
	if path == "" {
		return k, nil
	}
	f, err := os.Open(path)
	if errors.Is(err, fs.ErrNotExist) {
		return k, nil
	}
	if err != nil {
		return k, fmt.Errorf("known keys: %w", err)
	}
	defer f.Close()
	if err := k.parse(f); err != nil {
		return k, fmt.Errorf("known keys %s: %w", path, err)
	}
	return k, nil
}

// parse adds the "user fingerprint" pairs from r. Blank lines and #
// comments are skipped; a malformed line is an error, but the pairs parsed
// before it are kept.
func (k *KnownKeys) parse(r io.Reader) error {
	sc := bufio.NewScanner(r)
	for n := 1; sc.Scan(); n++ {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) != 2 || !strings.HasPrefix(fields[1], "SHA256:") {
			return fmt.Errorf("line %d: want \"user SHA256:fingerprint\"", n)
		}
		k.keys[knownKey{fields[0], fields[1]}] = struct{}{}
	}
	return sc.Err()
}

// Learn records that user logged in with fingerprint and reports whether
// the pair was new. A new pair is remembered in memory even if persisting
// it fails; the error is returned so the caller can log it.
func (k *KnownKeys) Learn(user, fingerprint string) (bool, error) {
	k.mu.Lock()
	defer k.mu.Unlock()
	key := knownKey{user, fingerprint}
	if _, ok := k.keys[key]; ok {
		return false, nil
	}
	k.keys[key] = struct{}{}
	return true, k.save()
}

// Len returns the number of remembered pairs.
func (k *KnownKeys) Len() int {
	k.mu.Lock()
	defer k.mu.Unlock()
	return len(k.keys)
}

// save rewrites the file atomically with owner-only permissions. Callers
// hold k.mu.
func (k *KnownKeys) save() error {
	if k.path == "" {
		return nil
	}
	lines := make([]string, 0, len(k.keys))
	for key := range k.keys {
		lines = append(lines, key.user+" "+key.fingerprint+"\n")
	}
	sort.Strings(lines)

	dir := filepath.Dir(k.path)
	tmp, err := os.CreateTemp(dir, ".known_keys-*")
	if err != nil {
		return fmt.Errorf("known keys: %w", err)
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName) // no-op after successful rename
	if err := tmp.Chmod(0o600); err != nil {
		tmp.Close()
		return fmt.Errorf("known keys: %w", err)
	}
	if _, err := io.WriteString(tmp, "# user fingerprint, learned from SSH key logins\n"+strings.Join(lines, "")); err != nil {
		tmp.Close()
		return fmt.Errorf("known keys: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("known keys: %w", err)
	}
	if err := os.Rename(tmpName, k.path); err != nil {
		return fmt.Errorf("known keys: %w", err)
	}
	return nil
}
