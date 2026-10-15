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
	"strconv"
	"strings"
	"sync"
	"unicode"
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
	// bad holds lines that did not parse; save writes them back verbatim
	// so a damaged file never loses entries it could not read.
	bad []string
	// readOnly is set when the file exists but could not be read: saving
	// would replace it with a smaller set, so new pairs stay in memory.
	readOnly bool
}

type knownKey struct{ user, fingerprint string }

// LoadKnownKeys reads the set from path. A missing file is an empty set.
// Malformed lines are skipped and reported, one error per line, in the
// joined error; the returned set is always usable.
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
		k.readOnly = true
		return k, fmt.Errorf("known keys: %w (new keys will not be saved)", err)
	}
	defer f.Close()
	if err := k.parse(f); err != nil {
		return k, fmt.Errorf("known keys %s: %w", path, err)
	}
	return k, nil
}

// parse adds the pairs from r. Blank lines and # comments are skipped;
// each malformed line is kept in k.bad and reported. A read error leaves
// the set read-only, since the rest of the file was never seen.
func (k *KnownKeys) parse(r io.Reader) error {
	var errs []error
	sc := bufio.NewScanner(r)
	for n := 1; sc.Scan(); n++ {
		raw := sc.Text()
		line := strings.TrimSpace(raw)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		user, fp, err := parseKnownKeyLine(line)
		if err != nil {
			k.bad = append(k.bad, raw)
			errs = append(errs, fmt.Errorf("line %d skipped: %w", n, err))
			continue
		}
		k.keys[knownKey{user, fp}] = struct{}{}
	}
	if err := sc.Err(); err != nil {
		k.readOnly = true
		errs = append(errs, fmt.Errorf("%w (new keys will not be saved)", err))
	}
	return errors.Join(errs...)
}

// parseKnownKeyLine splits `user SHA256:fingerprint`. The user is written
// Go-quoted when it would not survive a bare field (see formatUser).
func parseKnownKeyLine(line string) (user, fp string, err error) {
	rest := line
	if strings.HasPrefix(line, `"`) {
		q, err := strconv.QuotedPrefix(line)
		if err != nil {
			return "", "", errors.New("bad quoted user")
		}
		user, _ = strconv.Unquote(q)
		rest = line[len(q):]
		if rest != "" && !unicode.IsSpace(rune(rest[0])) {
			return "", "", errors.New("want \"user SHA256:fingerprint\"")
		}
	} else if i := strings.IndexFunc(line, unicode.IsSpace); i >= 0 {
		user, rest = line[:i], line[i:]
	} else {
		user, rest = line, ""
	}
	fields := strings.Fields(rest)
	if len(fields) != 1 || !validFingerprint(fields[0]) {
		return "", "", errors.New("want \"user SHA256:fingerprint\"")
	}
	return user, fields[0], nil
}

// formatUser writes a user name so parseKnownKeyLine reads it back
// unchanged: plain when it is a single bare word, Go-quoted when it is
// empty, contains whitespace or control characters, or starts with a
// comment or quote character.
func formatUser(user string) string {
	if user == "" || strings.HasPrefix(user, "#") || strings.HasPrefix(user, `"`) ||
		strings.IndexFunc(user, func(r rune) bool { return unicode.IsSpace(r) || !unicode.IsPrint(r) }) >= 0 {
		return strconv.Quote(user)
	}
	return user
}

func validFingerprint(fp string) bool {
	return strings.HasPrefix(fp, "SHA256:") && len(fp) > len("SHA256:") &&
		strings.IndexFunc(fp, func(r rune) bool { return unicode.IsSpace(r) || !unicode.IsPrint(r) }) < 0
}

// Known reports whether user has logged in with fingerprint before.
func (k *KnownKeys) Known(user, fingerprint string) bool {
	k.mu.Lock()
	defer k.mu.Unlock()
	_, ok := k.keys[knownKey{user, fingerprint}]
	return ok
}

// Learn records that user logged in with fingerprint and reports whether
// the pair was new. A new pair is remembered in memory even if persisting
// it fails; the error is returned so the caller can log it.
func (k *KnownKeys) Learn(user, fingerprint string) (bool, error) {
	if !validFingerprint(fingerprint) {
		return false, fmt.Errorf("known keys: invalid fingerprint %q", fingerprint)
	}
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

// save rewrites the file atomically with owner-only permissions, syncing
// the data before the rename and the directory after it so a power loss
// leaves either the old file or the new one, never an empty one. Callers
// hold k.mu.
func (k *KnownKeys) save() error {
	if k.path == "" {
		return nil
	}
	if k.readOnly {
		return errors.New("known keys: not saved, the existing file could not be read")
	}
	lines := make([]string, 0, len(k.keys))
	for key := range k.keys {
		lines = append(lines, formatUser(key.user)+" "+key.fingerprint+"\n")
	}
	sort.Strings(lines)
	var b strings.Builder
	b.WriteString("# user fingerprint, learned from SSH key logins\n")
	b.WriteString(strings.Join(lines, ""))
	for _, l := range k.bad {
		b.WriteString(l + "\n")
	}

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
	if _, err := io.WriteString(tmp, b.String()); err != nil {
		tmp.Close()
		return fmt.Errorf("known keys: %w", err)
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return fmt.Errorf("known keys: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("known keys: %w", err)
	}
	if err := os.Rename(tmpName, k.path); err != nil {
		return fmt.Errorf("known keys: %w", err)
	}
	// Best effort: make the rename itself durable. Not every platform
	// supports syncing a directory, and the data is already safe.
	if d, err := os.Open(dir); err == nil {
		d.Sync()
		d.Close()
	}
	return nil
}
