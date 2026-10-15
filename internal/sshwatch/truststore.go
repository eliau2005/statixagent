package sshwatch

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net/netip"
	"os"
	"slices"
	"strings"
	"sync"
)

// TrustStore holds the trusted SSH sources added from the bot (/trust and
// the "Trust this IP" button). They live apart from the config's
// ssh.trusted_ips, which stays a hand-edited static baseline, so the bot
// can always tell which entries it may remove.
//
// The file is one entry per line (a bare address for a single host, CIDR
// otherwise) with # comments, kept next to the config and rewritten like
// known_keys: atomically, with unparseable lines preserved, and never over
// a file that could not be read. An empty path keeps the list in memory.
type TrustStore struct {
	path  string
	parse func(string) (netip.Prefix, error)

	mu       sync.Mutex
	entries  []netip.Prefix // in the order they were added
	bad      []string
	readOnly bool
}

// LoadTrustStore reads the list from path, parsing each line with parse
// (config.ParseTrustedIP, so a hand-edited file obeys the same rules as
// the config). A missing file is an empty list. Malformed lines are
// skipped and reported, one error per line; the store is always usable.
func LoadTrustStore(path string, parse func(string) (netip.Prefix, error)) (*TrustStore, error) {
	s := &TrustStore{path: path, parse: parse}
	if path == "" {
		return s, nil
	}
	f, err := os.Open(path)
	if errors.Is(err, fs.ErrNotExist) {
		return s, nil
	}
	if err != nil {
		s.readOnly = true
		return s, fmt.Errorf("trusted ips: %w (changes will not be saved)", err)
	}
	defer f.Close()
	if err := s.read(f); err != nil {
		return s, fmt.Errorf("trusted ips %s: %w", path, err)
	}
	return s, nil
}

func (s *TrustStore) read(r io.Reader) error {
	var errs []error
	sc := bufio.NewScanner(r)
	for n := 1; sc.Scan(); n++ {
		raw := sc.Text()
		line := strings.TrimSpace(raw)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		p, err := s.parse(line)
		if err != nil {
			s.bad = append(s.bad, raw)
			errs = append(errs, fmt.Errorf("line %d skipped: %w", n, err))
			continue
		}
		if !slices.Contains(s.entries, p) {
			s.entries = append(s.entries, p)
		}
	}
	if err := sc.Err(); err != nil {
		s.readOnly = true
		errs = append(errs, fmt.Errorf("%w (changes will not be saved)", err))
	}
	return errors.Join(errs...)
}

// Entries returns a copy of the list, oldest first.
func (s *TrustStore) Entries() []netip.Prefix {
	s.mu.Lock()
	defer s.mu.Unlock()
	return slices.Clone(s.entries)
}

// Len returns the number of entries.
func (s *TrustStore) Len() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.entries)
}

// Add appends p and reports whether it was new. A new entry is kept in
// memory even if saving fails; the error says it will not survive a
// restart.
func (s *TrustStore) Add(p netip.Prefix) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if slices.Contains(s.entries, p) {
		return false, nil
	}
	s.entries = append(s.entries, p)
	return true, s.save()
}

// Remove deletes p and reports whether it was present. As with Add, the
// in-memory change sticks even if saving fails.
func (s *TrustStore) Remove(p netip.Prefix) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	i := slices.Index(s.entries, p)
	if i < 0 {
		return false, nil
	}
	s.entries = slices.Delete(s.entries, i, i+1)
	return true, s.save()
}

// FormatPrefix renders p the way users type it: a bare address for a
// single host, CIDR otherwise.
func FormatPrefix(p netip.Prefix) string {
	if p.IsSingleIP() {
		return p.Addr().String()
	}
	return p.String()
}

// save rewrites the file (see writeStateFile). Callers hold s.mu.
func (s *TrustStore) save() error {
	if s.path == "" {
		return nil
	}
	if s.readOnly {
		return errNotSaved("trusted ips")
	}
	var b strings.Builder
	b.WriteString("# SSH sources trusted from Telegram (/trust, /untrust); see also ssh.trusted_ips in config.toml\n")
	for _, p := range s.entries {
		b.WriteString(FormatPrefix(p) + "\n")
	}
	for _, l := range s.bad {
		b.WriteString(l + "\n")
	}
	if err := writeStateFile(s.path, []byte(b.String())); err != nil {
		return fmt.Errorf("trusted ips: %w", err)
	}
	return nil
}
