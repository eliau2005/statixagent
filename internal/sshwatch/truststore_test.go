package sshwatch

import (
	"net/netip"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"testing"

	"github.com/eliau2005/statixagent/internal/config"
)

func TestTrustStoreRoundTrip(t *testing.T) {
	path := filepath.Join(t.TempDir(), "trusted_ips")
	s, err := LoadTrustStore(path, config.ParseTrustedIP)
	if err != nil || s.Len() != 0 {
		t.Fatalf("missing file: %v, len %d", err, s.Len())
	}
	want := []netip.Prefix{
		netip.MustParsePrefix("203.0.113.7/32"),
		netip.MustParsePrefix("10.0.0.0/8"),
		netip.MustParsePrefix("2001:db8::/32"),
	}
	for _, p := range want {
		if added, err := s.Add(p); !added || err != nil {
			t.Fatalf("Add(%s) = %v, %v", p, added, err)
		}
	}
	if added, _ := s.Add(want[0]); added {
		t.Error("duplicate Add must report false")
	}

	if runtime.GOOS != "windows" {
		info, err := os.Stat(path)
		if err != nil {
			t.Fatal(err)
		}
		if perm := info.Mode().Perm(); perm != 0o600 {
			t.Errorf("perm = %o, want 600", perm)
		}
	}
	raw, _ := os.ReadFile(path)
	if !strings.HasSuffix(string(raw), "\n203.0.113.7\n10.0.0.0/8\n2001:db8::/32\n") {
		t.Errorf("file not one entry per line in order, single hosts bare:\n%s", raw)
	}

	reloaded, err := LoadTrustStore(path, config.ParseTrustedIP)
	if err != nil || !slices.Equal(reloaded.Entries(), want) {
		t.Fatalf("reload = %v, %v; want %v", reloaded.Entries(), err, want)
	}
	if removed, err := reloaded.Remove(want[1]); !removed || err != nil {
		t.Fatalf("Remove = %v, %v", removed, err)
	}
	if removed, _ := reloaded.Remove(want[1]); removed {
		t.Error("second Remove must report false")
	}
	again, _ := LoadTrustStore(path, config.ParseTrustedIP)
	if !slices.Equal(again.Entries(), []netip.Prefix{want[0], want[2]}) {
		t.Errorf("after Remove and reload: %v", again.Entries())
	}
}

func TestTrustStoreBadLinesSkippedAndKept(t *testing.T) {
	path := filepath.Join(t.TempDir(), "trusted_ips")
	// A hand edit can never smuggle in what /trust refuses: the file is
	// parsed with the same rules as the config.
	body := "# comment\n203.0.113.7\n0.0.0.0/0\n::/0\n::ffff:10.0.0.0/64\nnot-an-ip\n10.0.0.0/8\n10.0.0.0/8\n"
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	s, err := LoadTrustStore(path, config.ParseTrustedIP)
	for _, n := range []string{"line 3 skipped", "line 4 skipped", "line 5 skipped", "line 6 skipped"} {
		if err == nil || !strings.Contains(err.Error(), n) {
			t.Errorf("err = %v, want %q", err, n)
		}
	}
	want := []netip.Prefix{netip.MustParsePrefix("203.0.113.7/32"), netip.MustParsePrefix("10.0.0.0/8")}
	if !slices.Equal(s.Entries(), want) {
		t.Fatalf("entries = %v, want %v (bad lines skipped, duplicate merged)", s.Entries(), want)
	}

	if _, err := s.Add(netip.MustParsePrefix("2001:db8::/32")); err != nil {
		t.Fatal(err)
	}
	raw, _ := os.ReadFile(path)
	for _, line := range []string{"0.0.0.0/0\n", "::/0\n", "::ffff:10.0.0.0/64\n", "not-an-ip\n", "2001:db8::/32\n"} {
		if !strings.Contains(string(raw), line) {
			t.Errorf("rewritten file lost %q:\n%s", line, raw)
		}
	}
	// The preserved bad lines are still never trusted after a reload.
	again, _ := LoadTrustStore(path, config.ParseTrustedIP)
	if len(again.Entries()) != 3 {
		t.Errorf("reload entries = %v", again.Entries())
	}
}

func TestTrustStoreUnreadableNeverOverwritten(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("reading a directory as a file behaves differently on windows")
	}
	path := t.TempDir() // opens, but cannot be read as a file
	s, err := LoadTrustStore(path, config.ParseTrustedIP)
	if err == nil {
		t.Fatal("want a read error")
	}
	added, err := s.Add(netip.MustParsePrefix("203.0.113.7/32"))
	if !added || err == nil {
		t.Errorf("Add = %v, %v; want kept in memory with a not-saved error", added, err)
	}
	if info, statErr := os.Stat(path); statErr != nil || !info.IsDir() {
		t.Errorf("unreadable store was replaced: %v", statErr)
	}
}

func TestTrustStoreInMemory(t *testing.T) {
	s, err := LoadTrustStore("", config.ParseTrustedIP)
	if err != nil {
		t.Fatal(err)
	}
	if added, err := s.Add(netip.MustParsePrefix("10.0.0.0/8")); !added || err != nil {
		t.Errorf("Add = %v, %v", added, err)
	}
}

func TestFormatPrefix(t *testing.T) {
	for in, want := range map[string]string{
		"203.0.113.7/32":  "203.0.113.7",
		"10.0.0.0/8":      "10.0.0.0/8",
		"2001:db8::1/128": "2001:db8::1",
		"2001:db8::/32":   "2001:db8::/32",
	} {
		if got := FormatPrefix(netip.MustParsePrefix(in)); got != want {
			t.Errorf("FormatPrefix(%s) = %s, want %s", in, got, want)
		}
	}
}
