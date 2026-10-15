package sshwatch

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestKnownKeysLearn(t *testing.T) {
	k, err := LoadKnownKeys("")
	if err != nil {
		t.Fatal(err)
	}
	steps := []struct {
		user, fp string
		want     bool
	}{
		{"deploy", "SHA256:aaa", true},
		{"deploy", "SHA256:aaa", false}, // same pair again
		{"deploy", "SHA256:bbb", true},  // new key, same user
		{"alice", "SHA256:aaa", true},   // same key, different user
		{"alice", "SHA256:aaa", false},
	}
	for i, s := range steps {
		got, err := k.Learn(s.user, s.fp)
		if err != nil || got != s.want {
			t.Errorf("step %d Learn(%q, %q) = %v, %v; want %v", i, s.user, s.fp, got, err, s.want)
		}
	}
	if k.Len() != 3 {
		t.Errorf("Len = %d, want 3", k.Len())
	}
}

func TestKnownKeysPersist(t *testing.T) {
	path := filepath.Join(t.TempDir(), "known_keys")
	k, err := LoadKnownKeys(path)
	if err != nil || k.Len() != 0 {
		t.Fatalf("missing file: %v, len %d", err, k.Len())
	}
	for _, fp := range []string{"SHA256:bbb", "SHA256:aaa"} {
		if _, err := k.Learn("deploy", fp); err != nil {
			t.Fatal(err)
		}
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
	if !strings.Contains(string(raw), "deploy SHA256:aaa\ndeploy SHA256:bbb\n") {
		t.Errorf("file not sorted user/fingerprint lines:\n%s", raw)
	}

	reloaded, err := LoadKnownKeys(path)
	if err != nil {
		t.Fatal(err)
	}
	if added, _ := reloaded.Learn("deploy", "SHA256:aaa"); added {
		t.Error("a pair learned before the restart must stay known")
	}
	if added, _ := reloaded.Learn("deploy", "SHA256:ccc"); !added {
		t.Error("an unseen pair must still be new after the restart")
	}
}

func TestKnownKeysParse(t *testing.T) {
	cases := []struct {
		name    string
		body    string
		wantLen int
		wantErr bool
	}{
		{"empty", "", 0, false},
		{"comments and blanks", "# header\n\n  deploy SHA256:aaa  \n", 1, false},
		{"several", "deploy SHA256:aaa\nroot SHA256:bbb\n", 2, false},
		{"missing fingerprint", "deploy SHA256:aaa\ndeploy\n", 1, true},
		{"not a fingerprint", "deploy MD5:aa:bb\n", 0, true},
		{"extra field", "deploy SHA256:aaa extra\n", 0, true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "known_keys")
			if err := os.WriteFile(path, []byte(c.body), 0o600); err != nil {
				t.Fatal(err)
			}
			k, err := LoadKnownKeys(path)
			if (err != nil) != c.wantErr {
				t.Errorf("err = %v, wantErr %v", err, c.wantErr)
			}
			if k == nil || k.Len() != c.wantLen {
				t.Fatalf("len = %d, want %d (pairs before a bad line are kept)", k.Len(), c.wantLen)
			}
		})
	}
}

func TestKnownKeysSaveFailureKeepsMemory(t *testing.T) {
	path := filepath.Join(t.TempDir(), "missing-dir", "known_keys")
	k, err := LoadKnownKeys(path)
	if err != nil {
		t.Fatal(err)
	}
	added, err := k.Learn("deploy", "SHA256:aaa")
	if !added || err == nil {
		t.Fatalf("Learn = %v, %v; want new pair and a save error", added, err)
	}
	if again, _ := k.Learn("deploy", "SHA256:aaa"); again {
		t.Error("pair must be remembered in memory despite the save error")
	}
}

func TestKnownKeysMalformedLinesSkippedAndPreserved(t *testing.T) {
	path := filepath.Join(t.TempDir(), "known_keys")
	body := "deploy SHA256:aaa\ngarbage\nalice SHA256:bbb\ndeploy MD5:x\nbob SHA256:ccc\n"
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	k, err := LoadKnownKeys(path)
	if err == nil || !strings.Contains(err.Error(), "line 2 skipped") || !strings.Contains(err.Error(), "line 4 skipped") {
		t.Errorf("err = %v, want one report per bad line", err)
	}
	if k.Len() != 3 {
		t.Fatalf("len = %d, want the 3 good pairs, including those after a bad line", k.Len())
	}

	if added, err := k.Learn("carol", "SHA256:ddd"); !added || err != nil {
		t.Fatalf("Learn = %v, %v", added, err)
	}
	raw, _ := os.ReadFile(path)
	for _, want := range []string{"deploy SHA256:aaa\n", "alice SHA256:bbb\n", "bob SHA256:ccc\n", "carol SHA256:ddd\n", "garbage\n", "deploy MD5:x\n"} {
		if !strings.Contains(string(raw), want) {
			t.Errorf("rewritten file lost %q:\n%s", want, raw)
		}
	}
}

func TestKnownKeysUnreadableFileNeverOverwritten(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("reading a directory as a file behaves differently on windows")
	}
	// A directory opens but cannot be read, like a file with a bad sector.
	path := t.TempDir()
	k, err := LoadKnownKeys(path)
	if err == nil {
		t.Fatal("want a read error")
	}
	added, err := k.Learn("deploy", "SHA256:aaa")
	if !added || err == nil {
		t.Errorf("Learn = %v, %v; want new in memory and a not-saved error", added, err)
	}
	if info, statErr := os.Stat(path); statErr != nil || !info.IsDir() {
		t.Errorf("unreadable store was replaced: %v", statErr)
	}
}

func TestKnownKeysUserRoundTrip(t *testing.T) {
	path := filepath.Join(t.TempDir(), "known_keys")
	k, err := LoadKnownKeys(path)
	if err != nil {
		t.Fatal(err)
	}
	users := []string{
		"deploy",
		"#looks-like-a-comment",
		`"starts-with-quote`,
		"has space",
		"tab\tuser",
		"new\nline",
		"ünïcode",
		"",
	}
	for _, u := range users {
		if added, err := k.Learn(u, "SHA256:aaa"); !added || err != nil {
			t.Fatalf("Learn(%q) = %v, %v", u, added, err)
		}
	}
	reloaded, err := LoadKnownKeys(path)
	if err != nil {
		raw, _ := os.ReadFile(path)
		t.Fatalf("reload: %v\n%s", err, raw)
	}
	if reloaded.Len() != len(users) {
		t.Errorf("len = %d, want %d", reloaded.Len(), len(users))
	}
	for _, u := range users {
		if !reloaded.Known(u, "SHA256:aaa") {
			t.Errorf("user %q did not survive a save and reload", u)
		}
	}
	if reloaded.Known("has", "SHA256:aaa") {
		t.Error("a name with a space must not split into another user")
	}
}

func TestKnownKeysRejectsBadFingerprint(t *testing.T) {
	k, _ := LoadKnownKeys("")
	for _, fp := range []string{"", "SHA256:", "MD5:aa", "SHA256:a b", "SHA256:a\nb"} {
		if added, err := k.Learn("deploy", fp); added || err == nil {
			t.Errorf("Learn(%q) = %v, %v; want rejected", fp, added, err)
		}
	}
}
