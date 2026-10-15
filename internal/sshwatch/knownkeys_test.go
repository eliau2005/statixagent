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
