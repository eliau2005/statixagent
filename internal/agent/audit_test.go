package agent

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// TestAuditRotationAndMode: the log rotates past its size, keeps five
// files in all, and is readable by root only.
func TestAuditRotationAndMode(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "audit")
	l := newAuditLog(filepath.Join(dir, "actions.jsonl"))
	l.max = 300
	for range 40 {
		l.write(auditRecord{Phase: phaseExecuted, Action: actKick, Target: strings.Repeat("x", 50)})
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, e := range entries {
		names = append(names, e.Name())
		fi, err := e.Info()
		if err != nil {
			t.Fatal(err)
		}
		if fi.Mode().Perm() != 0o600 {
			t.Errorf("%s mode %v, want 0600", e.Name(), fi.Mode().Perm())
		}
		if fi.Size() > l.max {
			t.Errorf("%s is %d bytes, over the rotation size", e.Name(), fi.Size())
		}
	}
	want := "actions.jsonl actions.jsonl.1 actions.jsonl.2 actions.jsonl.3 actions.jsonl.4"
	if got := strings.Join(names, " "); got != want {
		t.Errorf("files = %s, want %s", got, want)
	}
	if fi, err := os.Stat(dir); err != nil || fi.Mode().Perm() != 0o700 {
		t.Errorf("dir mode = %v, %v; want 0700", fi.Mode().Perm(), err)
	}
}

// TestAuditTightensLooseModes: a directory or file left readable by
// others is tightened on the next write.
func TestAuditTightensLooseModes(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "audit")
	path := filepath.Join(dir, "actions.jsonl")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, nil, 0o644); err != nil {
		t.Fatal(err)
	}
	newAuditLog(path).write(auditRecord{Phase: phaseRequested})
	for p, want := range map[string]os.FileMode{dir: 0o700, path: 0o600} {
		if fi, err := os.Stat(p); err != nil || fi.Mode().Perm() != want {
			t.Errorf("%s mode = %v (%v), want %v", p, fi.Mode().Perm(), err, want)
		}
	}
}

func TestAuditDisabled(t *testing.T) {
	if l := newAuditLog(""); l != nil {
		t.Fatal("empty path must disable the audit file")
	}
	var l *auditLog
	l.write(auditRecord{Phase: phaseRequested}) // must not panic
}

// TestCmdTraceRecord: the output head is clipped and loses the bot
// token; the hash covers the whole output.
func TestCmdTraceRecord(t *testing.T) {
	a := testAgent(&fakeSender{})
	a.cfg.Telegram.Token = "123456:SECRETsecret"
	out := "url https://api.telegram.org/bot123456:SECRETsecret/x and bare 123456:SECRETsecret " + strings.Repeat("é", 400)
	var r auditRecord
	(&cmdTrace{argv: []string{"ufw", "deny", "22/tcp"}, out: out, err: errors.New("boom")}).record(&r, a.redactOutput)
	if strings.Contains(r.OutputHead, "SECRET") {
		t.Errorf("output head keeps the token: %q", r.OutputHead)
	}
	if len(r.OutputHead) > auditHead || !strings.HasPrefix(r.OutputHead, "url https://api.telegram.org/bot<redacted>/x") {
		t.Errorf("output head = %q (%d bytes)", r.OutputHead, len(r.OutputHead))
	}
	if r.ExitCode == nil || *r.ExitCode != -1 || len(r.OutputSHA256) != 64 {
		t.Errorf("record = %+v", r)
	}

	err := exec.Command("sh", "-c", "exit 3").Run()
	r = auditRecord{}
	(&cmdTrace{argv: []string{"sh"}, err: err}).record(&r, a.redactOutput)
	if r.ExitCode == nil || *r.ExitCode != 3 {
		t.Errorf("exit code = %v, want 3", r.ExitCode)
	}
	r = auditRecord{}
	(*cmdTrace)(nil).record(&r, a.redactOutput)
	if r.Argv != nil || r.ExitCode != nil {
		t.Errorf("no command must leave no command fields: %+v", r)
	}
}
